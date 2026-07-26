"""
Foundry Live — a FastAPI wrapper that STREAMS the real LangGraph run over SSE.

Takes the text of a live threat — any CVE, KEV entry, ATT&CK technique or incident
headline — and streams the actual Blue↔Red self-repair loop so each agent is visible
at work. There are no presets and no scenario registry: whatever is typed is what a
real model authors from.

Two streams are interleaved:

  * NODE events (analyst / telemetry / blue / evaluate / battery / red_propose /
    red_verify / verdict / gate / bundle) — emitted when a graph node completes,
    carrying the deterministic results.
  * LLM token events — emitted *during* an agent's model call, via the provider's
    token sink, so a multi-minute authoring call is watchable instead of a frozen
    screen.

That second stream is why the graph runs on a worker thread here. Tokens arrive
while a node is still executing, and `app.stream()` only yields between nodes — so
nothing can be sent from inside the graph iteration itself. The worker pushes both
kinds of event onto a queue; this generator drains it. The queue is the only
coupling, and it is one-way: nothing the UI does can reach back into the graph.

No proof-core changes. The graph authors, proves, red-teams and gates exactly as the
CLI does; this only observes. Every token event carries a `cached` flag — a replay of
bytes already on disk is labeled as such and never dressed up as live generation.

Determinism holds via providers.py's on-disk cache: calls are temperature 0 and keyed
by sha256(model|system|user), so re-running the same threat text replays byte-identical
model output and reproduces the same rule and the same bundle hash. The first run of
any given threat pays real model latency (~3-4 min/round); every run after that is a
cache hit. The model only ever PROPOSES: engine.py, the mutation battery, red_verify,
the verdict and Kartikeya's Gate are deterministic and recomputed every run.

Run:  uvicorn webui.server:app --port 8000    (from the code/ directory)
Then open http://127.0.0.1:8000
"""
from __future__ import annotations

import json
import os
import queue
import threading
import time
import traceback
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, StreamingResponse

from src import graph, review_chain
from src.providers import get_provider, live_provider_name
from src.state import DeployIntent

_HERE = Path(__file__).resolve().parent
_CACHE = _HERE.parent / ".cache"          # providers.py's response cache

app = FastAPI(title="Detection-as-Code Foundry — Live")

# Which agent owns each provider tag, so a token stream lands on the right node.
_TAG_AGENT = {"ingest": "analyst", "extract": "analyst", "corpus": "telemetry"}


def _agent_for(tag: str) -> str:
    if tag in _TAG_AGENT:
        return _TAG_AGENT[tag]
    if tag.startswith("author") or tag.startswith("draft") or tag.startswith("revise") \
            or tag.startswith("final"):
        return "blue"
    if tag.startswith("red_team") or tag.startswith("red_review"):
        return "red"
    if tag.startswith("soc"):
        return "soc"
    return "analyst"


def _cite(c) -> dict:
    return {"source": c.source, "title": c.title,
            "techniques": c.techniques, "score": c.score}


def _sse(event_type: str, payload: dict) -> str:
    return f"event: {event_type}\ndata: {json.dumps(payload)}\n\n"


def _event_for(node: str, delta: dict) -> tuple[str, dict] | None:
    """Translate a graph node's state delta into a UI event (type, payload)."""
    if node == "ingest":
        t = delta["threat"]
        return "analyst", {"stage": "ingest", "title": t.title,
                           "techniques": t.attack_techniques, "summary": t.summary}
    if node == "extract":
        return "analyst", {"stage": "extract",
                           "behaviors": len(delta.get("behaviors", []))}
    if node == "telemetry":
        c = delta["corpus"]
        return "telemetry", {"positives": len(c.positives), "negatives": len(c.negatives)}
    if node == "blue_author":
        r = delta["rule"]
        return "blue", {"round": delta.get("round"), "title": r.title, "rule_id": r.rule_id,
                        "level": r.level, "yaml": r.yaml_text,
                        "sources": [_cite(c) for c in delta.get("blue_sources", [])]}
    if node == "evaluate":
        e = delta["evaluation"]
        return "evaluate", {"tp": e.tp, "fn": e.fn, "fp": e.fp, "tn": e.tn,
                            "precision": e.precision, "recall": e.recall}
    if node == "battery":
        a = delta["adversarial"]
        return "battery", {"evaded": a.evaded, "total": a.total,
                           "rate": a.evasion_rate, "high_sev": len(a.high_severity_evasions)}
    if node == "red_propose":
        return "red_propose", {"proposed": len(delta.get("red_team_raw", [])),
                               "refused": bool(delta.get("red_refused")),
                               "sources": [_cite(c) for c in delta.get("red_sources", [])]}
    if node == "red_verify":
        props = delta.get("red_team", [])
        a = delta["adversarial"]
        return "red_verify", {
            "verified": sum(1 for p in props if p.verified),
            "total": len(props),
            "proposals": [{"description": p.description, "class": p.mutation_class,
                           "severity": p.severity, "verified": bool(p.verified)} for p in props],
            "high_sev": a.high_severity_evasions,
        }
    if node == "verdict":
        rec = delta.get("rounds", [])[-1]
        return "verdict", {"round": rec.round, "verdict": rec.verdict, "outcome": rec.outcome,
                           "fp": rec.fp, "fn": rec.fn, "battery_evaded": rec.battery_evaded,
                           "redteam_verified": rec.redteam_verified, "evasions": rec.evasions,
                           "remediation": rec.remediation}
    if node == "gate":
        g = delta["gate"]
        return "gate", {"blast": g.blast_radius, "cap": g.capability_delta, "score": g.score,
                        "tier": g.tier, "requires_human": g.requires_human}
    if node == "bundle":
        b = delta["bundle"]
        return "bundle", {"hash": b.content_hash, "verdict": b.coverage.verdict.value,
                          "final_rule": b.rule.yaml_text, "rule_title": b.rule.title,
                          "bundle_dir": delta.get("bundle_dir", "")}
    return None


def _run_stream(title: str, max_rounds: int):
    live = live_provider_name()
    if live is None:
        yield _sse("error", {"message": "Live authoring needs a model key: set GEMINI_API_KEY "
                                        "(or ANTHROPIC_API_KEY) and restart the server."})
        return

    provider = get_provider(live)
    threat = title.strip()

    # Node events land in bursts (the deterministic referee is instant); pace them so
    # the eye can follow. Token events are already paced by generation or by replay.
    pace = float(os.environ.get("FOUNDRY_PACE", "0.45"))

    q: queue.Queue = queue.Queue()
    provider.on_token = lambda *, tag, event, chunk="", cached=False: q.put(
        ("llm", {"tag": tag, "agent": _agent_for(tag), "event": event,
                 "chunk": chunk, "cached": cached}))

    def worker():
        try:
            app_graph = graph.build_app(provider)
            init = {
                "raw_threat": threat, "source_type": "writeup", "source_ref": threat[:60],
                "deploy_intent": DeployIntent(), "mode": provider.mode, "corpus_source": "model",
                "round": 0, "max_rounds": max_rounds, "rounds": [], "log": [],
            }
            for chunk in app_graph.stream(init, stream_mode="updates",
                                          config={"recursion_limit": 4 + max_rounds * 8}):
                for node, delta in chunk.items():
                    ev = _event_for(node, delta)
                    if ev is not None:
                        q.put(("node", ev))
            q.put(("done", None))
        except Exception as e:
            # A live run can 429/503, or a model can emit unparseable YAML. Surface it
            # in the UI rather than hanging the stream.
            traceback.print_exc()
            msg = f"{type(e).__name__}: {e}"
            hint = ""
            if type(e).__name__ == "ModelRefusal" or "safety classifier declined" in msg:
                # A refusal is a property of the threat, not a transient failure — say so,
                # and don't imply a re-run will fix it.
                hint = "Pick a different threat, or run this one on Gemini."
            elif "429" in msg or "RESOURCE_EXHAUSTED" in msg:
                hint = ("Model rate limit. Wait and re-run — completed steps are cached, "
                        "so it resumes cheaply.")
            elif "404" in msg:
                hint = "Model unavailable for this key. Set GEMINI_MODEL to one that works."
            q.put(("fail", {"message": msg, "hint": hint}))

    yield _sse("start", {"title": threat, "provider": provider.name,
                         "source_ref": threat[:60], "max_rounds": max_rounds})

    threading.Thread(target=worker, daemon=True, name="foundry-graph").start()

    while True:
        try:
            kind, payload = q.get(timeout=15)
        except queue.Empty:
            yield ": ping\n\n"        # keep proxies/browsers from dropping a quiet stream
            continue
        if kind == "llm":
            yield _sse("llm", payload)
        elif kind == "node":
            yield _sse(payload[0], payload[1])
            time.sleep(pace)
        elif kind == "fail":
            yield _sse("error", payload)
            return
        else:
            yield _sse("done", {})
            return


# --------------------------------------------------------------------------- #
# REVIEW CHAIN — the stakeholder-review pipeline (draft → Red → revise → SOC →
# final). Linear, no loop, no verdict. See src/review_chain.py.
# --------------------------------------------------------------------------- #
_CHAIN_STAGES = ["ingest", "extract", "telemetry", "profile", "draft",
                 "red_review", "revise", "soc_review", "final", "package"]


def _version_payload(v) -> dict:
    return {
        "version": v.version, "label": v.label, "title": v.title, "rule_id": v.rule_id,
        "level": v.level, "yaml": v.yaml_text, "note": v.author_note,
        "responding_to": v.responding_to,
        "changes": [{"finding_id": c.finding_id, "what_changed": c.what_changed, "why": c.why}
                    for c in v.changes],
    }


def _review_payload(r) -> dict:
    return {
        "reviewer": r.reviewer, "label": r.reviewer_label,
        "reviews_version": r.reviews_version, "summary": r.verdict_line,
        "findings": [{"id": f.id, "severity": f.severity, "title": f.title,
                      "detail": f.detail, "ask": f.ask} for f in r.findings],
    }


def _chain_event_for(node: str, delta: dict) -> tuple[str, dict] | None:
    if node == "ingest":
        t = delta["threat"]
        return "analyst", {"stage": "ingest", "title": t.title, "summary": t.summary,
                           "techniques": t.attack_techniques, "platforms": t.platforms}
    if node == "extract":
        bs = delta.get("behaviors", [])
        return "analyst", {"stage": "extract", "behaviors": len(bs),
                           "items": [{"id": b.id, "description": b.description,
                                      "technique": b.attack_technique} for b in bs[:6]]}
    if node == "telemetry":
        c = delta["corpus"]
        return "telemetry", {"positives": len(c.positives), "negatives": len(c.negatives)}
    if node == "profile":
        p = delta["telemetry"]
        return "profile", {"category": p.category, "product": p.product, "fields": p.fields}
    if node in ("draft", "revise", "final"):
        return "version", _version_payload(delta["rule"])
    if node in ("red_review", "soc_review"):
        return "review", _review_payload(delta["reviews"][-1])
    if node == "package":
        p = delta["package"]
        return "package", {
            "final_yaml": p.final_rule.yaml_text if p.final_rule else "",
            "final_title": p.final_rule.title if p.final_rule else "",
            "final_level": p.final_rule.level if p.final_rule else "",
            "versions": len(p.versions),
            "findings": sum(len(r.findings) for r in p.reviews),
            "dir": delta.get("package_dir", ""),
            "disclaimer": p.disclaimer,
        }
    return None


def _chain_stream(title: str):
    live = live_provider_name()
    if live is None:
        yield _sse("error", {"message": "Live authoring needs a model key: set ANTHROPIC_API_KEY "
                                        "(or GEMINI_API_KEY) and restart the server."})
        return

    provider = get_provider(live)
    threat = title.strip()
    pace = float(os.environ.get("FOUNDRY_PACE", "0.4"))

    q: queue.Queue = queue.Queue()
    provider.on_token = lambda *, tag, event, chunk="", cached=False: q.put(
        ("llm", {"tag": tag, "agent": _agent_for(tag), "event": event,
                 "chunk": chunk, "cached": cached}))

    def worker():
        try:
            chain = review_chain.build_chain(provider)
            init = {
                "raw_threat": threat, "source_type": "writeup", "source_ref": threat[:60],
                "mode": provider.mode, "versions": [], "reviews": [], "log": [],
            }
            for chunk in chain.stream(init, stream_mode="updates",
                                      config={"recursion_limit": 40}):
                for node, delta in chunk.items():
                    q.put(("stage", {"node": node}))
                    ev = _chain_event_for(node, delta)
                    if ev is not None:
                        q.put(("node", ev))
            q.put(("done", None))
        except Exception as e:
            traceback.print_exc()
            msg = f"{type(e).__name__}: {e}"
            hint = ""
            if type(e).__name__ == "ModelRefusal" or "safety classifier declined" in msg:
                hint = "Pick a different threat, or run this one on the other provider."
            elif "429" in msg or "RESOURCE_EXHAUSTED" in msg:
                hint = ("Model rate limit. Wait and re-run — completed steps are cached, "
                        "so it resumes cheaply.")
            elif "overloaded" in msg.lower() or "529" in msg:
                hint = "The model is overloaded right now. Re-run — cached steps replay instantly."
            q.put(("fail", {"message": msg, "hint": hint}))

    yield _sse("start", {"title": threat, "provider": provider.name,
                         "stages": _CHAIN_STAGES})

    threading.Thread(target=worker, daemon=True, name="foundry-chain").start()

    while True:
        try:
            kind, payload = q.get(timeout=15)
        except queue.Empty:
            yield ": ping\n\n"
            continue
        if kind == "llm":
            yield _sse("llm", payload)
        elif kind == "stage":
            yield _sse("stage", payload)
        elif kind == "node":
            yield _sse(payload[0], payload[1])
            time.sleep(pace)
        elif kind == "fail":
            yield _sse("error", payload)
            return
        else:
            yield _sse("done", {})
            return


@app.get("/chain")
def chain(title: str):
    return StreamingResponse(
        _chain_stream(title), media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/status")
def status():
    """Whether this box can author at all right now, and how warm the cache is."""
    live = live_provider_name()
    return {
        "live_provider": live,
        "live_available": live is not None,
        "model": os.environ.get("GEMINI_MODEL") if live == "gemini" else None,
        "cached_calls": len(list(_CACHE.glob("*.json"))) if _CACHE.exists() else 0,
    }


@app.get("/stream")
def stream(title: str, max_rounds: int = 3):
    # Three rounds: Red commits its two real attacks (round 1) and re-tests them; Blue
    # authors, re-authors on the accumulated gap set, and by the final round has seen every
    # gap from every prior round at once — so its last pass is a true consolidation, not a
    # reaction to only the latest failure. With that accumulated memory (see
    # agents._evidence_block) Blue stops oscillating and converges here instead of needing
    # a long round cap. A converged run still exits early.
    return StreamingResponse(
        _run_stream(title, max_rounds), media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/", response_class=HTMLResponse)
def index():
    """The review chain — the default surface."""
    return (_HERE / "chain.html").read_text(encoding="utf-8")


@app.get("/classic", response_class=HTMLResponse)
def classic():
    """The original adversarial proof loop (deterministic verdict + gate)."""
    return (_HERE / "index.html").read_text(encoding="utf-8")
