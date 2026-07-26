"""
The Foundry orchestrator — an adversarial MULTI-AGENT LangGraph StateGraph with a
Blue↔Red self-repair loop and a deterministic referee.

    ingest → extract → telemetry ─┐
                                  ▼
        ┌──────── SELF-REPAIR LOOP ────────────────────────────────────┐
        │  blue_author → evaluate → battery → red_propose → red_verify  │
        │       ▲                                              │        │
        │       └────────── repair (verdict != real) ──────── verdict   │
        └──────────────────────────────────────────────────────┬───────┘
                                                     done (real │ or cap)
                                                                ▼
                                                       gate → bundle

  [ Blue/Red/Telemetry/Analyst = LLM agents — they PROPOSE ]
  [ evaluate·battery·red_verify·verdict·gate = deterministic referee — it PROVES ]

The authoring/orchestration agents can only propose. `evaluate`/`battery` recompute
truth with engine.py + evaluator.py; `red_verify` engine-checks every red-team
proposal (a bypass counts only if the engine confirms the rule fails to fire);
`verdict` labels coverage; `gate` runs Kartikeya's Gate. There is deliberately NO
deploy node: deployment is egress and lives behind the human-gated MCP tool
(mcp_server.deploy_detection), which the graph cannot call. The harness holds the
privilege, not the agent.
"""
from __future__ import annotations

import json
from functools import partial
from pathlib import Path

from langgraph.graph import END, START, StateGraph

from . import agents, evaluator, governance, reporting
from .engine import SigmaConditionError, UnsupportedSigmaFeature
from .engine import evaluate as engine_evaluate
from .providers import LLMProvider
from .state import (
    AdversarialResult,
    CoverageVerdict,
    DeployIntent,
    EvalResult,
    FoundryState,
    Mutation,
    ProofBundle,
    RedTeamProposal,
    RoundRecord,
)

_OUT = Path(__file__).resolve().parent.parent / "Outputs"


def _slug(text: str) -> str:
    keep = [c.lower() if c.isalnum() else "-" for c in text]
    s = "".join(keep)
    while "--" in s:
        s = s.replace("--", "-")
    return s.strip("-")[:60] or "rule"


# --------------------------------------------------------------------------- #
# Deterministic referee nodes (NO LLM)
# --------------------------------------------------------------------------- #
def node_evaluate(state: FoundryState) -> dict:
    corpus = state["corpus"]
    try:
        ev = evaluator.evaluate(state["rule"], corpus)
    except (UnsupportedSigmaFeature, SigmaConditionError) as e:
        # Blue authored a construct the engine will not fake support for (`|in`,
        # `|cidr`, an aggregation, a malformed condition). engine.py raising is the
        # honesty contract working — an un-evaluable rule must never be scored as
        # covered. But it is a bad rule, not a broken program: score the round as a
        # total miss and hand the engine's own message back to Blue as evidence.
        # This is exactly what the self-repair loop is for.
        msg = f"{type(e).__name__}: {e}"
        ev = EvalResult(
            tp=0, fp=0, tn=len(corpus.negatives), fn=len(corpus.positives),
            precision=0.0, recall=0.0, f1=0.0,
            positives_total=len(corpus.positives), negatives_total=len(corpus.negatives),
            passed=False,
            failures=[f"RULE NOT EVALUABLE by the deterministic engine — {msg}"],
        )
        # Reset the adversarial result too: this round skips the battery and Red, and
        # last round's evasions must not leak into this round's verdict.
        return {"evaluation": ev, "rule_error": msg, "adversarial": AdversarialResult(),
                "red_team": [], "red_team_raw": [], "red_refused": False, "log": [
                    f"[eval] rule NOT EVALUABLE ({msg}) → round scored BROKEN, returning to Blue"
                ]}
    # Accumulate the exact benign events this rule wrongly fired on, so Blue's next
    # re-author sees the FULL running set of false positives (not just this round's) and
    # can suppress them all at once instead of oscillating.
    fp_events = []
    for n in corpus.negatives:
        try:
            if engine_evaluate(state["rule"].detection, n):
                fp_events.append(n)
        except (UnsupportedSigmaFeature, SigmaConditionError):
            pass
    return {"evaluation": ev, "rule_error": "", "seen_fps": fp_events, "log": [
        f"[eval] TP={ev.tp} FN={ev.fn} FP={ev.fp} TN={ev.tn} "
        f"precision={ev.precision} recall={ev.recall}"
    ]}


def route_after_evaluate(state: FoundryState) -> str:
    """
    Conditional edge: a rule the engine cannot evaluate skips the rest of the round.

    There is nothing to mutate and nothing for Red to attack — and asking a model to
    attack a rule that does not run would burn a live call to learn nothing. Go
    straight to the verdict, which will label it broken and loop back to Blue.
    """
    return "unevaluable" if state.get("rule_error") else "ok"


def node_battery(state: FoundryState) -> dict:
    adv = evaluator.adversarial(state["rule"], state["corpus"])
    return {"adversarial": adv, "log": [
        f"[battery] {adv.evaded}/{adv.total} deterministic mutations evaded "
        f"(rate={adv.evasion_rate}, high-sev={len(adv.high_severity_evasions)})"
    ]}


def node_redteam_merge(state: FoundryState) -> dict:
    """
    Engine-verify each red-team proposal and MERGE the confirmed ones into the
    battery result. A proposal is a real evasion ONLY if the deterministic engine
    confirms the rule fails to fire on the event — the adversary never gets to
    assert a bypass. Confirmed proposals become high-signal mutations; the rest
    are discarded (recorded as fired=True / verified=False).
    """
    rule = state["rule"]
    adv = state["adversarial"]
    raw = state.get("red_team_raw", []) or []

    proposals: list[RedTeamProposal] = []
    verified_muts: list[Mutation] = []
    for i, p in enumerate(raw):
        event = p.get("event") or {}
        try:
            fired = bool(engine_evaluate(rule.detection, event))
        except Exception:
            # An un-evaluable event can't be proven as a bypass → treat as fired
            # (discarded). We never score an unprovable claim as an evasion.
            fired = True
        verified = not fired
        prop = RedTeamProposal(
            id=str(p.get("id", f"rt{i}")),
            mutation_class=str(p.get("mutation_class", "semantic")),
            severity=str(p.get("severity", "medium")),
            description=str(p.get("description", "")),
            event=event, fired=fired, verified=verified,
        )
        proposals.append(prop)
        if verified:
            verified_muts.append(Mutation(
                id=f"rt-{prop.id}", mutation_class=prop.mutation_class, severity=prop.severity,
                description="[red-team] " + prop.description, event=event, evaded=True,
            ))

    merged = evaluator.merge_redteam(adv, verified_muts)
    nver = sum(1 for p in proposals if p.verified)
    return {"adversarial": merged, "red_team": proposals, "log": [
        f"[red/verify] {nver}/{len(proposals)} proposal(s) engine-VERIFIED as real evasions "
        f"(merged into battery); {len(proposals) - nver} discarded"
    ]}


def node_verdict(state: FoundryState) -> dict:
    ev = state["evaluation"]
    adv = state["adversarial"]
    lbl = evaluator.label(ev, adv)
    rnd = state.get("round", 1)
    maxr = state.get("max_rounds", 3)

    # A rule the engine refused to evaluate is BROKEN, stated plainly. It never
    # reached the battery or the adversary, so there is no coverage claim to make —
    # only a rule that does not run.
    if state.get("rule_error"):
        lbl = lbl.model_copy(update={
            "verdict": CoverageVerdict.broken,
            "rationale": [
                f"The deterministic engine refused to evaluate this rule: {state['rule_error']}.",
                "An un-evaluable rule is never scored as covered — it was not tested against "
                "the corpus, the mutation battery, or the adversary.",
            ],
            "remediation": [
                "Re-author using only Sigma constructs the engine evaluates: the modifiers "
                "contains / startswith / endswith / re / all / cased. A plain YAML list of "
                "values already means OR — there is no |in modifier in Sigma.",
            ],
        })

    # An adversary that never attacked is not evidence of a rule that holds. If the
    # model declined the red-team role, the deterministic battery still counts, but
    # this round is not adversarially tested — so it cannot earn real-coverage. Same
    # honesty contract as engine.py raising on constructs it can't truly evaluate:
    # never score an untested rule as covered.
    if state.get("red_refused") and lbl.verdict is CoverageVerdict.real:
        lbl = lbl.model_copy(update={
            "verdict": CoverageVerdict.brittle,
            "rationale": lbl.rationale + [
                "Red-team adversary declined the request — this round was NOT adversarially "
                "tested. Battery-only result; downgraded from real-coverage."
            ],
            "remediation": lbl.remediation + [
                "Re-run the adversarial round with a model that will perform the red-team role."
            ],
        })
    proposals = state.get("red_team", []) or []
    verified = [p for p in proposals if p.verified]
    battery_evaded = sum(1 for m in adv.mutations if m.evaded and not str(m.id).startswith("rt-"))

    if lbl.verdict is CoverageVerdict.real:
        outcome = "converged"
    elif rnd >= maxr:
        outcome = "capped"
    else:
        outcome = "repair"

    rule = state["rule"]
    rec = RoundRecord(
        round=rnd, rule_id=rule.rule_id, rule_title=rule.title, level=rule.level,
        verdict=lbl.verdict.value, tp=ev.tp, fp=ev.fp, fn=ev.fn,
        battery_evaded=battery_evaded, redteam_proposed=len(proposals),
        redteam_verified=len(verified),
        evasions=[m.description for m in adv.mutations if m.evaded],
        remediation=lbl.remediation, outcome=outcome,
    )
    # Accumulate the exact attack events that evaded this round (battery + verified
    # red-team) into the running gap memory, so Blue's next re-author must catch ALL of
    # them, not just this round's.
    evaded_events = [
        {"description": m.description, "mutation_class": m.mutation_class, "event": m.event}
        for m in adv.mutations if m.evaded
    ]
    return {"coverage": lbl, "rounds": [rec], "seen_evasions": evaded_events, "log": [
        f"[verdict r{rnd}] coverage = {lbl.verdict.value}  →  {outcome}"
    ]}


def route_after_verdict(state: FoundryState) -> str:
    """Conditional edge: loop back to Blue for repair, or exit to the gate."""
    if state["coverage"].verdict is CoverageVerdict.real:
        return "done"
    if state.get("round", 1) >= state.get("max_rounds", 3):
        return "done"          # cap reached — ship the best-so-far, gate will flag it
    return "repair"


def node_gate(state: FoundryState) -> dict:
    ev = state["evaluation"]
    intent: DeployIntent = state.get("deploy_intent") or DeployIntent()
    fp_rate = round(1.0 - ev.precision, 4)
    gate = governance.compute_gate(
        level=state["rule"].level, fp_rate=fp_rate,
        coverage=state["coverage"], intent=intent,
    )
    return {"gate": gate, "log": [
        f"[gate] blast={gate.blast_radius} × capΔ={gate.capability_delta} = {gate.score} "
        f"→ {gate.tier} (human={'yes' if gate.requires_human else 'no'})"
    ]}


def node_bundle(state: FoundryState) -> dict:
    threat = state["threat"]
    rule = state["rule"]
    corpus = state["corpus"]
    ev = state["evaluation"]
    adv = state["adversarial"]
    coverage = state["coverage"]
    gate = state["gate"]
    rounds = state.get("rounds", [])
    red_team = state.get("red_team", [])
    blue_sources = state.get("blue_sources", [])
    red_sources = state.get("red_sources", [])
    mode = state.get("mode", "fixture")

    proof_core = {
        "threat": threat.model_dump(mode="json"),
        "rule": {"yaml": rule.yaml_text, "detection": rule.detection},
        "corpus": corpus.model_dump(mode="json"),
        "evaluation": ev.model_dump(mode="json"),
        "adversarial": adv.model_dump(mode="json"),
        "coverage": coverage.model_dump(mode="json"),
        "gate": gate.model_dump(mode="json"),
    }
    content_hash = governance.canonical_hash(proof_core)

    report_md = reporting.render_report(
        threat=threat, behaviors=state.get("behaviors", []), rule=rule,
        ev=ev, adv=adv, coverage=coverage, gate=gate, mode=mode, content_hash=content_hash,
        rounds=rounds, red_team=red_team, blue_sources=blue_sources, red_sources=red_sources,
    )

    bundle = ProofBundle(
        threat=threat, rule=rule, corpus=corpus, evaluation=ev, adversarial=adv,
        coverage=coverage, gate=gate, report_md=report_md, content_hash=content_hash, mode=mode,
    )

    out_dir = _OUT / _slug(rule.title)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "rule.yml").write_text(rule.yaml_text.strip() + "\n", encoding="utf-8")
    (out_dir / "report.md").write_text(report_md, encoding="utf-8")
    (out_dir / "proof.json").write_text(
        json.dumps(
            {**proof_core, "content_hash": content_hash, "mode": mode,
             "convergence": [r.model_dump(mode="json") for r in rounds]},
            indent=2, default=str,
        ),
        encoding="utf-8",
    )

    return {"bundle": bundle, "bundle_dir": str(out_dir),
            "log": [f"[bundle] written → {out_dir}  (hash {content_hash[:23]}…)"]}


# --------------------------------------------------------------------------- #
def build_app(provider: LLMProvider):
    """Compile the adversarial multi-agent graph with the provider bound into LLM nodes."""
    g = StateGraph(FoundryState)

    # LLM agents (provider bound via partial)
    g.add_node("ingest", partial(agents.ingest, provider=provider))
    g.add_node("extract", partial(agents.extract_behaviors, provider=provider))
    g.add_node("telemetry", partial(agents.build_corpus, provider=provider))
    g.add_node("blue_author", partial(agents.blue_author, provider=provider))
    g.add_node("red_propose", partial(agents.red_team_propose, provider=provider))
    # deterministic referee
    g.add_node("evaluate", node_evaluate)
    g.add_node("battery", node_battery)
    g.add_node("red_verify", node_redteam_merge)
    g.add_node("verdict", node_verdict)
    g.add_node("gate", node_gate)
    g.add_node("bundle", node_bundle)

    g.add_edge(START, "ingest")
    g.add_edge("ingest", "extract")
    g.add_edge("extract", "telemetry")           # fixed test set, built once
    g.add_edge("telemetry", "blue_author")
    # --- self-repair loop body ---
    g.add_edge("blue_author", "evaluate")
    # An un-evaluable rule short-circuits to the verdict: nothing to mutate, nothing
    # for Red to attack, and no live call worth spending on a rule that won't run.
    g.add_conditional_edges("evaluate", route_after_evaluate,
                            {"ok": "battery", "unevaluable": "verdict"})
    g.add_edge("battery", "red_propose")
    g.add_edge("red_propose", "red_verify")
    g.add_edge("red_verify", "verdict")
    g.add_conditional_edges("verdict", route_after_verdict,
                            {"repair": "blue_author", "done": "gate"})
    # --- exit ---
    g.add_edge("gate", "bundle")
    g.add_edge("bundle", END)

    return g.compile()
