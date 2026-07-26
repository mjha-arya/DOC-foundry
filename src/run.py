"""
Entrypoint: drive a threat through the Foundry to a proven, gated bundle.

    python src/run.py "CVE-2026-45659 SharePoint deserialization RCE"   # live threat
    python src/run.py --threat fixtures/certutil_t1105.json             # canned/offline
    python src/run.py --claude "..."        # force real Claude authoring (ANTHROPIC_API_KEY)
    python src/run.py --gemini "..."        # force real Gemini authoring (GEMINI_API_KEY)
    python src/run.py --approve "alice"     # after a run, mint approval + attempt gated deploy
    python src/run.py --evals               # run the deterministic engine test suite

The Foundry takes a LIVE threat: pass any threat text — a CVE, a KEV entry, an
ATT&CK technique, an incident headline — and a real model authors from it. There is
no default scenario; a bare `python src/run.py` has nothing to work on and says so.

`--threat <fixture.json>` remains for canned, keyless, fully offline runs (the test
suite uses this path). Either way the model only PROPOSES — the proof engine, the
mutation battery, red-team verification, the verdict and the gate are deterministic
and recomputed on every run.
"""
from __future__ import annotations

import argparse
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Windows consoles default to cp1252; the report uses × / Δ / → glyphs.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
    except Exception:
        pass

from src.graph import build_app                                  # noqa: E402
from src.providers import get_provider, live_provider_name       # noqa: E402
from src.state import DeployIntent                               # noqa: E402
from src import governance, mcp_server                           # noqa: E402

_LINE = "  " + "-" * 68


def _load_fixture(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    responses: dict[str, str] = {}
    for tag, obj in data.get("responses_json", {}).items():
        responses[tag] = json.dumps(obj)
    for tag, text in data.get("responses_text", {}).items():
        responses[tag] = text
    return {
        "raw_threat": data["raw_threat"],
        "source_type": data.get("source_type", "writeup"),
        "source_ref": data.get("source_ref", "n/a"),
        "responses": responses,
    }


def _banner(title: str):
    print(f"\n{title}\n{_LINE}")


def _plan(args) -> tuple[dict, str]:
    """
    Resolve argv into (graph inputs, provider mode).

    Two ways in, and they are not interchangeable: live threat text (a real model
    authors it) or an explicit fixture (canned responses, no key). There is no
    default scenario to fall back on — an empty invocation is a user error, not a
    silent certutil demo.
    """
    text = " ".join(args.threat_text).strip()
    if text and args.threat:
        raise SystemExit("  ✗ pass EITHER live threat text OR --threat <fixture.json>, not both.")

    if args.threat:                     # canned scenario: offline unless forced live
        fixture = _load_fixture(args.threat)
        mode = "gemini" if args.gemini else ("claude" if args.claude else "auto")
        return {
            "raw_threat": fixture["raw_threat"],
            "source_type": fixture["source_type"],
            "source_ref": fixture["source_ref"],
            "responses": fixture["responses"],
        }, mode

    if not text:
        raise SystemExit(
            "  ✗ no threat given.\n"
            "     live   :  python src/run.py \"CVE-2026-45659 SharePoint deserialization RCE\"\n"
            "     canned :  python src/run.py --threat fixtures/certutil_t1105.json\n"
            "     tests  :  python src/run.py --evals"
        )

    mode = "gemini" if args.gemini else ("claude" if args.claude else live_provider_name())
    if mode is None:
        raise SystemExit(
            "  ✗ a live threat needs a model key: set ANTHROPIC_API_KEY or GEMINI_API_KEY.\n"
            "     Or run a canned scenario offline:  python src/run.py --threat fixtures/certutil_t1105.json"
        )
    return {
        "raw_threat": text,
        "source_type": "writeup",
        "source_ref": text[:60],
        "responses": None,
    }, mode


def _run_chain(args) -> int:
    """The stakeholder REVIEW CHAIN — a different product from the proof loop.

    Prints the trail the way the UI shows it: each rule version, each reviewer's
    findings, and which finding every edit answered. No verdict, no FP/FN, no gate —
    see the module docstring in src/review_chain.py for why.
    """
    from src import review_chain                                   # noqa: PLC0415

    threat_text = " ".join(args.threat_text).strip()
    if not threat_text:
        print("  The review chain takes a threat. Example:\n"
              '    python src/run.py --chain "CVE-2026-48939 Joomla iCagenda file upload RCE"')
        return 2

    live = live_provider_name()
    if live is None:
        print("  The review chain needs a live model. Set ANTHROPIC_API_KEY or GEMINI_API_KEY.")
        return 2
    provider = get_provider("claude" if args.claude else ("gemini" if args.gemini else live))

    _banner(f"  DETECTION REVIEW CHAIN   ·   {provider.name}")
    print(f"  threat: {threat_text[:70]}")
    print("  draft → Red Team review → revision → SOC Lead review → final\n")

    pkg = review_chain.run(threat_text, provider)

    reviews_by_version: dict[int, list] = {}
    for r in pkg.reviews:
        reviews_by_version.setdefault(r.reviews_version, []).append(r)

    for v in pkg.versions:
        _banner(f"  v{v.version} — {v.label.upper()}")
        print(f"  {v.title}   (level={v.level})")
        if v.author_note:
            print(f"  {v.author_note}")
        for c in v.changes:
            print(f"    [{c.finding_id}] {c.what_changed}")
            if c.why:
                print(f"          why: {c.why}")
        for review in reviews_by_version.get(v.version, []):
            _banner(f"  ⟶ {review.reviewer_label.upper()}")
            if review.verdict_line:
                print(f"  \"{review.verdict_line}\"")
            for f in review.findings:
                print(f"    {f.id} [{f.severity}] {f.title}")
                if f.ask:
                    print(f"          asks: {f.ask}")

    _banner("  FINAL RULE")
    print(pkg.final_rule.yaml_text.strip() if pkg.final_rule else "  (none)")
    _banner("")
    print(f"  {pkg.disclaimer}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Detection-as-Code Foundry — forge a proven detection from a live threat")
    ap.add_argument("threat_text", nargs="*",
                    help="the live threat: a CVE, a KEV entry, an ATT&CK technique, an incident headline")
    ap.add_argument("--threat", type=Path, metavar="FIXTURE.json",
                    help="run a canned scenario fixture instead (offline, no key)")
    ap.add_argument("--claude", action="store_true", help="force real Claude authoring")
    ap.add_argument("--gemini", action="store_true", help="force real Gemini authoring (GEMINI_API_KEY)")
    ap.add_argument("--approve", metavar="APPROVER", help="mint approval + attempt gated deploy")
    ap.add_argument("--evals", action="store_true", help="run the deterministic engine test suite")
    ap.add_argument("--corpus", choices=["model", "atomic"], default="model",
                    help="positive test corpus source: 'model' (LLM-authored) or "
                         "'atomic' (real Atomic Red Team commands for the threat's ATT&CK technique)")
    ap.add_argument("--max-rounds", type=int, default=3,
                    help="Blue↔Red self-repair loop cap (default 3; converged runs exit early)")
    ap.add_argument("--chain", action="store_true",
                    help="run the REVIEW CHAIN instead: draft → Red Team review → revision → "
                         "SOC Lead review → final rule. Linear, no verdict, no scoring.")
    args = ap.parse_args(argv)

    if args.chain:
        return _run_chain(args)

    if args.evals:
        loader = unittest.TestLoader()
        suite = loader.discover(str(Path(__file__).resolve().parent.parent / "tests"))
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        return 0 if result.wasSuccessful() else 1

    plan, mode = _plan(args)
    provider = get_provider(mode, fixture_responses=plan["responses"])

    _banner(f"  DETECTION-AS-CODE FOUNDRY   ·   authoring mode: {provider.mode}   ·   {provider.name}")
    print(f"  threat: {plan['source_ref']}")
    if provider.mode != "fixture":
        print("  authoring live — a cold round takes minutes; cached steps replay instantly.")

    app = build_app(provider)
    init = {
        "raw_threat": plan["raw_threat"],
        "source_type": plan["source_type"],
        "source_ref": plan["source_ref"],
        "deploy_intent": DeployIntent(),   # egress push, alert-only, prod, single-tenant
        "mode": provider.mode,
        "corpus_source": args.corpus,
        "round": 0,
        "max_rounds": args.max_rounds,
        "rounds": [],
        "log": [],
    }
    # recursion_limit headroom: up to max_rounds × 6 loop nodes + prefix/suffix.
    final = app.invoke(init, config={"recursion_limit": 4 + args.max_rounds * 8})

    _banner("  PIPELINE  (Blue = Detection Engineer · Red = Adversary · referee = deterministic)")
    for line in final["log"]:
        print("  " + line)

    rounds = final.get("rounds", [])
    _banner("  CONVERGENCE  (self-repair loop)")
    for r in rounds:
        badge = {"real-coverage": "✅ real-coverage", "brittle": "⚠️  brittle", "broken": "❌ broken"}.get(
            r.verdict, r.verdict)
        print(f"  round {r.round}: {r.rule_id:<32} {badge:<18} "
              f"FP={r.fp} FN={r.fn}  battery-evaded={r.battery_evaded} "
              f"red-team-verified={r.redteam_verified}  → {r.outcome}")

    blue_sources = final.get("blue_sources", [])
    red_sources = final.get("red_sources", [])
    if blue_sources or red_sources:
        _banner("  GROUNDING  (RAG — real OSS research the agents drew on)")
        for c in blue_sources:
            print(f"  🔵 Blue  ← [{c.source} · {'/'.join(c.techniques) or 'n/a'}] {c.title}  (rel {c.score})")
        for c in red_sources:
            print(f"  🔴 Red   ← [{c.source} · {'/'.join(c.techniques) or 'n/a'}] {c.title}  (rel {c.score})")

    gate = final["gate"]
    cov = final["coverage"]
    _banner("  VERDICT")
    print(f"  coverage : {cov.verdict.value}")
    for r in cov.rationale:
        print(f"           - {r}")
    if cov.remediation:
        print("  remediation:")
        for r in cov.remediation:
            print(f"           → {r}")
    _banner("  KARTIKEYA'S GATE")
    print(f"  blast_radius   = {gate.blast_radius}")
    print(f"  capability_Δ   = {gate.capability_delta}")
    print(f"  score          = {gate.score}  →  {gate.tier}")
    print(f"  requires_human = {gate.requires_human}")
    print(f"\n  bundle → {final['bundle_dir']}")
    print(f"  hash   → {final['bundle'].content_hash}")

    if args.approve:
        _demo_deploy(final, approver=args.approve)
    else:
        _demo_deploy_denied(final)

    return 0


def _demo_deploy_denied(final: dict):
    """Show that the authoring flow cannot deploy: no token → egress refused."""
    _banner("  DEPLOY ATTEMPT (no approval)")
    try:
        mcp_server.deploy_detection(final["bundle_dir"], token=None, approver="agent")
        print("  ✗ deploy unexpectedly succeeded")
    except mcp_server.EgressDenied as e:
        print(f"  ✅ egress correctly REFUSED:\n     {e}")


def _demo_deploy(final: dict, approver: str):
    """Human approves: mint a bound token, then deploy succeeds through the gate."""
    _banner(f"  HUMAN APPROVAL ({approver})")
    gate = final["bundle"].gate
    h = final["bundle"].content_hash
    token = governance.issue_approval(gate, h, approver)
    print(f"  approval token minted (bound to {h[:23]}…)")
    record = mcp_server.deploy_detection(final["bundle_dir"], token=token, approver=approver)
    print("  ✅ deploy authorized through the gate:")
    print("     " + json.dumps(record, indent=2).replace("\n", "\n     "))


if __name__ == "__main__":
    raise SystemExit(main())
