"""
Bundle rendering — the human-facing threat report + proof.

The report's defining section is "Proven vs. Authored": it states plainly which
claims the deterministic engine verified and which were proposed by the model.
That is the Foundry's intellectual-honesty contract on the page.
"""
from __future__ import annotations

from .state import (
    AdversarialResult,
    Citation,
    CoverageLabel,
    CoverageVerdict,
    DetectableBehavior,
    EvalResult,
    GateDecision,
    RedTeamProposal,
    RoundRecord,
    SigmaRuleArtifact,
    ThreatContext,
)

_VERDICT_BADGE = {
    CoverageVerdict.real: "✅ REAL COVERAGE",
    CoverageVerdict.brittle: "⚠️  BRITTLE",
    CoverageVerdict.broken: "❌ BROKEN",
}


def render_report(
    *,
    threat: ThreatContext,
    behaviors: list[DetectableBehavior],
    rule: SigmaRuleArtifact,
    ev: EvalResult,
    adv: AdversarialResult,
    coverage: CoverageLabel,
    gate: GateDecision,
    mode: str,
    content_hash: str,
    rounds: list[RoundRecord] | None = None,
    red_team: list[RedTeamProposal] | None = None,
    blue_sources: list[Citation] | None = None,
    red_sources: list[Citation] | None = None,
) -> str:
    rounds = rounds or []
    red_team = red_team or []
    blue_sources = blue_sources or []
    red_sources = red_sources or []
    L: list[str] = []
    w = L.append

    w(f"# Detection Report — {threat.title}")
    w("")
    w(f"> Verdict: **{_VERDICT_BADGE[coverage.verdict]}**  ·  "
      f"Gate tier: **{gate.tier}**  ·  Rounds to converge: **{len(rounds)}**  ·  "
      f"Authoring mode: `{mode}`")
    w("")
    w(f"- **Source:** `{threat.source_type.value}` — {threat.source_ref}")
    w(f"- **ATT&CK:** {', '.join(threat.attack_techniques) or 'n/a'}")
    w(f"- **Platforms:** {', '.join(threat.platforms) or 'n/a'}")
    w(f"- **Reproducibility hash:** `{content_hash}`")
    w("")
    w("## Summary")
    w(threat.summary)
    w("")

    if rounds:
        w("## Convergence history (Blue ↔ Red self-repair loop)")
        w("| round | rule | verdict | FP | FN | battery evaded | red-team verified | outcome |")
        w("|---|---|---|---|---|---|---|---|")
        for r in rounds:
            w(f"| {r.round} | `{r.rule_id}` | {_VERDICT_BADGE.get(CoverageVerdict(r.verdict), r.verdict)} "
              f"| {r.fp} | {r.fn} | {r.battery_evaded} | {r.redteam_verified} | **{r.outcome}** |")
        w("")
        # Narrate the arc: what each round's evidence forced.
        for r in rounds:
            if r.outcome == "repair" and r.evasions:
                w(f"- **Round {r.round}** was `{r.verdict}` — proven evasion(s) fed back to Blue: "
                  + "; ".join(r.evasions[:3]) + (" …" if len(r.evasions) > 3 else ""))
            elif r.outcome == "converged":
                w(f"- **Round {r.round}** reached **real coverage** — the re-authored rule "
                  "defeated the prior evasions and resisted a fresh red-team pass.")
            elif r.outcome == "capped":
                w(f"- **Round {r.round}** hit the max-round cap while still `{r.verdict}` — "
                  "shipped to the gate, which flags non-real coverage for a human.")
        w("")

    w("## Detectable behaviors")
    for b in behaviors:
        w(f"- **{b.id}** ({b.attack_technique or 'n/a'}) — {b.description}  "
          f"_[evidence: {b.evidence.value}]_")
    w("")

    w("## Detection rule (Sigma)")
    w("```yaml")
    w(rule.yaml_text.strip())
    w("```")
    w("")

    w("## Deterministic evaluation")
    w("| metric | value |")
    w("|---|---|")
    w(f"| positives (must fire) | {ev.positives_total} |")
    w(f"| negatives (must stay silent) | {ev.negatives_total} |")
    w(f"| TP / FN | {ev.tp} / {ev.fn} |")
    w(f"| TN / FP | {ev.tn} / {ev.fp} |")
    w(f"| precision | {ev.precision} |")
    w(f"| recall | {ev.recall} |")
    w(f"| F1 | {ev.f1} |")
    w(f"| passed | {'yes' if ev.passed else 'NO'} |")
    if ev.failures:
        w("")
        for f in ev.failures:
            w(f"- ⚠️ {f}")
    w("")

    w("## Adversarial mutation battery (deterministic)")
    w(f"{adv.evaded}/{adv.total} mutations evaded — evasion rate **{adv.evasion_rate}**.")
    w("")
    w("| mutation | class | severity | evaded? |")
    w("|---|---|---|---|")
    for m in adv.mutations:
        w(f"| {m.description} | {m.mutation_class} | {m.severity} | "
          f"{'🔴 YES' if m.evaded else 'green no'} |")
    if adv.high_severity_evasions:
        w("")
        w("**High-severity evasions:**")
        for e in adv.high_severity_evasions:
            w(f"- 🔴 {e}")
    w("")

    if red_team:
        w("## Red-team proposals (final round) — engine-verified, never trusted")
        w("| proposal | class | severity | engine result |")
        w("|---|---|---|---|")
        for p in red_team:
            result = "🔴 VERIFIED bypass (rule did not fire)" if p.verified \
                else "🟢 discarded — rule fired (claim unproven)"
            w(f"| {p.description} | {p.mutation_class} | {p.severity} | {result} |")
        w("")
        w("> The Red-Team agent only *proposes*. Each event is replayed through the deterministic "
          "engine: a bypass is counted **only** if the engine confirms the rule failed to fire. "
          "Proposals the rule catches are discarded — the adversary cannot assert a bypass.")
        w("")

    w("## Coverage verdict")
    w(f"**{_VERDICT_BADGE[coverage.verdict]}**")
    w("")
    for r in coverage.rationale:
        w(f"- {r}")
    if coverage.remediation:
        w("")
        w("**Recommended remediation:**")
        for r in coverage.remediation:
            w(f"- {r}")
    w("")

    w("## Kartikeya's Gate — `Blast Radius × Capability Delta`")
    w(f"- **Blast radius:** {gate.blast_radius}")
    w(f"- **Capability delta:** {gate.capability_delta}")
    w(f"- **Score:** {gate.score}  →  **{gate.tier}**")
    w(f"- **Requires human approval:** {'YES' if gate.requires_human else 'no'}")
    w("")
    for r in gate.rationale:
        w(f"- {r}")
    w("")

    if blue_sources or red_sources:
        w("## Grounding — retrieved prior art (RAG)")
        w("Both proposers are grounded in real, researcher-authored OSS content. The retriever is "
          "lexical (offline, deterministic) and is **never** consulted by the proof engine.")
        w("")
        if blue_sources:
            w("**🔵 Blue authored from:**")
            for c in blue_sources:
                w(f"- [{c.source} · {'/'.join(c.techniques) or 'n/a'}] {c.title} "
                  f"_(relevance {c.score})_")
        if red_sources:
            w("")
            w("**🔴 Red attacked from:**")
            for c in red_sources:
                w(f"- [{c.source} · {'/'.join(c.techniques) or 'n/a'}] {c.title} "
                  f"_(relevance {c.score})_")
        w("")

    w("## Proven vs. authored (honesty contract)")
    w("| element | origin |")
    w("|---|---|")
    w(f"| Threat normalization, behaviors, rule, corpus | 🟡 agent-authored (`{mode}`) — a seam |")
    w("| Red-team evasion proposals | 🟡 agent-proposed — then engine-verified below |")
    w("| FP/FN evaluation | 🟢 proven — deterministic engine over the corpus |")
    w("| Adversarial evasion results (battery + verified red-team) | 🟢 proven — deterministic engine |")
    w("| Coverage verdict | 🟢 proven — computed from the numbers above |")
    w("| Self-repair loop & convergence | 🟢 driven by the deterministic verdict, not the model |")
    w("| Gate decision & human requirement | 🟢 enforced — structural, in code |")
    w("")
    w("> Agents propose; the engine proves. A red-team bypass is counted only when the engine "
      "confirms the rule failed to fire; the loop repairs until coverage is proven real (or the "
      "cap is hit). Deployment is egress and is structurally gated behind a human — the authoring "
      "agents cannot push this rule.")
    w("")
    return "\n".join(L)
