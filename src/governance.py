"""
Kartikeya's Gate for detection deployment — Gate = Blast Radius × Capability Delta.

This is where trust is *computed and enforced*, not asserted. The autonomous
graph can author, test, and adversarially probe a detection all day; it can
NEVER push it. Deployment is an egress action, and egress is gated here.

Two independent axes, each in [0, 1]:

  Blast Radius  — how much harm a WRONG-or-misused artifact does once live.
                  Driven by false-alarm rate (analyst fatigue / disruption),
                  rule severity × whether a hit auto-acts, deployment scope,
                  prod-vs-lab, and — critically — brittleness (a brittle rule
                  ships false confidence, which is its own blast).

  Capability Δ  — how much NEW power deploying grants relative to now.
                  Driven by egress (push off-box), automated response
                  (can now act on hosts), and prod reach.

score = blast_radius * capability_delta

Structural invariants (not heuristics — hard rules):
  * Any egress  -> requires_human = True, always.
  * coverage != real-coverage -> blast_radius floored high + requires_human.
These cannot be reasoned away by a persuasive model; they are in the code path.
"""
from __future__ import annotations

import hashlib
import json

from .state import CoverageLabel, CoverageVerdict, DeployIntent, GateDecision

_SEVERITY_WEIGHT = {
    "informational": 0.1,
    "low": 0.3,
    "medium": 0.55,
    "high": 0.8,
    "critical": 1.0,
}

_HUMAN_REQUIRED = "HUMAN_REQUIRED"
_HUMAN_RECOMMENDED = "HUMAN_RECOMMENDED"
_AUTO_OK = "AUTO_OK"


def _clamp(x: float) -> float:
    return max(0.0, min(1.0, x))


def compute_gate(
    *,
    level: str,
    fp_rate: float,
    coverage: CoverageLabel,
    intent: DeployIntent,
) -> GateDecision:
    """
    Compute the deployment gate. `fp_rate` is the measured false-positive rate
    on the benign baseline (1 - precision). All inputs are DETERMINISTIC outputs
    of the eval/adversarial stages — the gate never consults an LLM.
    """
    rationale: list[str] = []
    sev = _SEVERITY_WEIGHT.get(level.lower(), 0.55)

    # ---- Blast Radius ----
    action_w = 1.0 if intent.automated_response else 0.35
    scope_w = 1.0 if intent.scope == "fleet" else 0.55
    prod_w = 1.0 if intent.prod else 0.4

    blast = _clamp(scope_w * (0.45 * sev * action_w + 0.35 * fp_rate + 0.20 * prod_w))
    rationale.append(
        f"blast: severity={level}({sev:.2f}) × action={'auto' if intent.automated_response else 'alert-only'}"
        f"({action_w:.2f}), fp_rate={fp_rate:.2f}, scope={intent.scope}({scope_w:.2f}), "
        f"prod={intent.prod} → {blast:.2f}"
    )

    # Honesty overlay: a brittle/broken rule carries hidden blast (false confidence).
    if coverage.verdict is not CoverageVerdict.real:
        floored = max(blast, 0.6)
        rationale.append(
            f"coverage={coverage.verdict.value} → blast floored {blast:.2f}→{floored:.2f} "
            f"(shipping unproven coverage is itself a blast risk)"
        )
        blast = floored

    # ---- Capability Delta ----
    cap = 0.15  # a persistent detection is itself a small standing capability
    if intent.egress:
        cap += 0.35
    if intent.automated_response:
        cap += 0.45
    if intent.prod:
        cap += 0.20
    cap = _clamp(cap)
    rationale.append(
        f"capability Δ: base 0.15"
        f"{' +egress 0.35' if intent.egress else ''}"
        f"{' +auto-response 0.45' if intent.automated_response else ''}"
        f"{' +prod 0.20' if intent.prod else ''} → {cap:.2f}"
    )

    score = round(blast * cap, 4)

    # ---- Tiering ----
    if score >= 0.5:
        tier = _HUMAN_REQUIRED
    elif score >= 0.25:
        tier = _HUMAN_RECOMMENDED
    else:
        tier = _AUTO_OK

    requires_human = tier != _AUTO_OK

    # ---- Hard structural invariants (override tiering) ----
    if intent.egress:
        requires_human = True
        computed_tier = tier
        tier = _HUMAN_REQUIRED
        rationale.append(
            f"STRUCTURAL: egress → human approval mandatory (harness holds the privilege); "
            f"tier {computed_tier}→{_HUMAN_REQUIRED}"
        )
    if coverage.verdict is not CoverageVerdict.real:
        requires_human = True
        rationale.append("STRUCTURAL: non-real coverage → human approval mandatory")

    return GateDecision(
        blast_radius=round(blast, 4),
        capability_delta=round(cap, 4),
        score=score,
        tier=tier,
        requires_human=requires_human,
        approval_token=None,   # issued ONLY by issue_approval() after a real human decision
        rationale=rationale,
    )


def issue_approval(decision: GateDecision, bundle_hash: str, approver: str) -> str:
    """
    Mint an approval token binding a specific gate decision to a specific bundle.
    deploy_detection() (mcp_server) refuses any token that doesn't verify against
    the live bundle hash — so an approval cannot be replayed onto a different rule.
    """
    payload = f"{decision.tier}|{decision.score}|{bundle_hash}|{approver}"
    return "gate:" + hashlib.sha256(payload.encode()).hexdigest()[:32]


def verify_approval(token: str | None, decision: GateDecision, bundle_hash: str, approver: str) -> bool:
    if not token:
        return False
    return token == issue_approval(decision, bundle_hash, approver)


def canonical_hash(obj: dict) -> str:
    """Stable content hash — the reproducibility proof stamped into every bundle."""
    blob = json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)
    return "sha256:" + hashlib.sha256(blob.encode()).hexdigest()
