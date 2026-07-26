"""
Typed state for the REVIEW CHAIN — the stakeholder-review pipeline.

This is a different product from the adversarial proof loop in `state.py` /
`graph.py`. That one asks "is this rule provably correct?" and answers with a
deterministic verdict. This one asks a different question:

    "What would each reviewer say about this rule, and what does it look like
     after their feedback is applied?"

The deliverable is a FINAL Sigma rule plus the complete, legible trail of how it
got there: draft → red-team feedback → revision → SOC-lead feedback → final.

There is deliberately NO scoring here — no coverage verdict, no FP/FN, no gate.
The proof core is untouched and still available through the classic pipeline;
this chain simply doesn't invoke it. Which means: nothing in this module verifies
that the final rule fires on anything. It is a reviewed rule, not a proven one,
and the packaged output says so in those words.
"""
from __future__ import annotations

from typing import Annotated, Any, TypedDict
import operator

from pydantic import BaseModel, Field

from .state import DetectableBehavior, LogSource, TestCorpus, ThreatContext


class Finding(BaseModel):
    """One piece of reviewer feedback on a specific rule version.

    `ask` is the actionable part — what the reviewer wants changed. Blue's
    revision is prompted against these, and each change it makes cites the
    finding id it answers, which is what makes the progression legible.
    """
    id: str                       # R1, R2… (red) / S1, S2… (SOC)
    severity: str = "medium"      # low | medium | high
    title: str                    # one-line headline
    detail: str = ""              # why it matters
    ask: str = ""                 # the concrete change requested


class ReviewRound(BaseModel):
    """A full pass by one reviewer over one version of the rule."""
    reviewer: str                 # "red" | "soc"
    reviewer_label: str           # "Red Team — Adversary Review"
    reviews_version: int          # which rule version was reviewed
    verdict_line: str = ""        # the reviewer's own one-line summary (prose, not a score)
    findings: list[Finding] = Field(default_factory=list)


class RuleChange(BaseModel):
    """One edit Blue made, tied to the finding that prompted it."""
    finding_id: str = ""
    what_changed: str = ""
    why: str = ""


class RuleVersion(BaseModel):
    """A Sigma rule at one point in the chain."""
    version: int                  # 1, 2, 3
    label: str                    # "First draft" | "Revision — after Red Team" | "Final"
    title: str
    rule_id: str
    yaml_text: str
    logsource: LogSource
    level: str = "medium"
    author_note: str = ""         # Blue's own summary of this pass
    changes: list[RuleChange] = Field(default_factory=list)
    responding_to: str = ""       # "" | "red" | "soc"


class TelemetryProfile(BaseModel):
    """The log source and field schema the whole chain is fought on.

    Pinned once, before drafting, so every reviewer and every revision is
    talking about the same telemetry. Without this the SOC lead comments on
    process-creation fields while Blue is writing a file-event rule.
    """
    category: str = "process_creation"
    product: str | None = None
    fields: list[str] = Field(default_factory=list)
    sample_positive: dict[str, Any] = Field(default_factory=dict)
    sample_benign: dict[str, Any] = Field(default_factory=dict)
    notes: str = ""


class ReviewPackage(BaseModel):
    """The shippable artifact: the final rule + the whole review trail."""
    threat: ThreatContext
    telemetry: TelemetryProfile
    versions: list[RuleVersion] = Field(default_factory=list)
    reviews: list[ReviewRound] = Field(default_factory=list)
    final_rule: RuleVersion | None = None
    history_md: str = ""
    mode: str = "claude"
    # Stated plainly in the packaged output. This chain reviews; it does not prove.
    disclaimer: str = (
        "Reviewed, not validated. This rule has been through adversarial and "
        "operational review by role-specialised agents; it has NOT been executed "
        "against a test corpus, and no false-positive/false-negative measurement "
        "was performed. Validate before deploying."
    )


class ReviewChainState(TypedDict, total=False):
    # inputs
    raw_threat: str
    source_type: str
    source_ref: str
    mode: str
    # accumulating artifacts
    threat: ThreatContext
    behaviors: list[DetectableBehavior]
    corpus: TestCorpus
    telemetry: TelemetryProfile
    rule: RuleVersion                    # the CURRENT rule under review
    package: ReviewPackage
    package_dir: str
    # append-only trails
    versions: Annotated[list[RuleVersion], operator.add]
    reviews: Annotated[list[ReviewRound], operator.add]
    log: Annotated[list[str], operator.add]
