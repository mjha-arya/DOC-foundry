"""
Strict, security-conscious typed state for the Detection-as-Code Foundry.

Every artifact that flows through the graph is a Pydantic model, and every
model that carries a model-authored claim also carries an EvidenceStrength —
so "real vs. seam" is a *structural field*, not a comment. The deterministic
engine (engine.py) never trusts these labels; it recomputes truth. The labels
exist so the human at the gate sees exactly which parts were reasoned by an LLM
and which parts were proven.
"""
from __future__ import annotations

import operator
from enum import Enum
from typing import Annotated, Any, TypedDict

from pydantic import BaseModel, Field


# --------------------------------------------------------------------------- #
# Provenance / honesty primitives
# --------------------------------------------------------------------------- #
class EvidenceStrength(str, Enum):
    """How grounded a claim is. The gate weighs `assumed` claims as blast risk."""
    confirmed = "confirmed"   # lifted directly from the source artifact
    inferred = "inferred"     # reasoned from the source, defensible
    assumed = "assumed"       # model assumption — an explicit seam


class SourceType(str, Enum):
    cve = "cve"
    kev = "kev"                # CISA Known Exploited Vulnerabilities
    writeup = "writeup"        # vendor / researcher report
    attack_technique = "attack_technique"


# --------------------------------------------------------------------------- #
# Threat + behavior models
# --------------------------------------------------------------------------- #
class LogSource(BaseModel):
    category: str | None = None   # e.g. process_creation
    product: str | None = None    # e.g. windows
    service: str | None = None     # e.g. sysmon


class ThreatContext(BaseModel):
    source_type: SourceType
    source_ref: str
    title: str
    summary: str
    platforms: list[str] = Field(default_factory=list)
    attack_techniques: list[str] = Field(default_factory=list)   # ["T1105"]
    iocs: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    provenance: EvidenceStrength = EvidenceStrength.confirmed


class DetectableBehavior(BaseModel):
    id: str
    description: str
    attack_technique: str | None = None
    log_source: LogSource
    telemetry_fields: list[str] = Field(default_factory=list)
    rationale: str
    evidence: EvidenceStrength = EvidenceStrength.inferred


# --------------------------------------------------------------------------- #
# Rule + corpus
# --------------------------------------------------------------------------- #
class SigmaRuleArtifact(BaseModel):
    title: str
    rule_id: str
    yaml_text: str
    detection: dict[str, Any]            # parsed `detection:` block → fed to engine
    logsource: LogSource
    level: str = "medium"                # informational|low|medium|high|critical
    backends: dict[str, str] = Field(default_factory=dict)  # name -> converted query


class TestCorpus(BaseModel):
    """Positives the rule MUST fire on; negatives it MUST stay silent on."""
    positives: list[dict[str, Any]] = Field(default_factory=list)
    negatives: list[dict[str, Any]] = Field(default_factory=list)
    notes: str = ""


# --------------------------------------------------------------------------- #
# Evaluation + adversarial
# --------------------------------------------------------------------------- #
class EvalResult(BaseModel):
    tp: int
    fp: int
    tn: int
    fn: int
    precision: float
    recall: float
    f1: float
    positives_total: int
    negatives_total: int
    passed: bool
    failures: list[str] = Field(default_factory=list)


class Mutation(BaseModel):
    id: str
    mutation_class: str        # casing | whitespace | flag-substitution | binary-rename | ...
    severity: str              # low | medium | high
    description: str
    event: dict[str, Any]
    evaded: bool | None = None  # True = rule FAILED to fire on the mutated malicious event


class AdversarialResult(BaseModel):
    mutations: list[Mutation] = Field(default_factory=list)
    total: int = 0
    evaded: int = 0
    evasion_rate: float = 0.0
    high_severity_evasions: list[str] = Field(default_factory=list)
    survived: bool = True       # survived = no material evasion


class CoverageVerdict(str, Enum):
    real = "real-coverage"      # fires on all positives, silent on negatives, resists evasion
    brittle = "brittle"          # works on the sample but trivially evaded / noisy
    broken = "broken"            # misses the very behavior it targets


class CoverageLabel(BaseModel):
    verdict: CoverageVerdict
    rationale: list[str] = Field(default_factory=list)
    remediation: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# Red-team proposals + convergence history (adversarial multi-agent workflow)
# --------------------------------------------------------------------------- #
class RedTeamProposal(BaseModel):
    """An evasion PROPOSED by the Red-Team agent. ``fired`` / ``verified`` are set
    by the DETERMINISTIC engine, never by the model: a proposal counts as a real
    evasion only if the engine confirms the rule fails to fire on the event.
    Unverified proposals (the rule catches them) are discarded, never trusted."""
    id: str
    mutation_class: str
    severity: str = "medium"
    description: str = ""
    event: dict[str, Any] = Field(default_factory=dict)
    fired: bool | None = None       # did the rule fire on this event? (engine-computed)
    verified: bool | None = None    # verified evasion == engine confirms it did NOT fire


class Citation(BaseModel):
    """A retrieved prior-art document from the detection knowledge base (RAG).
    Grounds a PROPOSER (Blue or Red) in real researcher-authored work — it never
    touches the deterministic proof, so it is not part of the reproducibility hash."""
    doc_id: str
    title: str
    source: str                     # e.g. "SigmaHQ", "MITRE ATT&CK", "LOLBAS Project"
    techniques: list[str] = Field(default_factory=list)
    score: float = 0.0
    snippet: str = ""


class RoundRecord(BaseModel):
    """One turn of the Blue↔Red self-repair loop, captured for the convergence report."""
    round: int
    rule_id: str
    rule_title: str
    level: str
    verdict: str
    tp: int = 0
    fp: int = 0
    fn: int = 0
    battery_evaded: int = 0
    redteam_proposed: int = 0
    redteam_verified: int = 0
    evasions: list[str] = Field(default_factory=list)
    remediation: list[str] = Field(default_factory=list)
    outcome: str = ""               # repair | converged | capped


# --------------------------------------------------------------------------- #
# Kartikeya's Gate
# --------------------------------------------------------------------------- #
class DeployIntent(BaseModel):
    """The *proposed* deployment whose trust the gate scores. v1 never executes it."""
    egress: bool = True                 # push off-box to a SIEM = egress
    automated_response: bool = False    # does a hit trigger host action?
    scope: str = "single"               # single | fleet
    prod: bool = True


class GateDecision(BaseModel):
    blast_radius: float                 # [0,1]
    capability_delta: float             # [0,1]
    score: float                        # blast_radius * capability_delta
    tier: str                           # AUTO_OK | HUMAN_RECOMMENDED | HUMAN_REQUIRED
    requires_human: bool
    approval_token: str | None = None   # issued only after a human approves; deploy needs it
    rationale: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# The shippable bundle
# --------------------------------------------------------------------------- #
class ProofBundle(BaseModel):
    threat: ThreatContext
    rule: SigmaRuleArtifact
    corpus: TestCorpus
    evaluation: EvalResult
    adversarial: AdversarialResult
    coverage: CoverageLabel
    gate: GateDecision
    report_md: str
    content_hash: str = ""              # sha256 over canonical JSON → reproducibility proof
    mode: str = "fixture"              # claude | fixture (the authoring seam, labeled)


# --------------------------------------------------------------------------- #
# LangGraph channel state
# --------------------------------------------------------------------------- #
class FoundryState(TypedDict, total=False):
    # inputs
    raw_threat: str
    source_type: str
    source_ref: str
    deploy_intent: DeployIntent
    mode: str
    corpus_source: str                  # "model" (LLM-authored) | "atomic" (Atomic Red Team)
    # self-repair loop control
    round: int                          # current Blue↔Red round (1-based; blue_author increments)
    max_rounds: int                     # convergence cap (default 3)
    # accumulating artifacts
    threat: ThreatContext
    behaviors: list[DetectableBehavior]
    rule: SigmaRuleArtifact
    corpus: TestCorpus
    evaluation: EvalResult
    adversarial: AdversarialResult
    coverage: CoverageLabel
    gate: GateDecision
    bundle: ProofBundle
    bundle_dir: str
    # red-team (current round): raw LLM proposals + engine-verified proposals
    red_team_raw: list[dict]
    red_team: list[RedTeamProposal]
    red_refused: bool                   # adversary declined/unparseable → round was NOT adversarially tested
    # The FIXED adversary test set: the 2 real attacks Red commits to in round 1, then
    # re-tested (unchanged) against the hardened rule every later round — the same
    # "built once, can't move its goalposts" discipline as the Telemetry corpus. This is
    # what makes honest convergence reachable: Blue closes a fixed pair of gaps rather
    # than chasing a fresh adversary each round. Set once; persists across rounds.
    red_team_frozen: list[dict]
    # Blue authored a rule the deterministic engine will not evaluate (an unsupported
    # Sigma construct). Not a crash and never a pass: the round is BROKEN and this
    # message is the evidence Blue re-authors from. Cleared on each new round.
    rule_error: str
    # RAG grounding (current round): prior art each proposer retrieved
    blue_sources: list[Citation]
    red_sources: list[Citation]
    # ACCUMULATED GAP MEMORY — the whole point of the self-repair loop working instead of
    # oscillating. Every attack event Blue has ever let bypass, and every benign event it
    # has ever wrongly fired on, appended across ALL rounds (deduped when shown to Blue).
    # Without this, Blue only sees the LAST round's gap and ping-pongs — closing round 2's
    # false positives by reopening round 1's evasion, forever. With it, Blue's re-author
    # must satisfy every constraint it has ever seen at once, so the final pass consolidates
    # instead of trading one gap for another. These feed Blue's prompt only; they never
    # enter the proof or the reproducibility hash.
    seen_evasions: Annotated[list[dict], operator.add]   # attack events Blue MUST catch
    seen_fps: Annotated[list[dict], operator.add]        # benign events Blue must NOT fire on
    # convergence history (append-only via reducer)
    rounds: Annotated[list[RoundRecord], operator.add]
    # narration (append-only via reducer)
    log: Annotated[list[str], operator.add]
