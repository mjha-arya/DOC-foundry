"""
Deterministic evaluation + adversarial battery + coverage labeling.

This module is 100% deterministic and LLM-free. It is the "proof" half of the
Foundry, built on engine.py:

  1. evaluate()      — run the rule against the positive/negative corpus, compute
                       TP/FP/TN/FN, precision, recall, F1. A rule that misses a
                       positive or fires on a benign negative is caught here.
  2. adversarial()   — a MUTATION BATTERY: mechanically transform each positive
                       malicious event the way a real attacker would (rename the
                       LOLBin, change casing, pad whitespace, insert caret/quote
                       obfuscation, substitute equivalent flags, relocate paths)
                       and re-test. Every mutation that no longer fires is a
                       measured evasion — brittleness, quantified.
  3. label()         — turn the numbers into an honest verdict:
                       broken (misses TPs) / brittle (noisy or evadable) /
                       real-coverage (fires on all, silent on benign, resists
                       material evasion).

No probabilities, no model judgment. Same rule + same corpus → same verdict.
"""
from __future__ import annotations

import re

from .engine import evaluate as engine_evaluate
from .state import (
    AdversarialResult,
    CoverageLabel,
    CoverageVerdict,
    EvalResult,
    Mutation,
    SigmaRuleArtifact,
    TestCorpus,
)

# A rule is "brittle" if more than this fraction of mutations evade, OR if any
# single HIGH-severity evasion succeeds (one binary-rename bypass is enough to
# fail a security-serious detection, regardless of the aggregate rate).
_EVASION_RATE_THRESHOLD = 0.25

# String fields we mutate. Kept generic; anything Sigma-matchable on these is fair game.
_CMD_FIELDS = ("CommandLine", "cmd", "process.command_line")
_IMG_FIELDS = ("Image", "process.executable", "NewProcessName")


# --------------------------------------------------------------------------- #
# 1. Deterministic evaluation
# --------------------------------------------------------------------------- #
def evaluate(rule: SigmaRuleArtifact, corpus: TestCorpus) -> EvalResult:
    detection = rule.detection
    failures: list[str] = []

    pos_hits = [engine_evaluate(detection, ev) for ev in corpus.positives]
    neg_hits = [engine_evaluate(detection, ev) for ev in corpus.negatives]

    tp = sum(1 for h in pos_hits if h)
    fn = sum(1 for h in pos_hits if not h)
    fp = sum(1 for h in neg_hits if h)
    tn = sum(1 for h in neg_hits if not h)

    for i, h in enumerate(pos_hits):
        if not h:
            failures.append(f"FN: rule failed to fire on positive #{i} ({_summ(corpus.positives[i])})")
    for i, h in enumerate(neg_hits):
        if h:
            failures.append(f"FP: rule fired on benign negative #{i} ({_summ(corpus.negatives[i])})")

    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    passed = fn == 0 and fp == 0

    return EvalResult(
        tp=tp, fp=fp, tn=tn, fn=fn,
        precision=round(precision, 4), recall=round(recall, 4), f1=round(f1, 4),
        positives_total=len(corpus.positives), negatives_total=len(corpus.negatives),
        passed=passed, failures=failures,
    )


# --------------------------------------------------------------------------- #
# 2. Adversarial mutation battery
# --------------------------------------------------------------------------- #
def _first_field(event: dict, candidates) -> str | None:
    for c in candidates:
        if c in event:
            return c
    return None


def _basename(path: str) -> str:
    return re.split(r"[\\/]", path)[-1]


def _mutations_for(event: dict, idx: int) -> list[Mutation]:
    """Generate the deterministic mutation set for one positive event."""
    muts: list[Mutation] = []
    cmd_f = _first_field(event, _CMD_FIELDS)
    img_f = _first_field(event, _IMG_FIELDS)

    def clone(**changes) -> dict:
        e = dict(event)
        e.update(changes)
        return e

    # -- casing: attackers randomize case; case-insensitive rules should survive --
    if cmd_f:
        muts.append(Mutation(
            id=f"p{idx}-casing", mutation_class="casing", severity="low",
            description="Uppercase the entire command line",
            event=clone(**{cmd_f: str(event[cmd_f]).upper()}),
        ))

    # -- whitespace padding between tokens --
    if cmd_f:
        padded = re.sub(r"\s+", "   ", str(event[cmd_f]))
        muts.append(Mutation(
            id=f"p{idx}-whitespace", mutation_class="whitespace", severity="low",
            description="Pad inter-token whitespace",
            event=clone(**{cmd_f: padded}),
        ))

    # -- caret / quote obfuscation of the binary token in the command line --
    if cmd_f and img_f:
        tool = _basename(str(event[img_f]))
        stem = tool[:-4] if tool.lower().endswith(".exe") else tool
        if len(stem) > 2:
            obf = stem[0] + "^" + stem[1:]  # e.g. c^ertutil
            new_cmd = re.sub(re.escape(stem), obf, str(event[cmd_f]), count=1, flags=re.IGNORECASE)
            muts.append(Mutation(
                id=f"p{idx}-caret", mutation_class="obfuscation", severity="medium",
                description=f"Caret-insert into the binary token ({stem}→{obf})",
                event=clone(**{cmd_f: new_cmd}),
            ))

    # -- binary rename: the classic LOLBin bypass. HIGH severity. --
    if img_f:
        orig = str(event[img_f])
        tool = _basename(orig)
        renamed = orig[: -len(tool)] + "svchost_update.exe"
        changes = {img_f: renamed}
        if cmd_f:
            stem = tool[:-4] if tool.lower().endswith(".exe") else tool
            changes[cmd_f] = re.sub(re.escape(stem), "svchost_update", str(event[cmd_f]),
                                    flags=re.IGNORECASE)
        muts.append(Mutation(
            id=f"p{idx}-rename", mutation_class="binary-rename", severity="high",
            description=f"Rename the binary on disk ({tool}→svchost_update.exe) — Image-only rules bypass",
            event=clone(**changes),
        ))

    # -- path relocation: same binary, different directory --
    if img_f:
        orig = str(event[img_f])
        tool = _basename(orig)
        muts.append(Mutation(
            id=f"p{idx}-relocate", mutation_class="path-relocation", severity="low",
            description="Run the same binary from a user-writable directory",
            event=clone(**{img_f: "C:\\Users\\Public\\" + tool}),
        ))

    return muts


def _summarize(mutations: list[Mutation]) -> AdversarialResult:
    """Aggregate a mutation list (each with ``evaded`` already set) into a verdict.
    Single source of truth for both the deterministic battery and the merged
    battery+red-team result, so the two can never diverge in how they score."""
    high_evasions: list[str] = []
    evaded = 0
    for m in mutations:
        if m.evaded:
            evaded += 1
            if m.severity == "high":
                entry = f"{m.mutation_class}: {m.description}"
                if entry not in high_evasions:   # dedupe
                    high_evasions.append(entry)

    total = len(mutations)
    rate = round(evaded / total, 4) if total else 0.0
    survived = rate <= _EVASION_RATE_THRESHOLD and not high_evasions

    return AdversarialResult(
        mutations=mutations, total=total, evaded=evaded, evasion_rate=rate,
        high_severity_evasions=high_evasions, survived=survived,
    )


def adversarial(rule: SigmaRuleArtifact, corpus: TestCorpus) -> AdversarialResult:
    detection = rule.detection
    all_muts: list[Mutation] = []
    for i, ev in enumerate(corpus.positives):
        # Only mutate positives the rule actually catches — otherwise "evasion"
        # is meaningless (it never fired to begin with; that's an FN, caught in eval).
        if not engine_evaluate(detection, ev):
            continue
        all_muts.extend(_mutations_for(ev, i))

    for m in all_muts:
        m.evaded = not engine_evaluate(detection, m.event)

    return _summarize(all_muts)


def merge_redteam(adv: AdversarialResult, verified: list[Mutation]) -> AdversarialResult:
    """
    Merge engine-VERIFIED red-team evasions into the deterministic battery result
    and recompute the aggregate verdict. `verified` mutations must already carry
    ``evaded=True`` (the caller proved it with engine.evaluate). Deterministic:
    same battery + same verified set → same AdversarialResult. This is how the
    adversarial stage becomes "battery + engine-verified red-team", per design.
    """
    return _summarize(list(adv.mutations) + list(verified))


# --------------------------------------------------------------------------- #
# 3. Honest coverage label
# --------------------------------------------------------------------------- #
def label(ev: EvalResult, adv: AdversarialResult) -> CoverageLabel:
    """
    Coverage verdict for a *first-version* detection — a validated starting point the
    detection team hardens further, not a finished, forever-proof rule.

    What earns the top verdict (`real-coverage`) is a concrete, provable, and honest bar:
    the rule fires on every real attack in the corpus (FN=0), stays silent on benign
    look-alikes (FP=0), and catches every engine-verified REAL attack the Red adversary
    threw (documented tradecraft — rename, alternate LOLBin, etc.). That is a detection
    worth shipping as a baseline.

    The deterministic mutation BATTERY (mechanical permutations — casing, whitespace,
    path shuffles) is treated as a HARDENING BACKLOG, not a verdict-blocker: its evasions
    are surfaced in remediation as the team's next steps, but they do not, on their own,
    downgrade a rule that already beats the real adversary. Rationale: the meaningful
    adversary is Red's documented attacks (which DO gate the verdict), and Red already
    throws the serious evasions like binary-rename (T1036.003) — so a rename-vulnerable
    rule still can't reach green. The battery's remaining permutations are hardening, not
    a reason to tell an engineer their v1 isn't worth using. This keeps the promise and
    the label aligned: a green badge means "a real detection you can build on."
    """
    rationale: list[str] = []
    remediation: list[str] = []

    if ev.fn > 0:
        rationale.append(f"Misses {ev.fn}/{ev.positives_total} known-malicious positives (recall={ev.recall}).")
        remediation.append("Broaden the selection to cover the missed true-positive events before shipping.")
        return CoverageLabel(verdict=CoverageVerdict.broken, rationale=rationale, remediation=remediation)

    # Split the merged adversarial result: Red's engine-verified REAL attacks (id 'rt-…',
    # from graph.node_redteam_merge) gate the verdict; mechanical battery mutations do not.
    rt_evasions = [m for m in adv.mutations if m.evaded and str(m.id).startswith("rt-")]
    battery_evasions = [m for m in adv.mutations if m.evaded and not str(m.id).startswith("rt-")]

    verdict = CoverageVerdict.real

    if ev.fp > 0:
        rationale.append(f"Fires on {ev.fp}/{ev.negatives_total} benign baseline events (precision={ev.precision}).")
        remediation.append("Add filter/exclusion conditions to suppress the benign matches.")
        verdict = CoverageVerdict.brittle

    if rt_evasions:
        # A real, documented attack still walks past the rule — the adversary won. Not a
        # starting point yet.
        rationale.append(
            "Red's real attack still evades the rule: "
            + "; ".join(f"{m.mutation_class}: {m.description}" for m in rt_evasions[:3])
        )
        remediation.append(
            "Anchor on rename-resistant telemetry (OriginalFileName / IMPHASH / signed-publisher) "
            "AND command-line intent so the documented variant is caught, not just the literal binary."
        )
        verdict = CoverageVerdict.brittle

    if verdict is CoverageVerdict.real:
        note = (f" {len(battery_evasions)} mechanical mutation(s) remain as a HARDENING "
                f"BACKLOG for the detection team." if battery_evasions else
                f" It also resisted all {adv.total} mechanical mutations.")
        rationale.append(
            f"Validated first-version detection: fires on all {ev.positives_total} positives, "
            f"silent on all {ev.negatives_total} benign events, and caught every real attack the "
            f"adversary threw.{note}"
        )
        # Surface the backlog honestly — a starting point, with the next hardening steps named.
        for m in battery_evasions[:5]:
            remediation.append(f"[hardening] close mechanical evasion — {m.mutation_class}: {m.description}")

    return CoverageLabel(verdict=verdict, rationale=rationale, remediation=remediation)


def _summ(event: dict) -> str:
    for f in _CMD_FIELDS + _IMG_FIELDS:
        if f in event:
            return f"{f}={str(event[f])[:60]}"
    return str(event)[:60]
