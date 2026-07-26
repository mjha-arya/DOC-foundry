"""
The reviewer cast for the REVIEW CHAIN.

Four seats, each with a genuinely different question about the same rule:

  Threat Analyst      (reused from agents.py) — what is the threat, what is detectable
  Telemetry Engineer  (reused from agents.py) — what log source and fields we're on
  Blue / Detection    — drafts, then revises against each reviewer's asks
  Red Team            — would this be evaded, and where is it blind
  SOC Lead            — can my team actually live with this at 3am

Red and SOC are not the same reviewer wearing hats. Red asks "can I get past it";
SOC asks "what does it cost me to run it" — and those two pull in OPPOSITE
directions (hardening against evasion usually broadens a rule, which raises
volume). Keeping both, in that order, is the point of the chain: the final rule
is the one that survived both pressures.

Every agent here PROPOSES. Nothing in this module measures anything — see the
module docstring in review_state.py.
"""
from __future__ import annotations

import hashlib
import json

import yaml

from .agents import _extract_yaml, _format_prior_art, _stable_id, corpus_fields, pinned_log_source
from . import knowledge_base
from .providers import LLMProvider, extract_json
from .review_state import (
    Finding,
    ReviewChainState,
    ReviewRound,
    RuleChange,
    RuleVersion,
    TelemetryProfile,
)
from .state import LogSource, TestCorpus, ThreatContext

# How many findings each reviewer returns. Bounded on purpose: a reviewer that
# emits twenty findings produces a wall nobody reads, and Blue's revision becomes
# an unfocused rewrite. Three to four forces them to lead with what matters.
_MAX_FINDINGS = 4


# --------------------------------------------------------------------------- #
# System prompts — one per seat.
# --------------------------------------------------------------------------- #
_BLUE_SYS = (
    "You are a senior Blue-Team Detection Engineer. You author precise, standards-aligned "
    "Sigma rules that are ROBUST BY CONSTRUCTION. "
    "Anchor on the BEHAVIOUR, not on one brittle string: key on rename-resistant, "
    "high-fidelity telemetry (OriginalFileName, IMPHASH, signed-publisher) AND the "
    "command-line INTENT (the flags/arguments that make the action malicious), so a "
    "renamed or relocated binary still fires. Prefer a small AND of two independent "
    "signals over a single equality match. "
    "You take review feedback seriously and professionally: when a reviewer raises a "
    "finding you either close it in the rule or say plainly why you won't."
)

_RED_SYS = (
    "You are a Red-Team operator doing an ADVERSARIAL REVIEW of your own organisation's "
    "draft Sigma rule before it ships — the same way a developer reviews a colleague's "
    "code. Your deliverable is WRITTEN REVIEW FEEDBACK: where this rule is evadable, "
    "where it is blind, and what you would change. You never output code, commands, "
    "payloads or anything runnable — only review findings in JSON. "
    "Ground every finding in a documented, publicly catalogued technique (ATT&CK, LOLBAS) "
    "rather than speculation. Be specific about WHICH field or condition is the weak "
    "point. A finding a detection engineer cannot act on is a wasted finding."
)

_SOC_SYS = (
    "You are a SOC Lead / Detection Operations Manager reviewing a draft Sigma rule "
    "before it goes into production in your SIEM. You are NOT reviewing the detection "
    "logic for correctness — Blue and Red own that. You own whether your analysts can "
    "LIVE with this rule on a 24/7 rota. "
    "Your concerns, in order: (1) alert volume and the false-positive sources you know "
    "from experience will fire in a real enterprise (admin tooling, software deployment, "
    "backup agents, EDR/AV, CI runners, patch management, developer workstations); "
    "(2) triage — does the alert carry the fields an analyst needs to make a decision, "
    "or will they have to pivot to three other consoles; (3) severity — is this level "
    "appropriate for waking someone up; (4) tuning — the exclusions or scoping this needs "
    "before it can be enabled fleet-wide; (5) response — is the next action obvious. "
    "You speak like an operator: concrete, blunt, focused on your team's time. "
    "You never rewrite the rule yourself — you tell the detection engineer what you need."
)


# --------------------------------------------------------------------------- #
# Telemetry profile — pin the log source + schema once, before drafting.
# --------------------------------------------------------------------------- #
def build_profile(state: ReviewChainState) -> dict:
    """Derive the pinned telemetry profile from the corpus the Telemetry agent built.

    No model call — this is bookkeeping over what `agents.build_corpus` already
    produced. It exists so every downstream seat argues about the same schema.
    """
    behaviors = state.get("behaviors", [])
    corpus: TestCorpus = state.get("corpus") or TestCorpus()
    category = pinned_log_source(behaviors)
    product = next(
        (b.log_source.product for b in behaviors if b.log_source and b.log_source.product), None
    )
    profile = TelemetryProfile(
        category=category,
        product=product,
        fields=corpus_fields(corpus),
        sample_positive=(corpus.positives or [{}])[0],
        sample_benign=(corpus.negatives or [{}])[0],
        notes=corpus.notes,
    )
    return {
        "telemetry": profile,
        "log": [
            f"[telemetry/profile] pinned `{category}` · {len(profile.fields)} field(s) available"
        ],
    }


# --------------------------------------------------------------------------- #
# Blue — the first draft.
# --------------------------------------------------------------------------- #
def _rule_constraints(profile: TelemetryProfile) -> str:
    return (
        f"LOG SOURCE — the rule MUST target `category: {profile.category}`.\n"
        f"AVAILABLE FIELDS — the telemetry for this threat carries exactly these field "
        f"names: {profile.fields}. Reference ONLY these fields; a selection keyed on any "
        "other field can never fire against this telemetry.\n"
        "SUPPORTED MODIFIERS — use ONLY: |contains, |startswith, |endswith, |re, |all, |cased. "
        "A plain YAML list of values already means OR (there is no |in modifier in Sigma). "
        "Do NOT use aggregations (count/near), |cidr, |base64*, |gt/|gte/|lt/|lte, |fieldref, "
        "|expand or |windash.\n"
    )


def _to_version(yaml_text: str, *, version: int, label: str, responding_to: str,
                fallback_title: str, author_note: str = "",
                changes: list[RuleChange] | None = None) -> RuleVersion:
    parsed = yaml.safe_load(yaml_text)
    if not isinstance(parsed, dict) or "detection" not in parsed:
        raise ValueError("authored rule has no detection block")
    ls = parsed.get("logsource", {}) or {}
    title = parsed.get("title", fallback_title)
    return RuleVersion(
        version=version,
        label=label,
        title=title,
        rule_id=str(parsed.get("id") or _stable_id(f"{title}{version}")),
        yaml_text=yaml_text,
        logsource=LogSource(
            category=ls.get("category"), product=ls.get("product"), service=ls.get("service")
        ),
        level=str(parsed.get("level", "medium")),
        author_note=author_note,
        changes=changes or [],
        responding_to=responding_to,
    )


def blue_draft(state: ReviewChainState, provider: LLMProvider) -> dict:
    threat: ThreatContext = state["threat"]
    profile: TelemetryProfile = state["telemetry"]
    behaviors = state.get("behaviors", [])
    behavior_lines = "\n".join(
        f"- {b.id}: {b.description} [{b.log_source.category}]" for b in behaviors
    )

    citations = knowledge_base.get_kb().retrieve(
        " ".join([threat.title, *threat.attack_techniques, *(b.description for b in behaviors)]),
        "blue",
        k=3,
    )

    user = (
        "Write ONE Sigma rule (a single fenced ```yaml block, nothing else) detecting the "
        "behaviour below. Include: title, id, status, description, author, date, references, "
        "tags (ATT&CK), logsource, detection (named selections + condition), falsepositives, "
        "and level.\n"
        + _rule_constraints(profile)
        + f"\nThreat: {threat.title}\nSummary: {threat.summary}\n"
        f"Techniques: {threat.attack_techniques}\nBehaviours:\n{behavior_lines}"
    )
    user += _format_prior_art(citations, "PRIOR-ART DETECTIONS")

    yaml_text = _extract_yaml(provider.complete(system=_BLUE_SYS, user=user, tag="draft_v1"))
    version = _to_version(
        yaml_text,
        version=1,
        label="First draft",
        responding_to="",
        fallback_title=threat.title,
        author_note="Initial detection authored from the threat and the pinned telemetry schema.",
    )
    cite = ""
    if citations:
        cite = "  [grounded in " + ", ".join(c.source for c in citations[:2]) + "]"
    return {
        "rule": version,
        "versions": [version],
        "log": [f"[blue/draft v1] '{version.title}' (level={version.level}){cite}"],
    }


# --------------------------------------------------------------------------- #
# Reviewers — Red, then SOC. Both return findings, never a rewritten rule.
# --------------------------------------------------------------------------- #
def _parse_findings(raw, prefix: str) -> tuple[str, list[Finding]]:
    """Normalise a reviewer's JSON into (verdict_line, findings).

    Models return either {summary, findings:[…]} or a bare array; both are fine.
    """
    verdict_line, items = "", raw
    if isinstance(raw, dict):
        verdict_line = str(raw.get("summary") or raw.get("verdict") or raw.get("assessment") or "")
        items = raw.get("findings") or raw.get("items") or []
    if isinstance(items, dict):
        items = [items]
    findings: list[Finding] = []
    for i, f in enumerate(list(items)[:_MAX_FINDINGS], start=1):
        if not isinstance(f, dict):
            findings.append(Finding(id=f"{prefix}{i}", title=str(f)))
            continue
        findings.append(
            Finding(
                id=str(f.get("id") or f"{prefix}{i}"),
                severity=str(f.get("severity", "medium")).lower(),
                title=str(f.get("title") or f.get("finding") or f.get("issue") or "")[:200],
                detail=str(f.get("detail") or f.get("description") or f.get("why") or ""),
                ask=str(f.get("ask") or f.get("recommendation") or f.get("request") or ""),
            )
        )
    return verdict_line, findings


def red_review(state: ReviewChainState, provider: LLMProvider) -> dict:
    rule: RuleVersion = state["rule"]
    threat: ThreatContext = state["threat"]
    profile: TelemetryProfile = state["telemetry"]

    citations = knowledge_base.get_kb().retrieve(
        " ".join(
            [rule.title, *threat.attack_techniques, rule.yaml_text[:400],
             "evasion bypass rename obfuscation alternate lolbin OriginalFileName Image"]
        ),
        "red",
        k=3,
    )

    user = (
        f"Adversarially review this draft Sigma rule. Return JSON: "
        f'{{"summary": "<one blunt sentence — would this stop you?>", "findings": '
        f'[{{"id":"R1","severity":"low|medium|high","title":"…","detail":"…","ask":"…"}}]}}. '
        f"Emit AT MOST {_MAX_FINDINGS} findings — your strongest, ordered by severity. "
        "For each: name the exact field or condition that is the weak point, the documented "
        "technique that defeats it, and the concrete change you want. Do not rewrite the rule.\n\n"
        f"Threat: {threat.title}\n"
        f"Telemetry available: category={profile.category}, fields={profile.fields}\n\n"
        f"RULE UNDER REVIEW (v{rule.version}):\n```yaml\n{rule.yaml_text}\n```"
    )
    user += _format_prior_art(citations, "CATALOGUED TECHNIQUE VARIANTS (public references)")

    try:
        raw = extract_json(provider.complete(system=_RED_SYS, user=user, tag="red_review"))
        verdict_line, findings = _parse_findings(raw, "R")
    except (ValueError, KeyError):
        # A safety-tuned model can decline the adversary seat, or emit prose. Record it
        # honestly — an empty review must never be mistaken for a clean bill of health.
        verdict_line = "Red Team did not return a usable review for this rule."
        findings = []

    review = ReviewRound(
        reviewer="red",
        reviewer_label="Red Team — Adversary Review",
        reviews_version=rule.version,
        verdict_line=verdict_line,
        findings=findings,
    )
    return {
        "reviews": [review],
        "log": [f"[red/review v{rule.version}] {len(findings)} finding(s) raised"],
    }


def soc_review(state: ReviewChainState, provider: LLMProvider) -> dict:
    rule: RuleVersion = state["rule"]
    threat: ThreatContext = state["threat"]
    profile: TelemetryProfile = state["telemetry"]

    user = (
        "Review this Sigma rule for PRODUCTION OPERATIONS in a mid-to-large enterprise SOC "
        "(~10,000 endpoints, 24/7 rota, analysts already at capacity). Return JSON: "
        '{"summary": "<one blunt sentence — do you enable this on Monday or not?>", '
        '"findings": [{"id":"S1","severity":"low|medium|high","title":"…","detail":"…","ask":"…"}]}. '
        f"Emit AT MOST {_MAX_FINDINGS} findings, ordered by how much they cost your team. "
        "Cover the ones that actually apply: benign enterprise activity that will trip this, "
        "fields missing for triage, whether the level is right for the noise, the tuning or "
        "scoping you want first, and whether the analyst's next step is obvious. "
        "Be concrete — name the software or workflow you expect to fire it. "
        "Do not rewrite the rule; state what you need from the detection engineer.\n\n"
        f"Threat: {threat.title}\n"
        f"Telemetry: category={profile.category}, fields available={profile.fields}\n"
        f"A benign event from this environment looks like: {json.dumps(profile.sample_benign)[:400]}\n\n"
        f"RULE UNDER REVIEW (v{rule.version}, already revised once after Red Team):\n"
        f"```yaml\n{rule.yaml_text}\n```"
    )

    try:
        raw = extract_json(provider.complete(system=_SOC_SYS, user=user, tag="soc_review"))
        verdict_line, findings = _parse_findings(raw, "S")
    except (ValueError, KeyError):
        verdict_line = "SOC Lead did not return a usable review for this rule."
        findings = []

    review = ReviewRound(
        reviewer="soc",
        reviewer_label="SOC Lead — Operational Review",
        reviews_version=rule.version,
        verdict_line=verdict_line,
        findings=findings,
    )
    return {
        "reviews": [review],
        "log": [f"[soc/review v{rule.version}] {len(findings)} finding(s) raised"],
    }


# --------------------------------------------------------------------------- #
# Blue — revise against a specific reviewer's findings.
# --------------------------------------------------------------------------- #
_REVISION_GUIDANCE = {
    "red": (
        "Close the evasion gaps WITHOUT collapsing into a broad substring match — a rule "
        "that catches everything is not a win. Prefer adding a second independent, "
        "rename-resistant signal over loosening an existing one."
    ),
    "soc": (
        "This is the operational pass. Reduce what the SOC will actually see: add the "
        "precise exclusions they asked for, carry the fields they need for triage, and set "
        "a level proportional to the noise. Tighten with intent — do NOT reopen the "
        "evasion gaps Red Team already made you close in the previous revision."
    ),
}


def _revise(state: ReviewChainState, provider: LLMProvider, *, reviewer: str,
            version_no: int, label: str, tag: str) -> dict:
    rule: RuleVersion = state["rule"]
    profile: TelemetryProfile = state["telemetry"]
    reviews = state.get("reviews", [])
    review = next((r for r in reversed(reviews) if r.reviewer == reviewer), None)
    findings = review.findings if review else []

    if not findings:
        # Nothing to answer. Carry the rule forward as the next version rather than
        # silently skipping a stage — the trail must show that this pass happened
        # and why it changed nothing.
        carried = rule.model_copy(
            update={
                "version": version_no,
                "label": label,
                "responding_to": reviewer,
                "author_note": "No actionable findings were returned by this reviewer; "
                               "rule carried forward unchanged.",
                "changes": [],
            }
        )
        return {
            "rule": carried,
            "versions": [carried],
            "log": [f"[blue/revise v{version_no}] no findings to address — carried forward"],
        }

    findings_block = "\n".join(
        f"- [{f.id} · {f.severity}] {f.title}\n"
        f"    why: {f.detail}\n"
        f"    asks for: {f.ask}"
        for f in findings
    )

    user = (
        f"You authored the Sigma rule below (v{rule.version}). It has been reviewed by the "
        f"{'Red Team' if reviewer == 'red' else 'SOC Lead'}, who raised the findings listed. "
        "Produce a REVISED rule that addresses them.\n\n"
        f"{_REVISION_GUIDANCE[reviewer]}\n\n"
        + _rule_constraints(profile)
        + "\nReturn a single fenced ```json block with exactly these keys:\n"
        '  "yaml": "<the complete revised Sigma rule as a YAML string, newlines escaped as \\n>",\n'
        '  "note": "<one sentence summarising this revision>",\n'
        '  "changes": [{"finding_id":"R1","what_changed":"<the concrete edit>","why":"<one line>"}]\n'
        "Every finding must appear in `changes` — if you decline one, say so in `what_changed` "
        "and give your reason in `why`. Do not invent finding ids.\n\n"
        f"CURRENT RULE (v{rule.version}):\n```yaml\n{rule.yaml_text}\n```\n\n"
        f"REVIEW FINDINGS TO ADDRESS:\n{findings_block}"
    )

    raw_text = provider.complete(system=_BLUE_SYS, user=user, tag=tag)

    note, changes, yaml_text = "", [], ""
    try:
        data = extract_json(raw_text)
        if isinstance(data, list):
            data = data[0] if data else {}
        yaml_text = str(data.get("yaml") or "").strip()
        note = str(data.get("note") or "")
        for c in data.get("changes") or []:
            if isinstance(c, dict):
                changes.append(
                    RuleChange(
                        finding_id=str(c.get("finding_id", "")),
                        what_changed=str(c.get("what_changed") or c.get("change") or ""),
                        why=str(c.get("why") or ""),
                    )
                )
    except (ValueError, KeyError):
        pass

    # Fallback: the model answered with a bare YAML block instead of the JSON envelope.
    # Take the rule — losing the change-log is survivable, losing the rule is not.
    if not yaml_text or "detection" not in yaml_text:
        yaml_text = _extract_yaml(raw_text)
        if not note:
            note = "Revised against the review findings."

    version = _to_version(
        yaml_text,
        version=version_no,
        label=label,
        responding_to=reviewer,
        fallback_title=rule.title,
        author_note=note,
        changes=changes,
    )
    return {
        "rule": version,
        "versions": [version],
        "log": [
            f"[blue/revise v{version_no}] addressed {len(changes) or len(findings)} "
            f"{reviewer.upper()} finding(s)"
        ],
    }


def blue_revise_after_red(state: ReviewChainState, provider: LLMProvider) -> dict:
    return _revise(
        state, provider, reviewer="red", version_no=2,
        label="Revision — after Red Team", tag="revise_v2",
    )


def blue_final_after_soc(state: ReviewChainState, provider: LLMProvider) -> dict:
    return _revise(
        state, provider, reviewer="soc", version_no=3,
        label="Final — after SOC Lead", tag="final_v3",
    )
