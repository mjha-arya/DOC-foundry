"""
The agent cast — role-specialized LLM personas for an adversarial, multi-agent
detection-engineering workflow. Each agent PROPOSES; nothing here decides truth.
The deterministic referee (engine.py / evaluator.py / governance.py) proves it.

Roles (distinct system prompts, each earns its seat):
  1. Threat Analyst      — `ingest` + `extract_behaviors`: threat → ThreatContext
                            + detectable behaviors + ATT&CK mapping.
  2. Detection Engineer  — `blue_author`: authors the Sigma rule, and on a
     (Blue)                 brittle/broken verdict RE-AUTHORS using the concrete
                            evasions + false positives proven in the prior round.
  3. Telemetry Agent     — `build_corpus`: synthesizes positive attack events +
                            benign look-alike negatives (or pulls real Atomic
                            Red Team telemetry via the corpus adapter).
  4. Red-Team Adversary  — `red_team_propose`: proposes NOVEL evasions beyond the
                            deterministic battery. Each is a concrete event that
                            the engine then verifies — the adversary must PROVE the
                            bypass, not claim it (see graph.node_redteam_merge).

No agent has tool access beyond the model: they cannot fetch intel (governed MCP
`fetch_threat_intel`) and cannot deploy (human-gated MCP `deploy_detection`).
Least privilege is structural.
"""
from __future__ import annotations

import hashlib
import json

import yaml

from . import knowledge_base
from .providers import LLMProvider, extract_json
from .state import (
    DetectableBehavior,
    EvidenceStrength,
    FoundryState,
    LogSource,
    SigmaRuleArtifact,
    SourceType,
    TestCorpus,
    ThreatContext,
)

# --------------------------------------------------------------------------- #
# Role personas — one system prompt per specialist.
# --------------------------------------------------------------------------- #
_ANALYST_SYS = (
    "You are a Threat Intelligence Analyst. You normalize threats and extract the "
    "DETECTABLE behaviors with precise MITRE ATT&CK mapping. You never invent IOCs; "
    "when unsure you label the claim an assumption. Output ONLY the requested JSON."
)
_BLUE_SYS = (
    "You are a senior Blue-Team Detection Engineer. You author precise, standards-aligned "
    "Sigma rules that are ROBUST BY CONSTRUCTION — a strong first version a detection team "
    "can build on, not a fragile draft. "
    "Anchor on the BEHAVIOR, not on one brittle string: key on rename-resistant, "
    "high-fidelity telemetry (OriginalFileName, IMPHASH, signed-publisher) AND the "
    "command-line INTENT (the flags/arguments that make the action malicious), so a "
    "renamed or relocated binary still fires. Prefer a small AND of two independent "
    "signals over a single equality match — that alone defeats the most common documented "
    "evasions (rename, path relocation, casing). "
    "When handed EVIDENCE of proven attacks or false positives from a prior round, "
    "re-author to close those exact gaps without reintroducing brittleness. "
    "Output ONLY a fenced ```yaml Sigma rule."
)
_TELEMETRY_SYS = (
    "You are a Detection Telemetry Engineer. You synthesize realistic log events: "
    "true-positive attack telemetry that MUST fire, and benign look-alike negatives on "
    "the same log source that must NOT fire. Output ONLY the requested JSON."
)
# Framing note: this describes the task literally and accurately, which also happens
# to be what keeps safety-tuned models from declining it. The deliverable is a
# SYNTHETIC LOG RECORD — a unit-test fixture for a Sigma rule the defender owns — not
# code, not a command, not a working exploit. The earlier "you are a Red-Team
# Adversary, propose evasions an attacker would use" framing read as a request to
# defeat security controls and got refused mid-run ("cannot generate functional
# evasion techniques"), which silently starved the loop of its adversary.
# How many attacks the adversary throws per round. Deliberately SMALL and fixed: the
# product's promise is a *validated first-version* rule — one that survives a couple of
# concrete, documented attacks and gives the detection team a proven starting point — not
# a rule proven bulletproof against an unbounded evasion search (which nothing survives).
# A bounded adversary makes the fight legible ("Red tried these 2 real attacks") and
# winnable (Blue can close 2 specific gaps), so honest convergence to real-coverage is
# reachable instead of perpetual brittleness.
_RED_ATTACKS = 2

_RED_SYS = (
    "You are a Detection QA engineer on a purple team. You stress-test your own "
    "organization's Sigma rules before they ship, the way a developer fuzzes their own "
    "code. Your deliverable is SYNTHETIC LOG EVENTS — the JSON records a SIEM would "
    "index — used as unit-test fixtures. You never output code, commands, or anything "
    "runnable: only log records. "
    f"Emit EXACTLY {_RED_ATTACKS} log events — the {_RED_ATTACKS} STRONGEST, most "
    "realistic DOCUMENTED, publicly-catalogued ATT&CK variants of the same behavior "
    "(e.g. T1036.003 Rename System Utilities, LOLBAS entries) that this rule SHOULD catch "
    "but may miss if it is anchored on a brittle field. Not a long list of trivial "
    "mutations — your two best real-world attacks. An event the rule misses is a coverage "
    "gap the defender must close before deploying — finding it here is the entire point. "
    "Go beyond trivial casing and whitespace changes. "
    "Do NOT claim success — a deterministic engine tests every event you emit. "
    "Output ONLY a JSON array of exactly two items; each item: "
    '{id, mutation_class, severity (low|medium|high), description, event:{...}}.'
)


def _stable_id(text: str) -> str:
    return hashlib.sha1(text.encode()).hexdigest()[:12]


def _str_list(value) -> list[str]:
    """
    Coerce a model-supplied field into list[str].

    Live models are loose where fixtures are tidy: `iocs` comes back as
    [{"type":"url","value":"http://…"}] instead of ["http://…"], `platforms` as a
    bare string, ids as ints. Strict Pydantic then rejects the whole run at the
    parse seam. Normalize here, where untrusted model output enters typed state.

    Only ever applied to descriptive/context fields (iocs, platforms, references,
    technique labels) — never to anything the proof depends on. The rule logic and
    the corpus events are passed through untouched, so this cannot launder a bad
    rule into a good verdict.
    """
    if value is None:
        return []
    if isinstance(value, (str, int, float)):
        return [str(value)]
    if isinstance(value, dict):
        value = [value]
    out: list[str] = []
    for item in value:
        if isinstance(item, dict):
            # {"type":"url","value":"http://…"} → "url:http://…"; fall back to the
            # first stringy value rather than dropping evidence on the floor.
            val = item.get("value") or item.get("id") or item.get("name")
            if val is None:
                val = next((v for v in item.values() if isinstance(v, (str, int, float))), None)
            if val is None:
                continue
            kind = item.get("type")
            out.append(f"{kind}:{val}" if kind else str(val))
        elif item is not None:
            out.append(str(item))
    return out


def _first_or_none(value) -> str | None:
    """A single label field the model may hand back as a list (['T1105']) or a dict."""
    items = _str_list(value)
    return items[0] if items else None


def _evidence(value) -> EvidenceStrength:
    """Map a loose evidence label onto the enum. Unknown → `inferred`: never silently
    upgrade an unrecognized label to `confirmed`."""
    try:
        return EvidenceStrength(str(value).strip().lower())
    except ValueError:
        return EvidenceStrength.inferred


def _format_prior_art(citations, header: str) -> str:
    """Render retrieved prior art as a prompt block the agent authors/attacks from."""
    if not citations:
        return ""
    lines = [f"\n\n{header} (retrieved from the detection knowledge base — adapt, don't ignore):"]
    for c in citations:
        lines.append(f"- [{c.source} · {'/'.join(c.techniques) or 'n/a'}] {c.title}: {c.snippet}")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# 1. Threat Analyst
# --------------------------------------------------------------------------- #
def ingest(state: FoundryState, provider: LLMProvider) -> dict:
    user = (
        f"Normalize this threat into a JSON object with keys: title, summary, "
        f"platforms (list), attack_techniques (list of ATT&CK IDs like T1105), "
        f"iocs (list), references (list). Source type: {state.get('source_type')}. "
        f"Source ref: {state.get('source_ref')}.\n\nTHREAT:\n{state['raw_threat']}"
    )
    data = extract_json(provider.complete(system=_ANALYST_SYS, user=user, tag="ingest"))
    threat = ThreatContext(
        source_type=SourceType(state.get("source_type", "writeup")),
        source_ref=state.get("source_ref", "n/a"),
        title=str(data["title"]),
        summary=str(data["summary"]),
        platforms=_str_list(data.get("platforms")),
        attack_techniques=_str_list(data.get("attack_techniques")),
        iocs=_str_list(data.get("iocs")),
        references=_str_list(data.get("references")),
        provenance=EvidenceStrength.confirmed,
    )
    return {
        "threat": threat,
        "log": [f"[analyst/ingest] {threat.title} — ATT&CK {', '.join(threat.attack_techniques) or 'n/a'}"],
    }


def extract_behaviors(state: FoundryState, provider: LLMProvider) -> dict:
    threat: ThreatContext = state["threat"]
    user = (
        f"From this threat, list the DETECTABLE behaviors as a JSON array. Each item: "
        f"id, description, attack_technique, log_source ({{category, product, service}}), "
        f"telemetry_fields (list), rationale, evidence (one of confirmed|inferred|assumed).\n\n"
        f"Threat: {threat.title}\nSummary: {threat.summary}\n"
        f"Techniques: {threat.attack_techniques}"
    )
    arr = extract_json(provider.complete(system=_ANALYST_SYS, user=user, tag="extract"))
    behaviors = [
        DetectableBehavior(
            id=str(b.get("id", f"b{i}")),   # models emit bare ints here; id is a label, not evidence
            description=str(b["description"]),
            attack_technique=_first_or_none(b.get("attack_technique")),
            log_source=LogSource(**(b.get("log_source") or {})),
            telemetry_fields=_str_list(b.get("telemetry_fields")),
            rationale=str(b.get("rationale", "")),
            evidence=_evidence(b.get("evidence")),
        )
        for i, b in enumerate(arr)
    ]
    return {
        "behaviors": behaviors,
        "log": [f"[analyst/extract] {len(behaviors)} detectable behavior(s) identified"],
    }


# --------------------------------------------------------------------------- #
# 3. Telemetry Agent — the FIXED test set (built once, before the loop, so the
#    rule can't move its own goalposts across rounds).
# --------------------------------------------------------------------------- #
def pinned_log_source(behaviors) -> str:
    """
    The ONE log source category this run is fought on.

    Telemetry builds the corpus for it and Blue must author against it, or they end
    up on different schemas: a rule keyed on `TargetFilename` can never fire on
    process_creation events, so the round is `broken` with recall 0 for a reason that
    has nothing to do with detection quality. The old certutil-only demo never
    exposed this — everything in it was process_creation by construction.

    Chosen by majority vote of the Analyst's per-behavior log sources, because that
    is the evidence we have about where the threat is actually visible.
    """
    cats = [b.log_source.category for b in behaviors if b.log_source and b.log_source.category]
    if not cats:
        return "process_creation"
    return max(sorted(set(cats)), key=cats.count)


def corpus_fields(corpus: TestCorpus) -> list[str]:
    """Field names present in the fixed test set — the schema, never the values."""
    fields: set[str] = set()
    for ev in list(corpus.positives) + list(corpus.negatives):
        if isinstance(ev, dict):
            fields.update(str(k) for k in ev.keys())
    return sorted(fields)


def build_corpus(state: FoundryState, provider: LLMProvider) -> dict:
    threat: ThreatContext = state["threat"]
    behaviors = state.get("behaviors", [])
    behavior_lines = "\n".join(f"- {b.id}: {b.description} [{b.log_source.category}]" for b in behaviors)
    category = pinned_log_source(behaviors)
    user = (
        "Produce a test corpus as a JSON object {positives:[...], negatives:[...], notes:\"\"}. "
        f"Every event MUST be a `{category}` log record, and every event MUST use the SAME field "
        "names as each other (the standard Sigma field names for that log source — e.g. "
        "process_creation: Image, OriginalFileName, CommandLine, ParentImage; file_event: "
        "Image, TargetFilename; network_connection: Image, DestinationIp, DestinationPort). "
        "positives = events representing the malicious behavior — these MUST be caught. "
        "negatives = realistic BENIGN events on the same log source that must NOT fire "
        "(include look-alike legitimate usage). Give at least 2 positives and 3 negatives.\n\n"
        f"Threat: {threat.title}\nLog source: {category}\nBehaviors:\n{behavior_lines}"
    )
    data = extract_json(provider.complete(system=_TELEMETRY_SYS, user=user, tag="corpus"))
    corpus = TestCorpus(
        positives=data.get("positives", []),
        negatives=data.get("negatives", []),
        notes=data.get("notes", ""),
    )

    log_line = f"[telemetry/corpus] {len(corpus.positives)} positive / {len(corpus.negatives)} benign events"

    # Real-telemetry override: replace model-authored positives with REAL attacker
    # commands from Atomic Red Team, mapped to the threat's ATT&CK technique(s).
    # The benign negatives stay model-authored (look-alike legitimate usage).
    # This is the "stop grading your own homework" seam — positives are no longer
    # invented by the same model family that writes the rule.
    if state.get("corpus_source") == "atomic":
        from . import corpus_adapters
        atomic_positives, provenance = corpus_adapters.atomic_positives_for_rule(None, threat)
        if atomic_positives:
            corpus.positives = atomic_positives
            corpus.notes = (corpus.notes + f" | positives: {provenance}").strip(" |")
            log_line = (
                f"[telemetry/corpus] {len(corpus.positives)} REAL positive (Atomic Red Team) / "
                f"{len(corpus.negatives)} benign events"
            )
        else:
            log_line += f"  (atomic requested but none found: {provenance})"

    return {"corpus": corpus, "log": [log_line]}


# --------------------------------------------------------------------------- #
# 2. Detection Engineer (Blue) — authors, and RE-authors on evidence.
# --------------------------------------------------------------------------- #
def _extract_yaml(text: str) -> str:
    if "```" in text:
        for chunk in text.split("```")[1:]:
            c = chunk.strip()
            if c.lower().startswith("yaml"):
                c = c[4:].strip()
            if "detection" in c and "condition" in c:
                return c
    return text.strip()


def _dedup_events(events: list[dict]) -> list[dict]:
    """Dedup accumulated gap events by content — the same benign event false-positives
    every round, so the running lists carry duplicates we don't want to show twice."""
    seen, out = set(), []
    for e in events or []:
        key = json.dumps(e, sort_keys=True, default=str)
        if key not in seen:
            seen.add(key)
            out.append(e)
    return out


def _evidence_block(state: FoundryState) -> str:
    """
    The consolidation hand-off: give Blue the FULL running set of gaps from EVERY round,
    not just the last one, and require it to close them all at once.

    This is the fix for the oscillation. Handed only the previous round's gap, Blue trades
    one for another forever (suppress this round's false positive → reopen last round's
    evasion). Handed the accumulated set — every attack it must catch AND every benign
    event it must stay silent on — its re-author has to satisfy all constraints
    simultaneously, which is exactly the "find the one rule that closes every gap" pass.
    """
    prev_cov = state.get("coverage")
    evasions = _dedup_events(state.get("seen_evasions", []))
    fps = _dedup_events(state.get("seen_fps", []))
    rnd = state.get("round", 0) + 1
    maxr = state.get("max_rounds", 3)
    final = rnd >= maxr

    header = (
        f"\n\nThe previous rule was judged **{prev_cov.verdict.value if prev_cov else 'insufficient'}**. "
        + ("This is your FINAL consolidation pass. " if final else "")
        + "Below is the COMPLETE set of gaps found across ALL rounds so far. Author ONE rule "
        "that closes EVERY gap at once — fires on all of the attack events AND stays silent on "
        "all of the benign events. Do NOT fix one and reopen another: a fix that reintroduces a "
        "gap already listed here is not acceptable."
    )
    lines = [header]

    if evasions:
        lines.append(f"\nMUST CATCH — {len(evasions)} attack event(s) that have evaded a prior rule "
                     "(fire on every one of these):")
        for e in evasions:
            lines.append(f"- [{e.get('mutation_class','evasion')}] {e.get('description','')}"
                         f"\n    event: {json.dumps(e.get('event', {}), default=str)}")
    if fps:
        lines.append(f"\nMUST NOT FIRE — {len(fps)} benign event(s) a prior rule wrongly matched "
                     "(stay silent on every one of these — add precise exclusions or tighten intent, "
                     "do not just drop the whole selection):")
        for f in fps:
            lines.append(f"- benign: {json.dumps(f, default=str)}")
    if not evasions and not fps:
        lines.append("- (no specific gaps captured — tighten fidelity generally)")

    lines.append(
        "\nStrategy: anchor on the BEHAVIOUR — rename-resistant telemetry (OriginalFileName / "
        "IMPHASH / signed publisher) AND the command-line intent that makes the action malicious — "
        "so the attack variants are caught while the benign look-alikes are excluded by that same "
        "intent. Two independent signals ANDed together usually separates them."
    )
    return "\n".join(lines)


def blue_author(state: FoundryState, provider: LLMProvider) -> dict:
    threat: ThreatContext = state["threat"]
    behaviors = state.get("behaviors", [])
    rnd = state.get("round", 0) + 1
    behavior_lines = "\n".join(f"- {b.id}: {b.description} [{b.log_source.category}]" for b in behaviors)

    # RAG: retrieve peer-reviewed detection prior art to author from. On a repair
    # round, fold the proven evasions into the query so retrieval surfaces
    # rename-resistant rules (the real SigmaHQ certutil rule anchors OriginalFileName).
    query_parts = [threat.title, *threat.attack_techniques, *(b.description for b in behaviors)]
    if rnd > 1:
        prev_adv = state.get("adversarial")
        query_parts += [m.description for m in (prev_adv.mutations if prev_adv else []) if m.evaded]
        query_parts.append("rename resistant OriginalFileName high fidelity anchor")
    citations = knowledge_base.get_kb().retrieve(" ".join(query_parts), "blue", k=3)

    # Blue authors against the SAME log source and schema the Telemetry agent already
    # fixed the corpus on. Handing over the field NAMES is not grading its own
    # homework — a real detection engineer knows their SIEM's schema. It sees no event
    # values and no labels, so it cannot overfit to the corpus; it just can't key on a
    # field that does not exist, which is an automatic recall-0 `broken` round.
    corpus: TestCorpus = state["corpus"]
    category = pinned_log_source(behaviors)
    fields = corpus_fields(corpus)

    # Spell out the evaluable subset. The engine refuses to fake support for anything
    # else (engine.py raises), which costs a whole repair round — and on a live threat
    # the model reaches for plausible-looking non-Sigma modifiers (`|in`) unless told
    # exactly what exists. Cheaper to constrain here than to repair there.
    base = (
        "Write ONE Sigma rule (fenced ```yaml block) detecting the behavior below. "
        "Include a logsource block, a title, a level (informational|low|medium|high|critical), "
        "and a detection block with named selections and a condition.\n"
        f"LOG SOURCE — the rule MUST target `category: {category}`.\n"
        f"AVAILABLE FIELDS — the fixed test telemetry carries exactly these field names: "
        f"{fields}. Your rule may reference ONLY these fields. A selection keyed on any other "
        "field can never fire against this telemetry, and the rule will be scored broken.\n"
        "SUPPORTED MODIFIERS — use ONLY these: |contains, |startswith, |endswith, |re, |all, |cased. "
        "A plain YAML list of values already means OR (there is no |in modifier in Sigma). "
        "Do NOT use aggregations (count/near), |cidr, |base64*, |gt/|gte/|lt/|lte, |fieldref, "
        "|expand or |windash — a deterministic engine must evaluate this rule, and it will "
        "reject anything else.\n\n"
        f"Threat: {threat.title}\nTechniques: {threat.attack_techniques}\n"
        f"Behaviors:\n{behavior_lines}"
    )
    base += _format_prior_art(citations, "PRIOR-ART DETECTIONS")
    if rnd == 1:
        tag = "author"
        user = base
    else:
        tag = f"author_r{rnd}"
        user = base + _evidence_block(state)

    yaml_text = _extract_yaml(provider.complete(system=_BLUE_SYS, user=user, tag=tag))
    parsed = yaml.safe_load(yaml_text)
    if not isinstance(parsed, dict) or "detection" not in parsed:
        raise ValueError("authored rule has no detection block")

    ls = parsed.get("logsource", {}) or {}
    title = parsed.get("title", threat.title)
    rule = SigmaRuleArtifact(
        title=title,
        rule_id=parsed.get("id") or _stable_id(title),
        yaml_text=yaml_text,
        detection=parsed["detection"],
        logsource=LogSource(category=ls.get("category"), product=ls.get("product"), service=ls.get("service")),
        level=str(parsed.get("level", "medium")),
    )
    where = "author" if rnd == 1 else "RE-author (evidence-driven)"
    cite_note = ""
    if citations:
        cite_note = "  [grounded in " + ", ".join(c.source for c in citations[:2]) + "]"
    return {
        "round": rnd,
        "rule": rule,
        "blue_sources": citations,
        "log": [f"[blue/{where} r{rnd}] Sigma '{rule.title}' (level={rule.level}){cite_note}"],
    }


# --------------------------------------------------------------------------- #
# 4. Red-Team Adversary — proposes; the engine (graph.node_redteam_merge) proves.
# --------------------------------------------------------------------------- #
def red_team_propose(state: FoundryState, provider: LLMProvider) -> dict:
    rule: SigmaRuleArtifact = state["rule"]
    threat: ThreatContext = state.get("threat")
    rnd = state.get("round", 1)

    # FIXED adversary test set: after round 1, Red does not invent fresh attacks — it
    # re-throws the SAME two it committed to, now against Blue's hardened rule. This is
    # the "corpus built once" discipline applied to the adversary: Blue must close a
    # fixed pair of real gaps, so the fight is winnable and convergence to real-coverage
    # is honest. Re-rolling the adversary every round (the old behavior) gave Red
    # unlimited fresh tries against Blue's 3 — an unfair fight nothing survives. No model
    # call here on repair rounds, so it's also free and instant.
    frozen = state.get("red_team_frozen")
    if frozen:
        return {
            "red_team_raw": list(frozen),
            "red_sources": state.get("red_sources", []),
            "red_refused": False,
            "log": [f"[red/adversary r{rnd}] re-testing the same {len(frozen)} committed "
                    f"attack(s) against the hardened rule"],
        }

    # RAG: retrieve real offensive tradecraft to ground the evasions (e.g. ATT&CK
    # T1036.003 Rename System Utilities) — Red cites documented techniques, not guesses.
    techs = threat.attack_techniques if threat else []
    query = " ".join([rule.title, *techs, str(rule.detection),
                      "evasion bypass rename obfuscation alternate lolbin OriginalFileName Image"])
    citations = knowledge_base.get_kb().retrieve(query, "red", k=3)

    user = (
        f"Generate EXACTLY {_RED_ATTACKS} test-fixture log events that probe this Sigma rule "
        "for coverage gaps — your two strongest, most realistic attacks, not a long list. "
        "Return a JSON array of two items; each: {id, mutation_class, severity, description, event}. "
        "`event` = a process_creation log record (same field names as the rule) describing a "
        "documented variant of the same behavior — one this rule OUGHT to catch, but might "
        "miss if it keys on a brittle field. Base each variant on the catalogued techniques "
        "below.\n\n"
        f"Rule under test: {rule.title}\nRule detection logic: {rule.detection}"
    )
    user += _format_prior_art(citations, "CATALOGUED TECHNIQUE VARIANTS (public references)")

    tag = f"red_team_r{rnd}"
    refused = False
    try:
        arr = extract_json(provider.complete(system=_RED_SYS, user=user, tag=tag))
    except KeyError:
        # Offline safety: no canned proposals for this round → propose nothing.
        arr = []
    except ValueError:
        # The model declined the adversary role (safety filter) or emitted
        # unparseable output. Propose nothing — but flag it, because "no evasions
        # found" and "the adversary never attacked" must never look alike. A
        # refusal that silently produced a clean verdict would certify a rule
        # nobody tested; node_verdict refuses to call this real-coverage.
        arr = []
        refused = True
    if isinstance(arr, dict):
        arr = [arr]
    # Hard cap: the adversary throws a fixed, bounded number of real attacks. A model
    # that over-produces despite the prompt cannot turn the fight into an unwinnable
    # evasion firehose — we keep only its strongest N. (Fewer than N is fine; that just
    # means it found fewer real gaps.)
    arr = list(arr)[:_RED_ATTACKS]
    cite_note = ""
    if citations:
        cite_note = "  [grounded in " + ", ".join(f"{c.source} {'/'.join(c.techniques)}" for c in citations[:1]) + "]"
    note = " — ADVERSARY DECLINED (verdict cannot be real-coverage)" if refused else cite_note
    out = {
        "red_team_raw": list(arr),
        "red_sources": citations,
        "red_refused": refused,
        "log": [f"[red/adversary r{rnd}] committed {len(arr)} real attack(s) for engine verification{note}"],
    }
    # Freeze this round's attacks as the fixed test set for the rest of the run — but
    # only if the adversary actually produced some. A refusal (empty arr) freezes
    # nothing, so a later round can retry rather than locking in "no attacks".
    if arr:
        out["red_team_frozen"] = list(arr)
    return out
