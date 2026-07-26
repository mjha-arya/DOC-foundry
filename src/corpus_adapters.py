"""
Corpus adapters — translate REAL open-source attack telemetry into the plain
event dicts the deterministic engine already consumes.

Why this exists
---------------
`agents.build_corpus` asks the *model* to invent the positive test events — the
same model that authored the rule. That is the "graded its own homework"
weakness: of course a rule passes tests written to fit it. This module replaces
those synthetic positives with **real attacker commands** from Red Canary's
Atomic Red Team, mapped 1:1 to the rule's ATT&CK technique.

Honesty contract (consistent with the rest of the Foundry)
----------------------------------------------------------
* REAL: the command lines are verbatim from Atomic Red Team, with each test's
  documented default `input_arguments` substituted in — nothing invented.
* SYNTHESIZED (a labelled seam): the process-creation *envelope* (the Image
  path, OriginalFileName, ParentImage). Atomic defines *commands*, not Sysmon
  events, so we model a process_creation event around each payload binary using
  a small, explicit LOLBin map. The fully-real telemetry seam is EVTX /
  Attack Range (see docs/OSS-PARTNERS.md) — this adapter is the honest halfway
  house: real commands, modelled envelope.

Offline by default, live as a seam
-----------------------------------
* Default source: the vendored copy at ``fixtures/atomic/<TID>.yaml`` (real
  Atomic content, checked in so runs are deterministic).
* Live seam: set env ``ATOMIC_RED_TEAM_DIR`` to a cloned
  ``redcanaryco/atomic-red-team`` checkout; we then read the real
  ``atomics/<TID>/<TID>.yaml`` straight from disk. Same parser, live data.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

import yaml

__all__ = ["atomic_events_for_technique", "atomic_positives_for_rule"]

_FIXTURE_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "atomic"

# Payload LOLBins we model a process_creation event for. Deliberately EXCLUDES
# the shell interpreters (cmd/powershell) — those are the PARENT of the payload,
# not the malicious indicator, and emitting them would create phantom positives
# the rule was never meant to catch (a false FN). Extend as new techniques land.
_LOLBINS: dict[str, tuple[str, str]] = {
    "certutil":  (r"C:\Windows\System32\certutil.exe", "CertUtil.exe"),
    "bitsadmin": (r"C:\Windows\System32\bitsadmin.exe", "bitsadmin.exe"),
    "curl":      (r"C:\Windows\System32\curl.exe", "curl.exe"),
    "certreq":   (r"C:\Windows\System32\certreq.exe", "CertReq.exe"),
    "mshta":     (r"C:\Windows\System32\mshta.exe", "MSHTA.EXE"),
    "regsvr32":  (r"C:\Windows\System32\regsvr32.exe", "REGSVR32.EXE"),
    "rundll32":  (r"C:\Windows\System32\rundll32.exe", "RUNDLL32.EXE"),
    "wget":      (r"C:\Windows\System32\wget.exe", "wget.exe"),
}

_SHELLS: dict[str, str | None] = {
    "command_prompt": r"C:\Windows\System32\cmd.exe",
    "powershell":     r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    "sh":             "/bin/sh",
    "bash":           "/bin/bash",
}


def _resolve_args(command: str, input_arguments: dict) -> str:
    """Substitute #{name} placeholders with each argument's documented default."""
    def repl(m: re.Match) -> str:
        name = m.group(1)
        arg = (input_arguments or {}).get(name, {})
        return str(arg.get("default", m.group(0)))
    return re.sub(r"#\{([^}]+)\}", repl, command)


def _events_from_command(command: str, executor: str) -> list[dict]:
    """Model one process_creation event per payload LOLBin invoked in `command`."""
    parent = _SHELLS.get(executor)
    events: list[dict] = []
    seen: set[tuple] = set()
    for line in command.splitlines():
        for name, (image, orig_name) in _LOLBINS.items():
            # Match the binary only at a real command position: not part of a
            # path/word, not inside a string literal or variable assignment
            # (excludes " ' = $ . before it), and actually *invoked* — i.e.
            # followed by whitespace/end, so `"certutil-$(...)"` is NOT a match
            # but `certutil -urlcache ...` is.
            m = re.search(
                r"(?<![\\/\w\"'=$.])" + re.escape(name) + r"(?:\.exe)?(?=\s|$)",
                line, re.IGNORECASE,
            )
            if not m:
                continue
            cmdline = line[m.start():].strip()
            ev: dict = {"Image": image, "OriginalFileName": orig_name, "CommandLine": cmdline}
            if parent:
                ev["ParentImage"] = parent
            key = (ev["Image"], ev["CommandLine"])
            if key not in seen:
                seen.add(key)
                events.append(ev)
    return events


def _load_technique_yaml(technique_id: str) -> tuple[dict | None, str]:
    """Load the Atomic YAML for a technique. Returns (data, provenance-note)."""
    tid = technique_id.strip().upper()
    live_root = os.environ.get("ATOMIC_RED_TEAM_DIR")
    if live_root:
        live_path = Path(live_root) / "atomics" / tid / f"{tid}.yaml"
        if live_path.is_file():
            return yaml.safe_load(live_path.read_text(encoding="utf-8")), f"live:{live_path}"
    vendored = _FIXTURE_DIR / f"{tid}.yaml"
    if vendored.is_file():
        return yaml.safe_load(vendored.read_text(encoding="utf-8")), f"vendored:{vendored.name}"
    return None, "none"


def atomic_events_for_technique(technique_id: str, platform: str = "windows") -> tuple[list[dict], str]:
    """
    Return (positive_events, provenance) for one ATT&CK technique, sourced from
    Atomic Red Team. Events are unfiltered: if the rule later misses one, that is
    a real coverage gap the evaluator must report — we never pre-filter to only
    the events that happen to fire.
    """
    data, source = _load_technique_yaml(technique_id)
    if not data:
        return [], f"{technique_id}: no atomic coverage ({source})"

    events: list[dict] = []
    tests = data.get("atomic_tests", []) or []
    used = 0
    for test in tests:
        if platform not in (test.get("supported_platforms") or []):
            continue
        executor = test.get("executor", {}) or {}
        raw_cmd = executor.get("command")
        if not raw_cmd:
            continue
        resolved = _resolve_args(raw_cmd, test.get("input_arguments", {}))
        new = _events_from_command(resolved, executor.get("name", ""))
        if new:
            used += 1
            events.extend(new)

    prov = (
        f"Atomic Red Team {technique_id}: {len(events)} event(s) from {used} {platform} "
        f"test(s) [{source}]"
    )
    return events, prov


def atomic_positives_for_rule(rule, threat) -> tuple[list[dict], str]:
    """
    Convenience: gather Atomic positives across every ATT&CK technique the threat
    is mapped to. Returns ([], note) when none of the techniques have coverage,
    so the caller can fall back to the model-authored corpus.
    """
    all_events: list[dict] = []
    notes: list[str] = []
    for tid in getattr(threat, "attack_techniques", []) or []:
        events, prov = atomic_events_for_technique(tid)
        notes.append(prov)
        all_events.extend(events)
    return all_events, " ; ".join(notes) if notes else "no ATT&CK techniques on threat"
