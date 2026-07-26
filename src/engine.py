"""
Deterministic Sigma detection engine — the PROOF core of the Foundry.

This module is the deterministic, offline heart of the pipeline. It takes a
parsed Sigma ``detection`` block and a log event (a plain ``dict``) and returns
a hard boolean: does this rule fire on this event? There is no LLM here, no
network, no randomness. Same rule + same event -> same verdict, forever.

Everything else in the Foundry is a "seam" (an LLM authored it, a model
proposed it). THIS is where trust is *computed*, not asserted.

--- Honestly-labeled supported subset of the Sigma spec ---
Supported:
  * search-identifiers as a map (fields AND'd) or a list of maps (OR'd)
  * field modifiers: |contains |startswith |endswith |re |all |cased
  * value lists (OR by default; AND when |all is present)
  * wildcards ``*`` and ``?`` in string values
  * ``field: null`` (matches when field absent or explicitly null)
  * nested field access via dotted keys (e.g. ``Event.EventID``)
  * case-insensitive string matching by default (Sigma default); |cased opts out
  * condition grammar: and / or / not / parentheses,
    ``N of them`` / ``all of them`` / ``N of <glob>*`` / ``all of <glob>*``
  * keyword lists (a bare list of strings) -> substring match across all values

NOT yet supported (raises UnsupportedSigmaFeature so we never silently pass):
  * |cidr, |base64, |base64offset, |gt/|lt numeric comparison modifiers
  * field-reference (|fieldref), placeholders (%...%)
  * aggregation conditions (count() by ..., | near, timeframe)
These raise loudly — a rule the engine can't fully evaluate must never be
scored as "covered". That is the intellectual-honesty contract of this module.
"""
from __future__ import annotations

import re
from typing import Any, Iterable

__all__ = ["evaluate", "count_matches", "UnsupportedSigmaFeature", "SigmaConditionError"]

_KNOWN_MODIFIERS = {"contains", "startswith", "endswith", "re", "all", "cased"}
_UNSUPPORTED_MODIFIERS = {
    "cidr", "base64", "base64offset", "gt", "gte", "lt", "lte",
    "fieldref", "expand", "windash",
}


class UnsupportedSigmaFeature(Exception):
    """Raised when a rule uses a construct this engine will not fake support for."""


class SigmaConditionError(Exception):
    """Raised when the ``condition`` expression is malformed or references unknowns."""


# --------------------------------------------------------------------------- #
# Value comparison primitives
# --------------------------------------------------------------------------- #
def _wildcard_to_regex(pattern: str) -> str:
    """Translate a Sigma value with ``*``/``?`` wildcards into a regex body."""
    out = []
    i = 0
    n = len(pattern)
    while i < n:
        c = pattern[i]
        if c == "\\" and i + 1 < n and pattern[i + 1] in ("*", "?", "\\"):
            # escaped wildcard -> literal
            out.append(re.escape(pattern[i + 1]))
            i += 2
            continue
        if c == "*":
            out.append(".*")
        elif c == "?":
            out.append(".")
        else:
            out.append(re.escape(c))
        i += 1
    return "".join(out)


def _dig(event: dict, dotted_key: str) -> tuple[bool, Any]:
    """Look up a possibly-dotted key. Returns (present, value)."""
    if dotted_key in event:
        return True, event[dotted_key]
    cur: Any = event
    for part in dotted_key.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return False, None
    return True, cur


def _compare_one(event_value: Any, pattern: Any, modifier: str | None, cased: bool) -> bool:
    """Compare a single event value against a single pattern under one modifier."""
    # null handling
    if pattern is None:
        return event_value is None

    if event_value is None:
        return False

    flags = 0 if cased else re.IGNORECASE

    if modifier == "re":
        return re.search(str(pattern), str(event_value), flags) is not None

    ev = str(event_value)
    pat = str(pattern)

    if modifier == "contains":
        return re.search(_wildcard_to_regex(pat), ev, flags) is not None
    if modifier == "startswith":
        return re.match(_wildcard_to_regex(pat) + r".*$", ev, flags | re.DOTALL) is not None
    if modifier == "endswith":
        return re.search(_wildcard_to_regex(pat) + r"$", ev, flags | re.DOTALL) is not None

    # base equality (with wildcard support). If no wildcards and both look
    # numeric, compare type-tolerantly.
    if "*" not in pat and "?" not in pat:
        if ev == pat:
            return True
        if not cased and ev.lower() == pat.lower():
            return True
        return False
    return re.fullmatch(_wildcard_to_regex(pat), ev, flags | re.DOTALL) is not None


def _match_field(event: dict, raw_key: str, spec_value: Any) -> bool:
    """Evaluate one ``field|mods: value`` pair against an event."""
    parts = raw_key.split("|")
    field = parts[0]
    modifiers = parts[1:]

    # These messages are not just diagnostics: on a live run they are handed straight
    # back to the authoring agent as repair evidence, so they must say what to do.
    for m in modifiers:
        if m in _UNSUPPORTED_MODIFIERS:
            raise UnsupportedSigmaFeature(
                f"modifier |{m} on field '{field}' is not supported by the deterministic engine; "
                f"supported modifiers are {sorted(_KNOWN_MODIFIERS)}")
        if m not in _KNOWN_MODIFIERS:
            extra = ""
            if m == "in":
                extra = " (Sigma has no |in modifier — a plain YAML list of values already means OR)"
            raise UnsupportedSigmaFeature(
                f"unknown modifier |{m} on field '{field}'{extra}; "
                f"supported modifiers are {sorted(_KNOWN_MODIFIERS)}")

    cased = "cased" in modifiers
    use_all = "all" in modifiers
    value_mods = [m for m in modifiers if m in ("contains", "startswith", "endswith", "re")]
    if len(value_mods) > 1:
        raise UnsupportedSigmaFeature(f"combining value modifiers {value_mods} is not supported")
    value_mod = value_mods[0] if value_mods else None

    present, ev_value = _dig(event, field)

    # normalise patterns to a list
    patterns = spec_value if isinstance(spec_value, list) else [spec_value]

    def one(pat: Any) -> bool:
        if pat is None:
            # field: null  -> true when absent or explicitly None
            return (not present) or ev_value is None
        if not present:
            return False
        # event value may itself be a list (multi-valued field) -> OR across it
        if isinstance(ev_value, list):
            return any(_compare_one(v, pat, value_mod, cased) for v in ev_value)
        return _compare_one(ev_value, pat, value_mod, cased)

    if use_all:
        return all(one(p) for p in patterns)
    return any(one(p) for p in patterns)


def _match_keyword_list(event: dict, keywords: list) -> bool:
    """A bare list of scalars = keywords: substring-match across ALL event values."""
    haystack = " ".join(str(v) for v in _flatten_values(event)).lower()
    return any(str(k).lower() in haystack for k in keywords)


def _flatten_values(obj: Any) -> Iterable[Any]:
    if isinstance(obj, dict):
        for v in obj.values():
            yield from _flatten_values(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _flatten_values(v)
    else:
        yield obj


def _match_search_id(event: dict, spec: Any) -> bool:
    """Evaluate a single named search identifier (selection/filter/keywords)."""
    if isinstance(spec, dict):
        # map: all field pairs AND together
        return all(_match_field(event, k, v) for k, v in spec.items())
    if isinstance(spec, list):
        if all(isinstance(item, dict) for item in spec):
            # list of maps: OR the maps
            return any(_match_search_id(event, item) for item in spec)
        # keyword list
        return _match_keyword_list(event, spec)
    # scalar keyword
    return _match_keyword_list(event, [spec])


# --------------------------------------------------------------------------- #
# Condition expression parser (recursive descent)
# --------------------------------------------------------------------------- #
_TOKEN_RE = re.compile(r"\(|\)|\||[^\s()|]+")


def _tokenize(condition: str) -> list[str]:
    return _TOKEN_RE.findall(condition)


class _Parser:
    def __init__(self, tokens: list[str], search_ids: dict[str, bool]):
        self.toks = tokens
        self.pos = 0
        self.ids = search_ids

    def _peek(self) -> str | None:
        return self.toks[self.pos] if self.pos < len(self.toks) else None

    def _next(self) -> str | None:
        t = self._peek()
        if t is not None:
            self.pos += 1
        return t

    def parse(self) -> bool:
        val = self._expr()
        if self.pos != len(self.toks):
            raise SigmaConditionError(f"trailing tokens in condition near {self._peek()!r}")
        return val

    def _expr(self) -> bool:  # OR level (also swallows '|' aggregation guard)
        val = self._term()
        while (t := self._peek()) is not None and t.lower() == "or":
            self._next()
            rhs = self._term()
            val = val or rhs
        if self._peek() == "|":
            raise UnsupportedSigmaFeature("aggregation conditions (| count/near/...) are not supported")
        return val

    def _term(self) -> bool:  # AND level
        val = self._factor()
        while (t := self._peek()) is not None and t.lower() == "and":
            self._next()
            rhs = self._factor()
            val = val and rhs
        return val

    def _factor(self) -> bool:
        t = self._peek()
        if t is None:
            raise SigmaConditionError("unexpected end of condition")
        low = t.lower()
        if low == "not":
            self._next()
            return not self._factor()
        if t == "(":
            self._next()
            val = self._expr()
            if self._next() != ")":
                raise SigmaConditionError("missing closing parenthesis")
            return val
        # quantifier?  "<N|all> of <them|glob>"
        if (low == "all" or t.isdigit()) and self._peek_ahead(1) and self._peek_ahead(1).lower() == "of":
            return self._quantifier()
        # plain identifier
        self._next()
        return self._resolve_id(t)

    def _peek_ahead(self, k: int) -> str | None:
        idx = self.pos + k
        return self.toks[idx] if idx < len(self.toks) else None

    def _quantifier(self) -> bool:
        qty_tok = self._next()  # N or 'all'
        of_tok = self._next()   # 'of'
        if of_tok is None or of_tok.lower() != "of":
            raise SigmaConditionError("expected 'of' in quantifier")
        target = self._next()
        if target is None:
            raise SigmaConditionError("expected target after 'of'")
        if target.lower() == "them":
            candidates = list(self.ids.values())
        else:
            # glob like selection* or a bare name
            pat = re.compile("^" + _wildcard_to_regex(target) + "$", re.IGNORECASE)
            candidates = [v for k, v in self.ids.items() if pat.match(k)]
            if not candidates:
                raise SigmaConditionError(f"'of {target}' matched no search identifiers")
        hits = sum(1 for c in candidates if c)
        if qty_tok.lower() == "all":
            return hits == len(candidates)
        return hits >= int(qty_tok)

    def _resolve_id(self, name: str) -> bool:
        if name not in self.ids:
            raise SigmaConditionError(f"condition references unknown identifier {name!r}")
        return self.ids[name]


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #
def evaluate(detection: dict, event: dict) -> bool:
    """
    Evaluate a Sigma ``detection`` mapping against a single event dict.

    ``detection`` must contain named search identifiers plus a ``condition``
    string, exactly as it appears under ``detection:`` in a Sigma rule.
    """
    if not isinstance(detection, dict) or "condition" not in detection:
        raise SigmaConditionError("detection block missing a 'condition'")

    condition = detection["condition"]
    if isinstance(condition, list):
        raise UnsupportedSigmaFeature("list-of-conditions (rule collections) not supported; split the rule")

    # Pre-evaluate every named search identifier once.
    search_ids: dict[str, bool] = {}
    for name, spec in detection.items():
        if name == "condition":
            continue
        search_ids[name] = _match_search_id(event, spec)

    tokens = _tokenize(str(condition))
    if not tokens:
        raise SigmaConditionError("empty condition")
    return _Parser(tokens, search_ids).parse()


def count_matches(detection: dict, events: list[dict]) -> list[bool]:
    """Return a per-event list of booleans. Deterministic, order-preserving."""
    return [evaluate(detection, ev) for ev in events]
