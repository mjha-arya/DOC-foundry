"""
LLM provider layer — the AUTHORING seam, explicitly bounded and labeled.

The Foundry's thesis: the author is non-deterministic (a model proposes a rule),
but the PROOF is deterministic (engine.py + evaluator.py). This module isolates
the only non-deterministic component behind one interface, and gives it two
implementations:

  * ClaudeProvider  — Anthropic (claude-opus-4-8), temperature 0, with an
                      on-disk response cache keyed by sha256(model|system|user).
                      Cache hit ⇒ byte-identical replay ⇒ reproducible bundle.
  * FixtureProvider — canned per-tag responses from a scenario fixture, so the
                      entire pipeline runs offline with NO API key, for tests and
                      for an explicit `--threat <fixture>` CLI run. It is labeled
                      mode="fixture" everywhere so no one mistakes a replayed
                      demo for a live authoring run.

The sibling senior-security-engineering-agent narrates with Gemini; here we use
Claude per the Foundry's design decision. Either way, the model only ever
*proposes* — it is structurally downstream of the deterministic verdict.

## The token sink (`on_token`) — watching an agent think, honestly

A Foundry node is a single blocking `complete()` call that can run for minutes.
Callers that want to *show* that work (the web UI) can attach a `TokenSink` to
`provider.on_token`; the provider then reports the model's output as it arrives.

Three honesty rules govern the sink, because a viewer cannot tell replay from
generation by looking:

  1. Every emission carries `cached` — True means these bytes came off disk, not
     off the wire. A cached replay is paced (FOUNDRY_REPLAY_CPS) so a human can
     read it, and the UI must label it as replay. Fabricating live-looking motion
     over cached bytes would be exactly the "vibes" this project exists to refuse.
  2. A failed attempt emits `reset`, so a partial stream that a retry supersedes
     is discarded on screen rather than left looking like output.
  3. The sink is observation only. It never feeds state, the proof engine, or the
     reproducibility hash — detach it and the verdict is byte-identical. When no
     sink is attached (CLI, tests, cache warmer) the provider does not stream at
     all, so this seam cannot change what any non-UI caller computes.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
from pathlib import Path
from typing import Protocol

_MODEL = "claude-opus-4-8"
_CACHE_DIR = Path(__file__).resolve().parent.parent / ".cache"

# Cached bytes replay instantly; that flashes past the eye. Pace them at a
# readable rate (chars/sec) purely for display. 0 disables pacing.
_REPLAY_CPS = float(os.environ.get("FOUNDRY_REPLAY_CPS", "1100"))
_REPLAY_STEP = 16


class ModelRefusal(RuntimeError):
    """Claude's safety classifier declined the request (HTTP 200, stop_reason=refusal).

    Distinct from a rate limit or a parse error: retrying the same threat won't help.
    Opus 4.8's cybersecurity classifier refuses some threat *content* — self-propagating
    worms, supply-chain malware — even for a purely defensive detection-writing task, and
    even with defensive framing. Carried up so the UI can say so plainly instead of failing
    with an opaque JSON-parse error three nodes later.
    """


def _guard_stop(message, tag: str) -> None:
    """Raise if a Claude response is a refusal — before it can be cached or parsed."""
    if getattr(message, "stop_reason", None) == "refusal":
        detail = ""
        det = getattr(message, "stop_details", None)
        if det is not None:
            cat = getattr(det, "category", None)
            if cat:
                detail = f" (category: {cat})"
        raise ModelRefusal(
            f"Claude's safety classifier declined to author for this threat{detail} "
            f"[node={tag}]. This is content-specific to the threat, not a bug — some "
            f"malware classes (self-propagating worms, supply-chain compromise) are "
            f"refused even for defensive detection work. Try a different threat "
            f"(LOLBins, CVEs, endpoint techniques author fine), or run this one on Gemini."
        )


def _retry_delay(msg: str, default: int = 32) -> int:
    """Pull the server-suggested retry delay (seconds) out of a 429 error text."""
    m = re.search(r"retry in ([\d.]+)s", msg) or re.search(r"retryDelay['\":\s]+([\d.]+)s", msg)
    if m:
        return min(int(float(m.group(1))) + 2, 65)
    return default


class TokenSink(Protocol):
    """
    Observer for one `complete()` call, in lifecycle order:

        open  → token* → close        (a completed call)
        open  → token* → reset → …    (a failed attempt; a retry re-opens)

    `tag` identifies the node (`author`, `red_team_r2`, …) so a UI can route the
    stream to the right agent. `cached` is True when the bytes are a replay.
    """

    def __call__(self, *, tag: str, event: str, chunk: str = "", cached: bool = False) -> None:
        ...


class LLMProvider(Protocol):
    name: str
    mode: str
    on_token: TokenSink | None

    def complete(self, *, system: str, user: str, tag: str, max_tokens: int = 2048) -> str:
        ...


class _Observable:
    """Token-sink plumbing shared by every provider. Attach via `provider.on_token`."""

    on_token: TokenSink | None = None

    def _emit(self, tag: str, event: str, chunk: str = "", cached: bool = False) -> None:
        sink = self.on_token
        if sink is None:
            return
        try:
            sink(tag=tag, event=event, chunk=chunk, cached=cached)
        except Exception:
            # A broken observer (a closed browser tab) must never fail a run that
            # is otherwise fine — the sink is decoration, the proof is the product.
            self.on_token = None

    def _replay(self, text: str, tag: str, cached: bool = True) -> str:
        """Feed already-known bytes to the sink at a readable pace, labeled as replay."""
        if self.on_token is None:
            return text
        self._emit(tag, "open", cached=cached)
        for i in range(0, len(text), _REPLAY_STEP):
            self._emit(tag, "token", chunk=text[i : i + _REPLAY_STEP], cached=cached)
            if _REPLAY_CPS > 0:
                time.sleep(_REPLAY_STEP / _REPLAY_CPS)
        self._emit(tag, "close", cached=cached)
        return text


# --------------------------------------------------------------------------- #
class ClaudeProvider(_Observable):
    """
    Real Claude authoring, cached on disk for reproducible replay.

    Determinism note — this is NOT temperature 0. Opus 4.8 removed `temperature`,
    `top_p` and `top_k` entirely; sending any of them is a 400. So the byte-identical
    replay this project relies on comes from the on-disk cache alone (keyed by
    sha256(model|system|user)), not from a sampling parameter. Nothing downstream
    changes: the model was always only a *proposer*, and engine.py / evaluator.py /
    governance.py recompute the verdict from scratch on every run regardless of what
    the author did. A cache miss re-authors and may differ; the proof does not.
    """

    name = "claude:" + _MODEL
    mode = "claude"

    def __init__(self, cache_dir: Path = _CACHE_DIR):
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        try:
            import anthropic  # noqa: F401
        except ImportError as e:  # pragma: no cover
            raise RuntimeError("anthropic SDK not installed; `pip install anthropic`") from e

    def _cache_path(self, key: str) -> Path:
        return self.cache_dir / f"{key}.json"

    def complete(self, *, system: str, user: str, tag: str, max_tokens: int = 2048) -> str:
        key = hashlib.sha256(f"{_MODEL}\n{system}\n{user}".encode()).hexdigest()[:24]
        cached = self._cache_path(key)
        if cached.exists():
            return self._replay(json.loads(cached.read_text(encoding="utf-8"))["text"], tag)

        import anthropic

        client = anthropic.Anthropic()  # reads ANTHROPIC_API_KEY
        kwargs = dict(
            model=_MODEL,
            # Thinking tokens count against max_tokens, and a truncated rule is an
            # unparseable rule. Give the same headroom the Gemini path gives.
            max_tokens=max(8192, max_tokens),
            # NO temperature/top_p/top_k — removed on Opus 4.8; sending one is a 400.
            # Adaptive thinking is off unless asked for, and the work that actually
            # needs it is the repair round: re-authoring a rule to defeat the specific
            # evasions that beat the last one. That is the step the loop lives or dies
            # on, so pay for the reasoning.
            thinking={"type": "adaptive"},
            output_config={"effort": "high"},
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        if self.on_token is None:
            resp = client.messages.create(**kwargs)
            _guard_stop(resp, tag)
            text = "".join(block.text for block in resp.content if block.type == "text")
        else:
            self._emit(tag, "open")
            parts: list[str] = []
            try:
                with client.messages.stream(**kwargs) as stream:
                    for piece in stream.text_stream:
                        parts.append(piece)
                        self._emit(tag, "token", chunk=piece)
                    final = stream.get_final_message()
                _guard_stop(final, tag)
            except Exception:
                self._emit(tag, "reset")
                raise
            text = "".join(parts)
            self._emit(tag, "close")

        # Never cache an empty completion. A cached "" is poison: every later run of
        # this threat replays the empty string and fails deep inside extract_json with
        # no hint that a refusal (not a parse bug) is the cause. An empty body here
        # means the guard above didn't catch it — surface it instead of sealing it in.
        if not text.strip():
            raise RuntimeError(
                f"Claude returned an empty response for tag={tag!r} (not cached). "
                "Re-run, or switch the threat/provider."
            )
        cached.write_text(json.dumps({"tag": tag, "text": text}), encoding="utf-8")
        return text


# --------------------------------------------------------------------------- #
class GeminiProvider(_Observable):
    """Real Gemini authoring, temp 0 + on-disk cache (reproducible replay).
    Supports both the new `google-genai` and the classic `google-generativeai`
    SDKs. Model via env GEMINI_MODEL (default gemini-2.5-flash)."""

    mode = "gemini"

    def __init__(self, cache_dir: Path = _CACHE_DIR):
        # Two traps this default has to dodge:
        #  1. gemini-2.5-flash is still advertised by models.list() but 404s for newer
        #     keys ("no longer available to new users") — it fails at call time, not
        #     at startup. A pinned version can retire under you; an alias can't.
        #  2. Free-tier quota is per-model-per-day, and the preview models are stingy
        #     (gemini-3-flash-preview: 20 requests/day — under two Foundry runs).
        #     The -lite line carries a far larger daily allowance.
        self.model = os.environ.get("GEMINI_MODEL", "gemini-flash-lite-latest")
        self.name = "gemini:" + self.model
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
        if not key:
            raise RuntimeError("set GEMINI_API_KEY (or GOOGLE_API_KEY) to use --gemini")
        self._key = key
        self._new = self._old = None
        try:                                   # preferred: new google-genai SDK
            from google import genai
            self._new = genai.Client(api_key=key)
        except Exception:
            try:                               # fallback: classic google-generativeai
                import google.generativeai as genai  # noqa: F401
                genai.configure(api_key=key)
                self._old = genai
            except Exception as e:  # pragma: no cover
                raise RuntimeError(
                    "no Gemini SDK found; `pip install google-genai` (or google-generativeai)"
                ) from e

    def _cache_path(self, key: str) -> Path:
        return self.cache_dir / f"gemini-{key}.json"

    def complete(self, *, system: str, user: str, tag: str, max_tokens: int = 2048) -> str:
        ckey = hashlib.sha256(f"{self.model}\n{system}\n{user}".encode()).hexdigest()[:24]
        cached = self._cache_path(ckey)
        if cached.exists():
            return self._replay(json.loads(cached.read_text(encoding="utf-8"))["text"], tag)

        # Real detection content (JSON arrays with rationales, full Sigma rules) is
        # long — a small cap truncates it into unparseable fragments. Give plenty of
        # room, and disable "thinking" so the budget isn't spent before the answer.
        out_tokens = max(8192, max_tokens)
        streaming = self.on_token is not None

        def _drain(chunks) -> str:
            parts: list[str] = []
            for ch in chunks:
                try:
                    piece = ch.text
                except Exception:
                    piece = None      # a chunk carrying no text part (safety/usage only)
                if piece:
                    parts.append(piece)
                    self._emit(tag, "token", chunk=piece)
            return "".join(parts)

        def _new_call(cfg) -> str:
            if streaming:
                return _drain(self._new.models.generate_content_stream(
                    model=self.model, contents=user, config=cfg))
            return self._new.models.generate_content(
                model=self.model, contents=user, config=cfg).text

        def _once() -> str:
            if streaming:
                self._emit(tag, "open")
            try:
                if self._new is not None:
                    cfg = {"system_instruction": system, "temperature": 0,
                           "max_output_tokens": out_tokens,
                           "thinking_config": {"thinking_budget": 0}}
                    try:
                        text = _new_call(cfg)
                    except Exception as e:
                        if "thinking" not in str(e).lower():
                            raise
                        cfg.pop("thinking_config", None)   # model without thinking control
                        if streaming:                      # drop any partial from attempt 1
                            self._emit(tag, "reset")
                            self._emit(tag, "open")
                        text = _new_call(cfg)
                else:
                    gm = self._old.GenerativeModel(self.model, system_instruction=system)
                    gcfg = {"temperature": 0, "max_output_tokens": out_tokens}
                    if streaming:
                        text = _drain(gm.generate_content(user, generation_config=gcfg, stream=True))
                    else:
                        text = gm.generate_content(user, generation_config=gcfg).text
            except Exception:
                if streaming:
                    self._emit(tag, "reset")   # a retry supersedes whatever was shown
                raise
            if streaming:
                self._emit(tag, "close")
            return text

        # Backoff for free-tier rate limits (429) and transient overload (503).
        # Successful calls are cached, so a completed step never re-hits the API.
        text = None
        for attempt in range(8):
            try:
                text = _once()
                break
            except Exception as e:
                msg = str(e)
                if "429" in msg or "RESOURCE_EXHAUSTED" in msg:
                    # Distinguish the two 429s. A per-MINUTE limit clears in a minute,
                    # so waiting is right. A per-DAY quota will not clear for hours —
                    # sleeping 8×60s against it just burns the demo window and then
                    # fails anyway. Fail fast and say what to actually do.
                    if "PerDay" in msg:
                        raise RuntimeError(
                            f"Gemini daily free-tier quota exhausted for model "
                            f"{self.model!r} (tag={tag}). This resets tomorrow — it will "
                            f"not clear by retrying. Either set GEMINI_MODEL to another "
                            f"model (quota is per-model: try gemini-3.1-flash-lite), or "
                            f"use ANTHROPIC_API_KEY. Already-cached steps are kept, so a "
                            f"re-run resumes from where this stopped."
                        ) from e
                    delay = _retry_delay(msg, default=32)
                    print(f"  [gemini] rate-limited (tag={tag}); waiting {delay}s…", flush=True)
                    time.sleep(delay)
                elif "503" in msg or "UNAVAILABLE" in msg:
                    time.sleep(6)
                else:
                    raise
        if not text:
            raise RuntimeError(f"Gemini failed for tag={tag} after retries (model={self.model})")

        cached.write_text(json.dumps({"tag": tag, "text": text}), encoding="utf-8")
        return text


# --------------------------------------------------------------------------- #
class FixtureProvider(_Observable):
    """Offline, keyless authoring: canned responses keyed by node `tag`."""

    name = "fixture"
    mode = "fixture"

    def __init__(self, responses: dict[str, str]):
        self._responses = responses

    def complete(self, *, system: str, user: str, tag: str, max_tokens: int = 2048) -> str:
        if tag not in self._responses:
            raise KeyError(
                f"FixtureProvider has no canned response for tag={tag!r}. "
                f"Available: {sorted(self._responses)}"
            )
        # Canned bytes are replay by definition — always labeled cached=True.
        return self._replay(self._responses[tag], tag)


# --------------------------------------------------------------------------- #
def live_provider_name() -> str | None:
    """
    Which real-model provider this environment can actually reach, or None.

    For the live-only callers (the web UI, the cache warmer). Deliberately NOT wired
    into get_provider('auto'): `run.py` defaults to auto and must stay
    offline-by-default — auto silently reaching for a live model would spend API
    quota on every plain `python src/run.py`.
    """
    if os.environ.get("ANTHROPIC_API_KEY"):
        return "claude"
    if os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY"):
        return "gemini"
    return None


def get_provider(mode: str, fixture_responses: dict[str, str] | None = None) -> LLMProvider:
    """
    mode: 'auto' -> Claude if ANTHROPIC_API_KEY set, else fixture.
          'claude' -> force Claude (errors without a key).
          'fixture' -> force offline fixture.
    """
    if mode == "claude":
        return ClaudeProvider()
    if mode == "gemini":
        return GeminiProvider()
    if mode == "fixture":
        if fixture_responses is None:
            raise ValueError("fixture mode requires fixture_responses")
        return FixtureProvider(fixture_responses)
    # auto
    if os.environ.get("ANTHROPIC_API_KEY"):
        return ClaudeProvider()
    if fixture_responses is None:
        raise RuntimeError("no ANTHROPIC_API_KEY and no fixture_responses to fall back to")
    return FixtureProvider(fixture_responses)


def extract_json(text: str) -> dict | list:
    """
    Pull the first JSON object/array out of a model response. Tolerates ```json
    fences and leading prose. Raises on genuinely unparseable output — we never
    guess, because a mis-parsed rule would be scored as real coverage.
    """
    t = text.strip()
    if "```" in t:
        # take the content of the first fenced block
        parts = t.split("```")
        for chunk in parts[1:]:
            chunk = chunk.strip()
            if chunk.lower().startswith("json"):
                chunk = chunk[4:].strip()
            if chunk[:1] in "{[":
                t = chunk
                break
    start = min((i for i in (t.find("{"), t.find("[")) if i != -1), default=-1)
    if start == -1:
        raise ValueError(f"no JSON found in model response: {text[:200]!r}")
    span = _balanced_span(t, start)
    try:
        return json.loads(span)
    except json.JSONDecodeError:
        # tolerate the common LLM quirk: a trailing comma before } or ]. The
        # pattern (comma + whitespace + closer) is JSON-illegal, so stripping it
        # is safe and won't touch commas inside string values or // in URLs.
        return json.loads(re.sub(r",(\s*[}\]])", r"\1", span))


def _balanced_span(t: str, start: int) -> str:
    """Return the substring from the opening bracket at `start` to its matching
    close, respecting string literals/escapes. Tolerant of trailing prose after
    the JSON value (naive rfind picks up stray braces in that prose)."""
    open_ch = t[start]
    close_ch = "}" if open_ch == "{" else "]"
    depth = 0
    in_str = False
    esc = False
    for j in range(start, len(t)):
        ch = t[j]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch in "{[":
            depth += 1
        elif ch in "}]":
            depth -= 1
            if depth == 0:
                return t[start : j + 1]
    return t[start:]   # unbalanced (truncated) — let json.loads raise a clear error
