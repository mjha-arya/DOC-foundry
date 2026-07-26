"""
Warm the provider response cache for a threat you're about to demo.

The Foundry authors live from whatever threat text you hand it: every rule comes
from a real model call, so a threat the cache has never seen pays real latency
(~3-4 min/round, ~10 min for a full 3-round convergence). That is fine for a batch
job and terrible in front of an audience.

providers.py caches every completion on disk, keyed by sha256(model|system|user) at
temperature 0. So running a threat once here makes every later run of that SAME
threat text a pure cache hit: byte-identical model output, same rule, same bundle
hash — still live authoring, just already answered. Nothing is faked; the proof
engine, mutation battery, red-team verification and gate all recompute from scratch
on every run regardless.

    python tools/warm_cache.py "CVE-2026-45659 SharePoint deserialization RCE"
    python tools/warm_cache.py "threat one" "threat two"    # warm several
    python tools/warm_cache.py --list                       # what's cached now
    python tools/warm_cache.py --clear                      # drop the cache

Warm the EXACT text you will type into the UI. The cache key is derived from the
prompt, and the prompt is built from that text — "CVE-2026-45659 SharePoint RCE"
and "CVE-2026-45659 Sharepoint rce" are two different cold runs. This script builds
its graph inputs identically to webui/server.py for that reason; keep them in step.

Run it once, on the machine and network you'll demo from, before you go on stage.
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")  # Windows consoles default to cp1252
    except Exception:
        pass

from src.graph import build_app                                  # noqa: E402
from src.providers import get_provider, live_provider_name       # noqa: E402
from src.state import DeployIntent                               # noqa: E402

_CACHE = _ROOT / ".cache"


def _warm(threat: str, max_rounds: int) -> bool:
    live = live_provider_name()
    if live is None:
        print("  ✗ no model key — set GEMINI_API_KEY or ANTHROPIC_API_KEY")
        return False
    provider = get_provider(live)
    print(f"\n  {threat[:66]}  ({provider.name})")
    print(f"  {'-' * 66}")

    # Must mirror webui/server.py's init exactly, or the prompts differ and the UI
    # run will miss every entry this just paid for.
    init = {
        "raw_threat": threat, "source_type": "writeup", "source_ref": threat[:60],
        "deploy_intent": DeployIntent(), "mode": provider.mode, "corpus_source": "model",
        "round": 0, "max_rounds": max_rounds, "rounds": [], "log": [],
    }
    t0 = time.time()
    try:
        final = build_app(provider).invoke(
            init, config={"recursion_limit": 4 + max_rounds * 8})
    except Exception as e:
        print(f"  ✗ FAILED after {time.time()-t0:.0f}s — {type(e).__name__}: {str(e)[:120]}")
        print("    (rerun: completed steps are already cached, so it resumes cheaply)")
        return False

    dt = time.time() - t0
    for r in final.get("rounds", []):
        print(f"    round {r.round}: {r.verdict:<14} FP={r.fp} FN={r.fn} "
              f"battery-evaded={r.battery_evaded} red-verified={r.redteam_verified} → {r.outcome}")
    print(f"  ✓ warmed in {dt:.0f}s — final: {final['coverage'].verdict.value}")
    print(f"    hash {final['bundle'].content_hash[:30]}…")
    return True


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Warm the Foundry's model-response cache")
    ap.add_argument("threats", nargs="*", help="the exact threat text you will demo")
    ap.add_argument("--list", action="store_true", help="show cache contents and exit")
    ap.add_argument("--clear", action="store_true", help="delete the cache and exit")
    ap.add_argument("--max-rounds", type=int, default=3)
    args = ap.parse_args(argv)

    if args.clear:
        n = 0
        for f in _CACHE.glob("*.json"):
            f.unlink()
            n += 1
        print(f"cleared {n} cached call(s) from {_CACHE}")
        return 0

    if args.list:
        files = sorted(_CACHE.glob("*.json")) if _CACHE.exists() else []
        print(f"{len(files)} cached call(s) in {_CACHE}")
        return 0

    if not args.threats:
        print("  ✗ give the threat text to warm, e.g.\n"
              '      python tools/warm_cache.py "CVE-2026-45659 SharePoint deserialization RCE"')
        return 2

    print("\n  Warming the response cache — the first pass pays full model latency.")
    ok = all([_warm(t, args.max_rounds) for t in args.threats])

    n = len(list(_CACHE.glob("*.json"))) if _CACHE.exists() else 0
    print(f"\n  {n} cached call(s). Re-runs of these exact threats are now instant.")
    print("  Any other threat still authors cold — that's the point of live mode.\n")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
