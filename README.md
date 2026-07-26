# Detection-as-Code Foundry
### An adversarial multi-agent detection-engineering workflow — LangGraph · Pydantic · FastMCP · Claude

Turn a threat (a CVE, a CISA KEV entry, an incident writeup, an ATT&CK technique)
into a **validated first-version detection** — a proven starting point a detection
team hardens further, not a claim of finished, forever-bulletproof coverage — plus
**three artifacts that ship together**:

1. a **Sigma detection rule** that has survived a Blue-vs-Red adversarial loop,
2. a **threat report** with the round-by-round **convergence history**, and
3. a **proof bundle** — a positive corpus the rule fires on, a benign baseline it
   stays silent on, an adversarial mutation set, and a **computed coverage label**
   (`real-coverage` / `brittle` / `broken`) with FP/FN numbers and a reproducibility hash.

The thing nobody else produces is #3. A model can write you a Sigma rule; it cannot
hand you a *proof* that the rule works, an adversary that *provably* evades the weak
version, and an honest record of how the rule was hardened until it held.

> **A bounded, fixed adversary.** Red commits to **two real, documented attacks** in
> round one and re-throws *those same two* against the hardened rule each round — the
> same "built once, can't move its goalposts" discipline as the fixed test corpus.
> `real-coverage` therefore means something concrete and honest: the first-version rule
> fires on every attack in the corpus, stays silent on benign look-alikes, and caught
> **both** of Red's real attacks. It is a validated baseline, not a promise of coverage
> against every future evasion — that is the detection team's job to extend.

> **Agents propose; the engine proves.** Four role-specialized LLM agents (Threat
> Analyst, Blue Detection Engineer, Telemetry, Red-Team Adversary) do the creative
> work. Everything that decides truth — FP/FN evaluation, adversarial evasion,
> the coverage verdict, red-team verification, and the deployment gate — is a
> deterministic referee. Same input → same verdict → same reproducibility hash.

## Run it
```bash
pip install -r requirements.txt          # or just run --evals on stdlib alone

# LIVE — any threat text; a real model authors it (needs GEMINI_API_KEY or ANTHROPIC_API_KEY)
python src/run.py "CVE-2026-45659 SharePoint deserialization RCE"
python src/run.py "T1218.011 rundll32 remote scriptlet execution via mshtml"

# CANNED — a fixture scenario, fully offline, no key (what the test suite drives)
python src/run.py --threat fixtures/certutil_t1105.json   # brittle→repair→proven

python src/run.py --corpus atomic         # positives from REAL Atomic Red Team commands
python src/run.py --max-rounds 3          # self-repair loop cap (default 3)
python src/run.py --evals                 # deterministic engine + proof + workflow tests
python src/run.py --approve alice         # human approves → gated deploy succeeds
python src/run.py --claude "..."          # force claude-opus-4-8 authoring (ANTHROPIC_API_KEY)
python src/run.py --gemini "..."          # force Gemini authoring (GEMINI_API_KEY)
```
There is **no default scenario** — the Foundry takes the threat you give it. A bare
`python src/run.py` has nothing to work on and says so.
Bundles are written to `Outputs/<rule-slug>/` (`rule.yml`, `report.md`, `proof.json`).

## The Review Chain — a second, different pipeline (`--chain`, and the default UI)

The pipeline above asks *"is this rule provably correct?"* and answers with a
deterministic verdict. The **Review Chain** asks a different question — *"what would
each stakeholder say about this rule, and what does it look like after their feedback
is applied?"* — and answers with a **final rule plus the complete trail that shaped it**.

```
ingest ─▶ extract ─▶ telemetry ─▶ profile
    ─▶ Blue: DRAFT v1
    ─▶ RED TEAM review        (findings: where is this evadable / blind)
    ─▶ Blue: REVISION v2      (each edit cites the finding id it answers)
    ─▶ SOC LEAD review        (findings: volume, triage, severity, tuning)
    ─▶ Blue: FINAL v3
    ─▶ package
```

```bash
python src/run.py --chain "CVE-2026-48939 Joomla iCagenda arbitrary file upload RCE"
python -m uvicorn webui.server:app --port 8000   # → http://127.0.0.1:8000  (chain UI)
                                                 # → /classic for the proof loop above
```

Red and SOC are not the same reviewer in two hats — they pull in **opposite**
directions. Hardening against evasion broadens a rule; broadening raises alert volume.
Running both, in that order, is the point: the final rule is the one that survived both
pressures, and the trail shows exactly what each pass cost.

Output lands in `Outputs/<rule-slug>/` as `final-rule.yml`, `review-history.md`
(the full progression, rendered) and `review.json`.

> **Reviewed, not validated — and the artifact says so.** This chain does not invoke
> the proof core. It never executes the rule against telemetry, counts no false
> positives, and issues no coverage verdict. A rule that has been through four
> professional reviewers *looks* finished, which is precisely why the packaged output
> leads with that sentence. Run the classic pipeline (or `--evals`) when you need proof
> rather than review.

## The demo UI (`webui/`) — live authoring, watch the agents work
```bash
python -m uvicorn webui.server:app --port 8000
# → http://127.0.0.1:8000 ; type ANY threat, watch the loop run
python tools/warm_cache.py "the exact threat you'll demo"   # optional — see below
```
FastAPI + SSE over the **real** graph. Two streams are interleaved and neither is
scripted: **node events** fire when a graph node genuinely completes, and **token
events** stream each agent's raw model output *as it is generated*, via the token sink
on `providers.py`. The graph runs on a worker thread precisely because tokens arrive
mid-node; the queue between them is the only coupling, and it is one-way.

You watch: the LangGraph shape animate (the node in flight glows, the edge into it
flows, the **loop-back arc fires red on a repair round**), the agent console type out
what the model is producing right now, the Sigma rule write itself line by line, and
the convergence timeline, Kartikeya gate and reproducibility hash land at the end.

**It authors LIVE — there are no presets and no fixture/replay path in the UI**, so any
threat works. Determinism comes from `providers.py`'s on-disk cache: temperature 0,
keyed by `sha256(model|system|user)`, so re-running the *same threat text* replays
byte-identical model output → same rule → same bundle hash. Cold-run latency depends
entirely on the model (a 3-round convergence on `gemini-flash-lite` lands in ~20-40s;
a bigger model is minutes). `warm_cache.py` pre-pays it for a threat you plan to demo.

> **Replay is labeled, always.** A cached token stream is marked `cached` end-to-end and
> the console badge reads **⟳ REPLAY (cached)** instead of **● GENERATING**. A viewer
> cannot tell replay from generation by looking, so the UI says which it is. Dressing
> cached bytes up as live motion would be exactly the "vibes" this project refuses.
> The sink is observation only: detach it and the verdict and hash are byte-identical.

> **Red-team refusals are handled honestly.** Safety-tuned models sometimes decline the
> adversary role. A refusal is recorded, surfaced in the UI, and — critically —
> `graph.node_verdict` refuses to award `real-coverage` to a round nobody attacked.
> "No evasions found" and "the adversary never ran" must never look alike.

## Architecture — Blue vs. Red, a deterministic referee, and a self-repair loop
```
  ingest ─▶ extract ─▶ telemetry            (Analyst normalizes; Telemetry fixes the test set)
                          │
                          ▼
   ┌──────────────── SELF-REPAIR LOOP (LangGraph conditional edges) ─────────────────┐
   │                                                                                  │
   │   blue_author ─▶ evaluate ─▶ battery ─▶ red_propose ─▶ red_verify ─▶ verdict     │
   │        ▲          (FP/FN)   (mutation   (Red-Team     (engine-      (coverage)    │
   │        │             │       battery)    proposes)     verifies)        │         │
   │        │             └── un-evaluable rule ─────────────────────────────┤         │
   │        │                  (engine refuses → broken, skip the round)     │         │
   │        └───────────────── repair: verdict ≠ real-coverage ◀────────────┘         │
   │                                                                        │         │
   └──────────────────────────── done: real-coverage OR round == cap ──────┘         │
                                                                            ▼
                                                                     gate ─▶ bundle

  [ blue/red/telemetry/analyst = LLM agents — PROPOSE ]
  [ evaluate·battery·red_verify·verdict·gate = deterministic referee — PROVE ]
```

- **Agents (`src/agents.py`)** — four distinct personas. The **Blue Detection
  Engineer** authors a robust-by-construction first version (behavior + command-line
  intent, not one brittle string) and re-authors on a brittle/broken verdict using the
  *concrete* evidence (the exact evasions + false positives). The **Red-Team Adversary**
  commits to **two real, documented attacks** in round one and re-throws *those same
  two* against the hardened rule every round — a fixed adversarial test set, not a fresh
  ambush each round, so Blue closes a bounded pair of gaps and honest convergence is
  reachable.
- **Research grounding (`src/knowledge_base.py` + `rule_corpus/`)** — a two-partition
  **RAG** knowledge base grounds both proposers in real, researcher-authored OSS:
  Blue authors from peer-reviewed **SigmaHQ** rules; Red attacks from **MITRE ATT&CK**
  defense-evasion (e.g. **T1036.003 Rename System Utilities**) and **LOLBAS**. The
  retriever is lexical (BM25), fully offline and deterministic. It grounds *proposals
  only* — it never touches the proof engine and never enters the reproducibility hash.
- **`src/engine.py`** — the deterministic Sigma matcher (the proof core). Zero deps.
  Honesty contract: it *raises* on constructs it can't truly evaluate (`|cidr`,
  aggregations, the `|in` that models like to invent) rather than silently passing —
  an un-evaluable rule is never scored as "covered". The loop treats that as a
  **broken** round and hands the engine's own message back to Blue as repair
  evidence, so a rule that doesn't run costs a round, not the run.
- **`src/evaluator.py`** — FP/FN evaluation + a deterministic **adversarial mutation
  battery** (binary-rename, casing, whitespace, caret/quote obfuscation, path
  relocation), and `merge_redteam()` which folds **engine-verified** red-team
  evasions into the same verdict. Brittleness is *measured*, not guessed.
- **`src/graph.py`** — the loop. `red_verify` replays every red-team event through
  the engine: **a bypass counts only if the engine confirms the rule failed to fire.**
  Unverified proposals are discarded — the adversary cannot assert a bypass.
- **`src/governance.py`** — **Kartikeya's Gate = Blast Radius × Capability Delta**.
  Structural invariants a persuasive model can't argue away: *egress always
  requires a human*, and *non-real coverage floors blast radius*.
- **`src/mcp_server.py`** — governed tool boundary. The graph can neither fetch nor
  deploy; `deploy_detection` refuses any approval token not bound to the exact
  bundle hash. **The harness holds the privilege, not the agent.**

## The canned scenario tells the truth (a two-round convergence)
`python src/run.py --threat fixtures/certutil_t1105.json` — offline, no key:
- **Round 1** — Blue anchors on the `Image` path. The deterministic battery lands the
  **binary-rename** bypass *and* the Red-Team lands a real-world variant (certutil
  copied to `AdobeUpdater.exe`), engine-verified → verdict **BRITTLE** → loop back.
- **Round 2** — Blue re-authors on rename-resistant `OriginalFileName`. The battery
  evades nothing, and the **same** red-team rename is now **engine-discarded** because
  the rule fires on it → verdict **REAL-COVERAGE** → Kartikeya's Gate → bundle.

The report shows the full arc (rule v1 brittle → evasion → rule v2 proven). That is the
Foundry being honest about a rule that *looks* fine and isn't — then fixing it and
proving the fix held.

This scenario is a **fixture**, not the demo: it exists so the workflow runs offline and
the test suite has a deterministic end-to-end case. The UI never touches it. A live
threat converges on its own merits or doesn't — and "doesn't" is a real result the
Foundry is built to report rather than hide.

## One log source per run
The Analyst's per-behavior log sources elect a single category for the run (majority
vote); the Telemetry agent builds the fixed corpus on it, and Blue is told both that
category and the exact **field names** the corpus carries. Blue sees no event values and
no labels, so it cannot overfit — it just cannot key on a field that isn't in the
telemetry, which is an automatic recall-0 `broken` round for a reason that has nothing
to do with detection quality. (A rule anchored on `TargetFilename` can never fire on
process-creation events.)

## Kartikeya alignment
This is the [Shiva/Kartikeya](../README.md) thesis applied to detection engineering:
deploying a detection is a **capability request** (egress to a SIEM), scored through
`Gate = Blast Radius × Capability Delta` before any human is bothered — and *no*
autonomous path can push a rule. Least privilege and human-gated egress are computed
and enforced in code, not asserted in a prompt.

_Runs fully offline/deterministic. The sibling senior-security-engineering-agent
narrates with Gemini; the Foundry authors with Claude — but in both, the model only
proposes and the proof is deterministic._

## OSS integration (the ecosystem this plugs into)
The Foundry's **proof core** (`engine.py → evaluator.py → governance.py`) is deterministic and
self-contained. Its **seams** — ingest, author, convert, test-corpus, deploy, report — are designed
to be fed by open-source detection sources:

- [`docs/OSS-PARTNERS.md`](docs/OSS-PARTNERS.md) — canonical partner catalog: each repo mapped to the
  tool's actual pipeline stage, with priority, integration point, and **license posture**.
- [`docs/OSS-INTEGRATION-MINDMAP.md`](docs/OSS-INTEGRATION-MINDMAP.md) — the full researched map.

**First wire-in (highest value):** Atomic Red Team → positive corpus + EVTX-ATTACK-SAMPLES → benign
baseline, so the adversarial battery runs against *real* attack telemetry. Then pySigma + SigmAIQ for
multi-SIEM authoring/conversion (the `SigmaRuleArtifact.backends` slot already exists for this).
