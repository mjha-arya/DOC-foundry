# DOC Foundry — OSS Partners Catalog

> **Canonical reference.** Every open-source repo the Detection-as-Code Foundry integrates with,
> mapped to the tool's **actual** pipeline stage, with role, integration point, priority, and
> license posture. Future Claude Code sessions should use this when wiring an integration or
> selecting a dependency.
>
> **Honesty note (the Foundry contract):** these partners complement the tool's **seams**
> (ingest, author, convert, deploy, report) — the parts that are currently fixtures or LLM-proposed.
> They do **not** replace the **proof core** (`engine.py` → `evaluator.py` → `governance.py`),
> which stays deterministic, offline, and is the tool's actual differentiator. A partner feeds the
> Foundry; the Foundry still computes the proof.
>
> Repo handles below are transcribed from research; **verify each handle at wire-time** before
> depending on it (some are secondary mirrors / community forks).

> **Wired in so far (real, running):**
> - **Atomic Red Team** → positive test corpus (`src/corpus_adapters.py`, `--corpus atomic`).
> - **SigmaHQ**, **MITRE ATT&CK** (incl. T1036.003), **LOLBAS** → **RAG grounding** for the Blue and
>   Red agents (`src/knowledge_base.py`, `rule_corpus/`). Lexical/BM25, offline, deterministic;
>   grounds *proposals only*, never the deterministic proof.
>
> Everything else below is a prioritized, license-checked backlog — catalogued, not yet connected.

---

## How the partner map lines up with our pipeline

The research map uses `INGEST → GENERATE → CONVERT → TEST → DEPLOY → REPORT`.
Our code (`src/graph.py`) runs `ingest → extract → author → corpus → evaluate → adversarial → verdict → gate → bundle`. Reconciliation:

| Research stage | Our stage(s) | Currently | Partners add |
|---|---|---|---|
| INGEST | `ingest` | fixture threat | real CVE/KEV/ATT&CK feeds |
| GENERATE | `author` | LLM seam / fixture | SigmAIQ + reference corpora |
| **CONVERT** | *(new)* — `SigmaRuleArtifact.backends` slot already exists | single Sigma only | pySigma multi-SIEM output |
| TEST | `corpus` → `evaluate` → `adversarial` | hand-written fixtures | Atomic Red Team + EVTX real telemetry |
| **DEPLOY** | `gate` (+ new CI/CD) | gate + offline deploy-record | GitHub Actions detection-as-code |
| **REPORT** | `bundle` (+ new viz) | markdown + proof.json | ATT&CK Navigator coverage layer |

Bold = a genuinely new capability; the rest strengthen a stage we already have.

---

## 1. INGEST — threat input feeds

| Partner | Repo | Role | Priority | License |
|---|---|---|---|---|
| CISA KEV data | `cisagov/kev-data` | Git-diff on each commit = newly exploited CVEs → **pipeline trigger**. Fields incl. `knownRansomwareCampaignUse`. | **P1** | US Gov / public domain |
| CVE enrichment | `cisagov/vulnrichment` | STIX 2.1 CVE records enriched with **SSVC / CWE / CVSS** → sets rule priority metadata. | **P1** | US Gov / public domain |
| ATT&CK data | `mitre-attack/attack-stix-data` | Technique → tactic, platform, **data_sources → Sigma `logsource`**. Powers `extract`. | **P1** | MITRE / Apache-2.0-like |
| KEV RSS mirror | `CryptoGenNepal/CVE-KEV-RSS` | KEV as JSON Feed + RSS — lightweight automation hook alternative. | P3 | verify |
| Deep enrichment | `Patrowl/PatrowlHearsData` | Aggregates CVE + CPE + CWE + exploit refs. | P3 | verify (BSD/AGPL family) |
| Threat-scored CVSS | `kston83/cvss-te` | KEV + EPSS + Metasploit + ExploitDB → one severity → auto-sets Sigma `level:`. | P3 | verify |

**Integration point:** each maps onto our existing `ThreatContext` model (`state.py`) — `SourceType` already enumerates `cve / kev / writeup / attack_technique`. Mapping chain: `CVE-ID → CWE → ATT&CK Technique → Sigma logsource`.

---

## 2. GENERATE — rule authoring

| Partner | Repo | Role | Priority | License |
|---|---|---|---|---|
| **SigmAIQ** | `AttackIQ/SigmAIQ` | **The authoring brain.** pySigma + LangChain toolkit: NL threat → valid Sigma YAML, wraps all backends. Replaces our `author` seam. | **P0** | verify (LGPL-ish) |
| Sigma corpus | `SigmaHQ/sigma` | 3,000+ peer-reviewed rules mapped to ATT&CK. **Search before generate**; adapt/enhance; cite as prior art. | **P0** | DRL (Detection Rule License) |
| yarGen-Go | `Neo23x0/yarGen-Go` | Sample → YARA rule (strings/opcodes, goodware-filtered). For the YARA track. | P2 | verify |
| YARA corpus | `Yara-Rules/rules` | CVE/malware/webshell reference YARA. | P2 | verify (mixed) |
| YARA gold-standard | `reversinglabs/reversinglabs-yara-rules` | Production metadata template (desc, severity, FP notes). | P2 | verify |
| YARA index | `InQuest/awesome-yara` | Meta-index of YARA tooling/rulesets. | P3 | reference only |

**⚠ License gate:** `SigmaHQ/sigma` ships under the **Detection Rule License (DRL)**, and community YARA sets are mixed. If the Foundry *redistributes* adapted rules in a commercial product, DRL attribution/terms apply. Treat corpora as **reference + prior-art citation** by default; get explicit clearance before bundling derived rules into a paid output. (This is a product decision, not a code one — flag to Manish.)

---

## 3. CONVERT — multi-SIEM translation *(new stage)*

Fills `SigmaRuleArtifact.backends` (the dict is already in `state.py`, currently empty).

| Partner | Repo | Output | Priority |
|---|---|---|---|
| **pySigma** | `SigmaHQ/pySigma` | Core: parse Sigma → pipeline → target query. Py 3.10+. | **P0** |
| sigma-cli | `SigmaHQ/sigma-cli` | CLI for convert/check/list. | **P0** |
| KQL backend | `AttackIQ/pySigma-backend-kusto` | Sentinel / Defender XDR | **P0** |
| Splunk backend | `SigmaHQ/pySigma-backend-splunk` | SPL + savedsearches.conf | P1 |
| Elastic backend | `SigmaHQ/pySigma-backend-elasticsearch` | Lucene / ES\|QL / EQL | P1 |
| QRadar / CrowdStrike / SentinelOne / Google SecOps / Cortex XDR | various `pySigma-*` | per-SIEM | P2 |

**Integration point:** after `author` produces canonical Sigma, a new `convert` node calls pySigma backends and populates `rule.backends = {"kusto": "...", "splunk": "..."}`. The **proof core still runs on the canonical detection dict** — conversions are outputs, not trusted inputs.

---

## 4. TEST — real malicious + benign telemetry

This is the **highest-value** ingestion: replace hand-written fixtures in `TestCorpus` with real, technique-aligned telemetry.

| Partner | Repo | Role | Priority | License |
|---|---|---|---|---|
| Atomic Red Team | `redcanaryco/atomic-red-team` | Per-technique attack simulations → **positive corpus**. Look up Atomic(s) for the rule's T-ID, use their logs as `positives`. | **P1** | MIT |
| Atomic executor | `redcanaryco/invoke-atomicredteam` | PowerShell runner (or `atomic-operator` in Python) to actually generate telemetry in a lab. | P1 | MIT |
| EVTX samples | `sbousseaden/EVTX-ATTACK-SAMPLES` | Windows EVTX by technique — attack **and** normal activity → **benign baseline** (`negatives`) + more positives. | **P1** | verify |
| YARA-X | `VirusTotal/yara-x` | Rust YARA engine — compile + run generated YARA against corpus (the YARA analogue of our Sigma `engine.py`). | P1 | BSD-3 |
| YARA-CI | `VirusTotal/yara-ci` | GitHub App: continuous YARA rule linting/FP checks. | P2 | verify |
| Splunk Attack Range | `splunk/attack_range` | Full Windows+Splunk+Sysmon lab for E2E: deploy rule, run Atomic, confirm fire + measure FP. | P3 | Apache-2.0 |

**Integration point:** an `ingest_corpus` adapter converts Atomic/EVTX telemetry into the plain event dicts our `engine.py` already consumes. **No engine change needed** — this is the cleanest, most differentiating wire-in, because the adversarial battery then runs against *real* attack traces.

---

## 5. DEPLOY — detection-as-code CI/CD *(new)*

| Partner | Repo | Role | Priority |
|---|---|---|---|
| GitHub Actions | *(pattern)* | On rule change → `sigma check` → convert → run vs EVTX → **manual-approval gate** → prod. Mirrors our `governance.py` gate at the CI layer. | P2 |

**Alignment:** the CI "manual approval" environment is the *same structural invariant* as Kartikeya's Gate — egress requires a human. Keep the gate authoritative in-tool; CI enforces it a second time (defense in depth).

---

## 6. REPORT — coverage visualization *(new)*

| Partner | Repo | Role | Priority |
|---|---|---|---|
| ATT&CK Navigator | `mitre-attack/attack-navigator` | Auto-generate a Navigator layer JSON per rule set → embed heatmap in the threat report / bundle. | P2 |
| Volexity threat-intel | `volexity/threat-intel` | Reference **output-package format** (YARA+Suricata+Sigma alongside writeup) — template for our bundle layout. | P3 |

---

## 7. Priority ranking (what to wire first)

| Priority | Component | Why |
|---|---|---|
| **P0** | pySigma + sigma-cli + kusto backend | Core conversion — unlocks the CONVERT stage the schema already reserves |
| **P0** | SigmAIQ | Real authoring to replace the `author` seam |
| **P0** | SigmaHQ/sigma corpus | Prior-art search before generating |
| **P1** | kev-data + vulnrichment | Automated ingest triggers |
| **P1** | Atomic Red Team + EVTX | **Real** positive/benign corpus — biggest proof upgrade |
| **P1** | YARA-X | YARA compilation/validation runtime |
| **P2** | yarGen-Go, ATT&CK Navigator, GitHub Actions | YARA gen, coverage viz, CI/CD |
| **P3** | Attack Range, PatrowlHearsData, cvss-te, Volexity format | Lab E2E, deep enrichment, packaging |

---

## 8. Recommended first wire-in (matches the Foundry thesis)

Start with **Atomic Red Team → positive corpus** and **EVTX-ATTACK-SAMPLES → benign baseline**.
Reason: they feed the stages that make the proof *credible* (`corpus → evaluate → adversarial`)
without touching the deterministic core. The moment the adversarial battery runs against real
attack telemetry instead of fixtures, the "proof of coverage" claim stops being a demo and becomes
a product. **pySigma + SigmAIQ** follow, to turn one canonical rule into every SIEM dialect.

> Do **not** bulk-install the toolchain or clone the corpora until the wire-in is scoped — several
> are large repos and network downloads. Confirm scope, then pull only what the first adapter needs.

---

## 9. Install sequence (for when wiring begins — run deliberately, not all at once)

```bash
# CONVERT core
pip install pysigma sigma-cli
sigma plugin install kusto splunk elasticsearch

# GENERATE
pip install sigmaiq langchain

# YARA
cargo install yara-x        # or: pip install yara-x
go install github.com/Neo23x0/yarGen-Go/cmd/yargen@latest

# Feeds + corpora (shallow clones)
git clone --depth 1 https://github.com/cisagov/kev-data.git
git clone --depth 1 https://github.com/cisagov/vulnrichment.git
git clone --depth 1 https://github.com/mitre-attack/attack-stix-data.git
git clone --depth 1 https://github.com/redcanaryco/atomic-red-team.git
git clone --depth 1 https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES.git
git clone --depth 1 https://github.com/SigmaHQ/sigma.git
```

_Full researched mind map (source of this catalog) is preserved at
[`OSS-INTEGRATION-MINDMAP.md`](./OSS-INTEGRATION-MINDMAP.md)._
