# DOC Foundry — OSS Integration Mind Map

> **Purpose:** This document maps every researched open-source tool/repo to its exact role inside the Detection-as-Code (DOC) Foundry pipeline. Claude Code should use this as the canonical reference when wiring integrations, writing glue code, or selecting dependencies.
>
> _Source: research pass from a prior session. Distilled, license-annotated, and reconciled to the tool's actual pipeline stages in [`OSS-PARTNERS.md`](./OSS-PARTNERS.md). Verify repo handles at wire-time._

---

## Pipeline Overview

```
INGEST → GENERATE → CONVERT → TEST → DEPLOY → REPORT
```

---

## 1. INGEST — Threat Input Layer

The foundry accepts 5 input types. Each has a dedicated OSS data source.

### 1.1 CVE Feed
- **Repo:** `cisagov/vulnrichment` — https://github.com/cisagov/vulnrichment
- **Format:** STIX 2.1 CVE records enriched with SSVC, CWE, CVSS by CISA ADP
- **Integration point:** Parse the ADP container for severity triage (SSVC decision points: Exploitation=active/poc/none, Automatable=yes/no, Technical Impact=total/partial). Use SSVC output to set rule priority metadata
- **Update cadence:** Continuous — watch for new commits via GitHub webhook or poll
- **Key field mapping:** `CVE-ID → CWE → ATT&CK Technique → Sigma logsource`

### 1.2 CISA KEV (Known Exploited Vulnerabilities)
- **Repo:** `cisagov/kev-data` — https://github.com/cisagov/kev-data
- **Format:** JSON + CSV mirror of the official KEV catalog
- **Integration point:** Git diff on each commit = newly added KEVs. Trigger foundry pipeline on new KEV addition. Fields: `cveID`, `vendorProject`, `product`, `vulnerabilityName`, `dateAdded`, `dueDate`, `knownRansomwareCampaignUse`
- **Enrichment:** Cross-reference with vulnrichment for SSVC + CVSS
- **Secondary feed:** `CryptoGenNepal/CVE-KEV-RSS` — https://github.com/CryptoGenNepal/CVE-KEV-RSS — KEV as JSON Feed + RSS for automation hooks

### 1.3 MITRE ATT&CK Techniques
- **Repo:** `mitre-attack/attack-stix-data` — https://github.com/mitre-attack/attack-stix-data
- **Format:** STIX 2.1 bundles per ATT&CK domain (Enterprise, Mobile, ICS)
- **Integration point:** Given a technique ID (e.g., T1059.001), extract: tactic, platform, data sources, detection notes, procedure examples. Map `data_sources` → Sigma `logsource` categories
- **Key mapping chain:** `Technique ID → data_component → logsource.category + logsource.product`

### 1.4 Vendor Writeups / Threat Reports
- **Input type:** Unstructured text (blog posts, PDFs, advisories)
- **Processing:** LLM extraction (via SigmAIQ/LangChain) to pull: IOCs, TTPs, affected platforms, log sources, behavioral indicators
- **Reference corpus for structure:** `volexity/threat-intel` — https://github.com/volexity/threat-intel — shows how to package YARA + Suricata + Sigma rules alongside threat writeups. Use as the template for DOC Foundry's output format

### 1.5 Enrichment Layer
- **Repo:** `Patrowl/PatrowlHearsData` — https://github.com/Patrowl/PatrowlHearsData
- **Role:** Aggregates CVE + CPE + CWE + exploit references from multiple upstream sources
- **Integration point:** Enrich any CVE input with exploit availability, affected products (CPE), and weakness class (CWE) before rule generation
- **Repo:** `kston83/cvss-te` — https://github.com/kston83/cvss-te
- **Role:** Threat-enhanced CVSS scoring — combines CISA KEV + EPSS + Metasploit + ExploitDB signals into actionable severity. Use this score to auto-set rule `level:` (critical/high/medium/low) in Sigma output

---

## 2. GENERATE — Rule Creation Engine

### 2.1 Sigma Rule Generation (Primary)

#### 2.1.1 AI-Powered Generation
- **Repo:** `AttackIQ/SigmAIQ` — https://github.com/AttackIQ/SigmAIQ
- **What it is:** pySigma wrapper + LangChain toolkit for LLM-driven rule creation
- **THIS IS THE CORE ENGINE FOR DOC FOUNDRY**
- **Capabilities:**
  - Takes natural language threat description → generates valid Sigma YAML
  - Wraps all pySigma backends — auto-applies correct pipelines
  - Supports all output formats: SPL, KQL, Lucene, QRadar AQL
- **Usage pattern:**
  ```python
  from sigmaiq import SigmAIQBackend
  from sigma.rule import SigmaRule
  # LLM generates the Sigma YAML from threat description
  # SigmAIQ converts it to target SIEM
  backend = SigmAIQBackend(backend="kusto").create_backend()
  output = backend.translate(sigma_rule)
  ```
- **DOC Foundry integration:** Feed the INGEST layer output (CVE + ATT&CK technique + enrichment) as structured prompt → SigmAIQ generates Sigma → SigmAIQ converts to all target formats

#### 2.1.2 Reference Rule Corpus
- **Repo:** `SigmaHQ/sigma` — https://github.com/SigmaHQ/sigma
- **Stars:** 8,500+
- **What it is:** 3,000+ peer-reviewed Sigma rules mapped to ATT&CK
- **DOC Foundry use:** Before generating a new rule, search this corpus for existing rules matching the technique. If found: adapt/enhance. If not found: generate from scratch via SigmAIQ. Always cite SigmaHQ rules as prior art in the threat report

### 2.2 YARA Rule Generation

#### 2.2.1 Automated Generation from Samples
- **Repo:** `Neo23x0/yarGen-Go` — https://github.com/Neo23x0/yarGen-Go
- **What it is:** Go rewrite of yarGen — submit malware sample → get YARA rules back
- **Key features:**
  - Extracts strings + opcodes from malicious samples
  - Filters against goodware database (loaded in memory, O(1) lookups) to eliminate FPs
  - Has built-in LLM integration for rule enrichment
  - Web UI at `http://127.0.0.1:8080` + REST API for automation
  - Claude Code skill available: `~/.openclaw/skills/yargen`
- **Usage:**
  ```bash
  yargen-util submit -a "DOC Foundry" malware_sample.exe
  yargen -m ./malware-samples -o rules.yar --opcodes --score
  ```
- **DOC Foundry integration:** When ingest layer provides a malware sample or hash → fetch sample → run yarGen-Go → output YARA rule + metadata

#### 2.2.2 YARA Engine (Execution + Validation)
- **Repo:** `VirusTotal/yara-x` — https://github.com/VirusTotal/yara-x
- **What it is:** YARA rewritten in Rust — faster, safer, production-proven at VirusTotal scale (billions of files)
- **Why YARA-X not YARA:** Original YARA is in maintenance mode. All new features/modules go to YARA-X
- **DOC Foundry use:** Compile + validate generated YARA rules. Run against test corpus. YARA-X is the runtime engine

#### 2.2.3 Reference YARA Corpus
- **Repo:** `Yara-Rules/rules` — https://github.com/Yara-Rules/rules
- **Coverage:** CVE-specific rules, malware families, exploit kits, packers, webshells, email malware
- **DOC Foundry use:** Search corpus before generating. Adapt existing rules where possible. Use as training reference for LLM-generated rules

- **Repo:** `reversinglabs/reversinglabs-yara-rules` — https://github.com/reversinglabs/reversinglabs-yara-rules
- **Quality:** Production-grade, tested against 10B+ binaries. Covers exploits, infostealers, ransomware, trojans
- **DOC Foundry use:** Gold-standard metadata template — copy their rule structure (descriptions, severity, FP notes, references) for DOC Foundry output

- **Repo:** `InQuest/awesome-yara` — https://github.com/InQuest/awesome-yara
- **What it is:** Mega-index of all YARA tools, rule collections, generators, and scanners
- **DOC Foundry use:** Reference index when searching for specialized rule sets (APT-specific, CVE-specific, platform-specific)

### 2.3 Suricata Rule Generation
- **Reference:** `volexity/threat-intel` packages Suricata rules alongside YARA + Sigma per threat
- **DOC Foundry pattern:** LLM generates Suricata rule from network IOCs (IPs, domains, JA3 hashes, HTTP patterns) extracted during INGEST. Use Volexity's output format as template

---

## 3. CONVERT — Multi-SIEM Translation Layer

### 3.1 Core Conversion Engine
- **Repo:** `SigmaHQ/pySigma` — https://github.com/SigmaHQ/pySigma
- **What it is:** Python library — parse Sigma YAML → apply processing pipeline → output target query language
- **Architecture:** Backend (target language) + Pipeline (field mapping + log source mapping) + Validators
- **Minimum Python:** 3.10+
- **Install:** `pip install pysigma`

### 3.2 Target Backends (install per SIEM)

| Backend | Repo | Output | Install |
|---------|------|--------|---------|
| **KQL (Sentinel/XDR)** | `AttackIQ/pySigma-backend-kusto` | Sentinel Analytics + XDR Advanced Hunting | `sigma plugin install kusto` |
| **Splunk SPL** | `SigmaHQ/pySigma-backend-splunk` | SPL queries + savedsearches.conf | `sigma plugin install splunk` |
| **Elasticsearch** | `SigmaHQ/pySigma-backend-elasticsearch` | Lucene + ES\|QL + EQL + Kibana NDJSON | `sigma plugin install elasticsearch` |
| **QRadar AQL** | `SigmaHQ/pySigma-backend-qradar` | IBM QRadar queries | `sigma plugin install qradar` |
| **CrowdStrike** | `SigmaHQ/pySigma-pipeline-crowdstrike` | CrowdStrike Falcon queries | `sigma plugin install crowdstrike` |
| **Carbon Black** | pySigma-backend-carbonblack | CB queries | `sigma plugin install carbonblack` |
| **SentinelOne** | pySigma-backend-sentinelone | Deep Visibility queries | `sigma plugin install sentinelone` |
| **Google SecOps** | pySigma-backend-secops | UDM + YARA-L 2.0 | `sigma plugin install secops` |
| **Cortex XDR** | pySigma-backend-cortexxdr | XQL queries | `sigma plugin install cortexxdr` |

### 3.3 Processing Pipelines (field mapping)

| Pipeline | Purpose |
|----------|---------|
| `sysmon` | Sysmon field schema → target fields |
| `splunk_windows` | Windows log source conditions for Splunk |
| `splunk_cim` | Splunk CIM Data Model mapping |
| `microsoft_xdr` | Map to DeviceProcessEvents / DeviceNetworkEvents etc. |
| `sentinelasim` | Azure Sentinel ASIM schema |
| `crowdstrike` | CrowdStrike field naming |

### 3.4 CLI Interface
- **Repo:** `SigmaHQ/sigma-cli` — command line for all conversions
- **Usage:**
  ```bash
  sigma convert -t kusto -p microsoft_xdr rule.yml      # → KQL
  sigma convert -t splunk -p splunk_windows rule.yml     # → SPL
  sigma convert -t elasticsearch rule.yml                # → Lucene
  sigma check rule.yml                                   # → Validate
  sigma list backends                                    # → Show installed
  sigma list pipelines                                   # → Show pipelines
  ```

---

## 4. TEST — Validation & Proof Layer

### 4.1 Attack Simulation (Malicious Test Corpus)
- **Repo:** `redcanaryco/atomic-red-team` — https://github.com/redcanaryco/atomic-red-team
- **Stars:** 10,000+
- **What it is:** Library of small, portable attack simulations mapped 1:1 to ATT&CK techniques
- **DOC Foundry integration:** For each generated Sigma rule mapped to technique T[xxxx]:
  1. Look up matching Atomic test(s) for that technique
  2. Execute the atomic test in sandbox
  3. Collect generated logs
  4. Run converted Sigma rule (KQL/SPL) against those logs
  5. Assert: rule fires = TRUE POSITIVE confirmed
- **Execution framework:** `redcanaryco/invoke-atomicredteam` (PowerShell) or `atomic-operator` (Python)
- **Supported platforms:** Windows, macOS, Linux, Office 365, Azure AD, GCP, AWS, containers

### 4.2 Benign Baseline (False Positive Testing)
- **Repo:** `sbousseaden/EVTX-ATTACK-SAMPLES` — https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES
- **Stars:** 2,000+
- **What it is:** Windows EVTX log files organized by ATT&CK technique — contains BOTH attack traces AND normal system activity
- **DOC Foundry integration:**
  1. Import benign EVTX baseline into test SIEM workspace
  2. Run converted Sigma rule against benign data
  3. Assert: rule stays SILENT = FALSE POSITIVE rate confirmed
  4. If rule fires on benign data → flag for tuning before deployment
- **Alternative:** Collect clean EVTX from a vanilla Windows VM as your own benign corpus

### 4.3 YARA Rule Validation
- **Tool:** `VirusTotal/yara-ci` — GitHub App for continuous YARA rule testing
- **DOC Foundry integration:** On every YARA rule commit → YARA-CI validates syntax, checks for common mistakes, tests against known FP patterns
- **Manual validation:** Run YARA-X against:
  - Malicious samples → must match (true positive)
  - Goodware database (yarGen-Go's built-in DB) → must NOT match (false positive check)

### 4.4 Full Lab Environment
- **Repo:** `splunk/attack_range` — https://github.com/splunk/attack_range
- **Stars:** 2,000+
- **What it is:** Spins up full Windows + Splunk + Sysmon lab environment
- **DOC Foundry use:** End-to-end integration test — deploy converted rule to Splunk, execute Atomic Red Team test, confirm alert fires, measure FP rate on baseline logs
- **Alternative for Sentinel:** Use `az monitor log-analytics query` CLI against a test Log Analytics workspace

---

## 5. DEPLOY — CI/CD Detection Pipeline

### 5.1 Pipeline Architecture (GitHub Actions)
```yaml
# .github/workflows/doc-foundry-pipeline.yml
on:
  push:
    paths: ['rules/**']
  pull_request:
    paths: ['rules/**']

jobs:
  validate:
    # sigma check on changed rules
    # sigma convert to all target backends
    # Run against EVTX test samples

  staging:
    # Deploy to staging SIEM workspace
    # Wait for 24hr FP monitoring window

  production:
    # Requires manual approval (GitHub Environments)
    # Deploy to production SIEM
    # Auto-rollback PR if FP rate spikes
```

### 5.2 Directory Structure
```
doc-foundry/
├── rules/
│   ├── initial-access/
│   ├── execution/
│   ├── persistence/
│   ├── privilege-escalation/
│   ├── defense-evasion/
│   ├── credential-access/
│   ├── discovery/
│   ├── lateral-movement/
│   ├── collection/
│   ├── command-and-control/
│   ├── exfiltration/
│   └── impact/
├── yara/
│   ├── malware/
│   ├── exploits/
│   └── webshells/
├── suricata/
│   ├── network-iocs/
│   └── protocol-anomalies/
├── tests/
│   ├── malicious-samples/    ← Atomic Red Team logs
│   ├── benign-baseline/      ← Clean EVTX corpus
│   └── test-results/         ← Proof artifacts
├── reports/
│   ├── threat-reports/       ← Generated markdown reports
│   └── coverage-maps/        ← ATT&CK Navigator layers
├── pipelines/
│   └── convert.py            ← pySigma multi-backend conversion
└── .github/
    └── workflows/
        └── doc-foundry-pipeline.yml
```

---

## 6. REPORT — Threat Report Generation

### 6.1 ATT&CK Coverage Visualization
- **Repo:** `mitre-attack/attack-navigator` — https://github.com/mitre-attack/attack-navigator
- **Stars:** 5,000+
- **DOC Foundry integration:** For each generated rule set, auto-generate an ATT&CK Navigator layer JSON showing which techniques are now covered. Embed in the threat report as a visual heatmap

### 6.2 Report Template Structure
Every DOC Foundry output package contains:
```
output-package/
├── threat-report.md          ← Narrative: what the threat is, why it matters
├── sigma/
│   ├── rule.yml              ← Canonical Sigma rule
│   ├── rule.kql              ← Converted KQL
│   ├── rule.spl              ← Converted SPL
│   └── rule.lucene           ← Converted Elasticsearch
├── yara/
│   └── rule.yar              ← YARA detection rule
├── suricata/
│   └── rule.rules            ← Suricata IDS rule (if network IOCs exist)
├── tests/
│   ├── true-positive.log     ← Proof: rule fires on malicious sample
│   ├── false-positive.log    ← Proof: rule silent on benign baseline
│   └── atomic-test-id.md     ← Which Atomic Red Team test was used
├── coverage/
│   └── navigator-layer.json  ← ATT&CK Navigator heatmap
└── metadata.json             ← CVE, KEV status, SSVC score, ATT&CK IDs, timestamps
```

---

## 7. Dependency Map — What Depends on What

```
SigmAIQ ──────────► pySigma ──────────► sigma-cli
   │                   │                    │
   │                   ├── backend-kusto    ├── GitHub Actions
   │                   ├── backend-splunk   └── CI/CD pipeline
   │                   ├── backend-elastic
   │                   └── pipeline-sysmon
   │
   ├── LangChain (LLM layer)
   │
   └── SigmaHQ/sigma (reference corpus)

yarGen-Go ─────────► YARA-X (runtime engine)
   │                    │
   └── goodware DB      └── YARA-CI (GitHub validation)

Atomic Red Team ───► invoke-atomicredteam (PowerShell executor)
   │                    │
   └── ATT&CK STIX      └── EVTX-ATTACK-SAMPLES (test data)
       data

cisagov/kev-data ──► cisagov/vulnrichment ──► PatrowlHearsData
                                               │
                                               └── cvss-te (enriched scoring)
```

---

## 8. Install Sequence for Claude Code

```bash
# 1. Core conversion engine
pip install pysigma sigma-cli --break-system-packages

# 2. SIEM backends
sigma plugin install kusto
sigma plugin install splunk
sigma plugin install elasticsearch

# 3. AI-powered rule generation
pip install sigmaiq langchain --break-system-packages

# 4. YARA engine
# Install YARA-X (Rust)
cargo install yara-x
# Or via pip for Python bindings
pip install yara-x --break-system-packages

# 5. YARA rule generator
go install github.com/Neo23x0/yarGen-Go/cmd/yargen@latest
go install github.com/Neo23x0/yarGen-Go/cmd/yargen-util@latest

# 6. Threat data feeds
git clone --depth 1 https://github.com/cisagov/kev-data.git
git clone --depth 1 https://github.com/cisagov/vulnrichment.git
git clone --depth 1 https://github.com/mitre-attack/attack-stix-data.git

# 7. Test corpus
git clone --depth 1 https://github.com/redcanaryco/atomic-red-team.git
git clone --depth 1 https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES.git

# 8. Reference rule sets
git clone --depth 1 https://github.com/SigmaHQ/sigma.git
git clone --depth 1 https://github.com/Yara-Rules/rules.git
```

---

## 9. Priority Ranking — What to Wire First

| Priority | Component | Why |
|----------|-----------|-----|
| **P0** | pySigma + sigma-cli + kusto backend | Core conversion — nothing works without this |
| **P0** | SigmAIQ | AI-powered rule generation — the foundry's brain |
| **P0** | SigmaHQ/sigma corpus | Existing rules to reference/adapt before generating new |
| **P1** | cisagov/kev-data + vulnrichment | Automated threat ingestion triggers |
| **P1** | Atomic Red Team + EVTX samples | Validation proof — "rule fires" + "rule stays silent" |
| **P1** | YARA-X | YARA rule compilation and validation |
| **P2** | yarGen-Go | Automated YARA generation from samples |
| **P2** | ATT&CK Navigator | Coverage visualization for reports |
| **P2** | GitHub Actions pipeline | CI/CD for detection-as-code deployment |
| **P3** | splunk/attack_range | Full lab environment for E2E testing |
| **P3** | PatrowlHearsData + cvss-te | Deep enrichment layer |
| **P3** | Volexity threat-intel format | Report packaging template |
