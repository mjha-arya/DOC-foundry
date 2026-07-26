"""
Build the bulk RAG corpus from real OSS datasets → rule_corpus/{blue,red}.jsonl.

  RED  ← MITRE ATT&CK Enterprise STIX (attack-pattern objects): every technique &
         sub-technique becomes an evasion/tradecraft doc (200+ TTPs).
  BLUE ← SigmaHQ rules (read straight from the repo zip): every rule becomes a
         detection prior-art doc, tagged with its ATT&CK techniques.

This is an ingestion tool, not part of src/. Run offline against pre-downloaded
sources. The curated demo docs in rule_corpus/{blue,red}/*.json are KEPT — the
knowledge base loads both the per-file docs and these JSONL indexes.

Usage:
  python tools/build_rag_corpus.py <attack_stix.json> <sigma.zip>
"""
from __future__ import annotations

import json
import re
import sys
import zipfile
from pathlib import Path

import yaml

_OUT = Path(__file__).resolve().parent.parent / "rule_corpus"
_TECH_RE = re.compile(r"attack[._]t(\d{4}(?:\.\d{3})?)", re.IGNORECASE)


def _norm_tech(raw: str) -> str:
    return "T" + raw.upper()


def build_red(stix_path: Path) -> int:
    data = json.loads(stix_path.read_text(encoding="utf-8"))
    out = (_OUT / "red.jsonl").open("w", encoding="utf-8")
    n = 0
    for obj in data.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        tid = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                tid = ref["external_id"]
                break
        if not tid:
            continue
        name = obj.get("name", tid)
        tactics = [p.get("phase_name", "") for p in obj.get("kill_chain_phases", [])]
        desc = obj.get("description", "")
        detection = obj.get("x_mitre_detection", "")
        data_sources = obj.get("x_mitre_data_sources", [])
        platforms = obj.get("x_mitre_platforms", [])
        text = " ".join([
            name, tid, " ".join(tactics), " ".join(platforms),
            " ".join(data_sources), desc, detection,
        ])
        doc = {
            "id": f"attack-{tid}", "partition": "red",
            "title": f"{name} ({tid})", "source": "MITRE ATT&CK",
            "techniques": [tid], "tactic": ", ".join(tactics), "text": text,
        }
        out.write(json.dumps(doc, ensure_ascii=False) + "\n")
        n += 1
    out.close()
    return n


def build_blue(sigma_zip: Path) -> int:
    out = (_OUT / "blue.jsonl").open("w", encoding="utf-8")
    n = 0
    seen: set[str] = set()
    with zipfile.ZipFile(sigma_zip) as zf:
        for name in zf.namelist():
            if not name.endswith(".yml"):
                continue
            if "/rules" not in name:      # skip tests, deprecated tooling, etc.
                continue
            try:
                raw = zf.read(name).decode("utf-8", "replace")
                docs = [d for d in yaml.safe_load_all(raw) if isinstance(d, dict)]
            except Exception:
                continue
            title_global = next((d.get("title") for d in docs if d.get("title")), None)
            for d in docs:
                if "detection" not in d:
                    continue
                title = d.get("title") or title_global or Path(name).stem
                stem = Path(name).stem
                doc_id = "sigma-" + stem
                if doc_id in seen:
                    doc_id = f"{doc_id}-{n}"
                seen.add(doc_id)
                tags = d.get("tags", []) or []
                techs = sorted({_norm_tech(m.group(1))
                                for t in tags for m in [_TECH_RE.search(str(t))] if m})
                ls = d.get("logsource", {}) or {}
                text = " ".join([
                    title, " ".join(techs),
                    str(d.get("description", "")),
                    f"logsource {ls.get('category','')} {ls.get('product','')} {ls.get('service','')}",
                    str(d.get("detection", "")),
                    str(d.get("level", "")),
                ])
                doc = {
                    "id": doc_id, "partition": "blue", "title": title,
                    "source": "SigmaHQ", "techniques": techs, "text": text,
                }
                out.write(json.dumps(doc, ensure_ascii=False) + "\n")
                n += 1
    out.close()
    return n


if __name__ == "__main__":
    stix, sigma = Path(sys.argv[1]), Path(sys.argv[2])
    red = build_red(stix)
    blue = build_blue(sigma)
    techs = set()
    for line in (_OUT / "red.jsonl").read_text(encoding="utf-8").splitlines():
        techs.update(json.loads(line)["techniques"])
    for line in (_OUT / "blue.jsonl").read_text(encoding="utf-8").splitlines():
        techs.update(json.loads(line)["techniques"])
    print(f"red (ATT&CK techniques): {red}")
    print(f"blue (Sigma rules):      {blue}")
    print(f"distinct TTPs covered:   {len(techs)}")
