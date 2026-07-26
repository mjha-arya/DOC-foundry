"""
Detection Knowledge Base — an offline, deterministic lexical retriever (BM25)
over two partitions of real, researcher-authored OSS content:

  * blue/  — peer-reviewed DETECTION rules (SigmaHQ etc.). Grounds the Blue
             Detection Engineer so it authors by adapting proven prior art.
  * red/   — offensive EVASION tradecraft (MITRE ATT&CK defense-evasion, LOLBAS).
             Grounds the Red-Team Adversary so its proposed bypasses are drawn
             from documented attacker techniques, not invented.

Why lexical, not vectors: detection content is keyword-dense and structured
(ATT&CK IDs like T1036.003, field names like OriginalFileName, binary names like
certutil). Exact-token matching is both effective and — crucially — fully offline,
dependency-free, and deterministic, which keeps the tool's no-API-key /
reproducible-hash contract intact. A vector/embedding retriever is a documented
upgrade seam, not a requirement.

HONESTY CONTRACT: this module grounds the two PROPOSERS. It is never consulted by
the deterministic referee (engine.py / evaluator.py / governance.py) and never
enters the reproducibility hash. Retrieval makes proposals research-backed; trust
is still computed, not retrieved.
"""
from __future__ import annotations

import json
import math
import re
from pathlib import Path

from .state import Citation

_CORPUS_DIR = Path(__file__).resolve().parent.parent / "rule_corpus"
_K1 = 1.5
_B = 0.75

# Pure alphanumeric tokens, lowercased. "certutil.exe" -> [certutil, exe];
# "T1036.003" -> [t1036, 003]; "-urlcache" -> [urlcache]; "OriginalFileName"
# -> [originalfilename]. Splitting on the dot lets a "certutil" query match a
# "certutil.exe" document, which is what we want in this domain.
_TOKEN_RE = re.compile(r"[a-z0-9]+")


def _tokenize(text: str) -> list[str]:
    return _TOKEN_RE.findall(text.lower())


class _Doc:
    __slots__ = ("id", "partition", "title", "source", "techniques", "snippet", "tokens", "tf", "length")

    def __init__(self, raw: dict):
        self.id = raw["id"]
        self.partition = raw.get("partition", "blue")
        self.title = raw.get("title", raw["id"])
        self.source = raw.get("source", "unknown")
        self.techniques = raw.get("techniques", [])
        body = raw.get("text", "")
        self.snippet = (body[:160] + "…") if len(body) > 160 else body
        # index title + techniques + body together
        indexed = f"{self.title} {' '.join(self.techniques)} {body}"
        self.tokens = _tokenize(indexed)
        self.tf: dict[str, int] = {}
        for t in self.tokens:
            self.tf[t] = self.tf.get(t, 0) + 1
        self.length = len(self.tokens)


class KnowledgeBase:
    """Loads the corpus once and answers BM25 queries per partition."""

    def __init__(self, corpus_dir: Path = _CORPUS_DIR):
        self._docs: dict[str, list[_Doc]] = {"blue": [], "red": []}
        self._idf: dict[str, dict[str, float]] = {"blue": {}, "red": {}}
        self._avgdl: dict[str, float] = {"blue": 0.0, "red": 0.0}
        self._load(corpus_dir)

    def _load(self, corpus_dir: Path) -> None:
        for partition in ("blue", "red"):
            docs: list[_Doc] = []
            seen: set[str] = set()
            # 1) curated per-file demo docs (rule_corpus/<partition>/*.json)
            pdir = corpus_dir / partition
            if pdir.is_dir():
                for f in sorted(pdir.glob("*.json")):   # sorted → deterministic
                    try:
                        d = _Doc(json.loads(f.read_text(encoding="utf-8")))
                        if d.id not in seen:
                            seen.add(d.id)
                            docs.append(d)
                    except Exception:
                        continue
            # 2) bulk index (rule_corpus/<partition>.jsonl) from tools/build_rag_corpus.py
            jsonl = corpus_dir / f"{partition}.jsonl"
            if jsonl.is_file():
                with jsonl.open(encoding="utf-8") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            d = _Doc(json.loads(line))
                            if d.id not in seen:
                                seen.add(d.id)
                                docs.append(d)
                        except Exception:
                            continue
            self._docs[partition] = docs
            self._build_idf(partition)

    def _build_idf(self, partition: str) -> None:
        docs = self._docs[partition]
        n = len(docs)
        if not n:
            return
        df: dict[str, int] = {}
        for d in docs:
            for term in d.tf:
                df[term] = df.get(term, 0) + 1
        # BM25 idf with the standard +0.5 smoothing; floored at 0 so a term in
        # every doc contributes nothing rather than going negative.
        self._idf[partition] = {
            term: max(0.0, math.log(1 + (n - c + 0.5) / (c + 0.5)))
            for term, c in df.items()
        }
        self._avgdl[partition] = sum(d.length for d in docs) / n

    def _score(self, partition: str, query_terms: list[str], doc: _Doc) -> float:
        idf = self._idf[partition]
        avgdl = self._avgdl[partition] or 1.0
        score = 0.0
        for t in query_terms:
            f = doc.tf.get(t, 0)
            if not f:
                continue
            denom = f + _K1 * (1 - _B + _B * doc.length / avgdl)
            score += idf.get(t, 0.0) * (f * (_K1 + 1)) / denom
        return score

    def retrieve(self, query: str, partition: str, k: int = 3) -> list[Citation]:
        docs = self._docs.get(partition, [])
        if not docs:
            return []
        qterms = _tokenize(query)
        scored = [(self._score(partition, qterms, d), d) for d in docs]
        # deterministic ordering: score desc, then doc id asc for ties
        scored.sort(key=lambda sd: (-sd[0], sd[1].id))
        out: list[Citation] = []
        for s, d in scored[:k]:
            if s <= 0:
                continue
            out.append(Citation(
                doc_id=d.id, title=d.title, source=d.source,
                techniques=d.techniques, score=round(s, 4), snippet=d.snippet,
            ))
        return out


_KB: KnowledgeBase | None = None


def get_kb() -> KnowledgeBase:
    """Process-wide singleton; corpus is small and loads once."""
    global _KB
    if _KB is None:
        _KB = KnowledgeBase()
    return _KB
