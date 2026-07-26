"""
RAG knowledge-base tests — the offline lexical retriever that grounds Blue and Red.
Deterministic, no network, no API key.
Run: python src/run.py --evals
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.knowledge_base import get_kb                                      # noqa: E402


class TestRetrieval(unittest.TestCase):
    def setUp(self):
        self.kb = get_kb()

    def test_blue_retrieves_a_certutil_rule(self):
        hits = self.kb.retrieve("certutil download urlcache T1105 process_creation", "blue", k=3)
        self.assertTrue(hits, "blue partition should return results")
        self.assertIn("certutil", hits[0].doc_id, "top blue hit should be a certutil rule")
        self.assertEqual(hits[0].source, "SigmaHQ")

    def test_red_retrieves_rename_tradecraft_for_image_anchored_rule(self):
        # An Image-anchored certutil rule → the relevant evasion is Rename System Utilities.
        query = ("Certutil LOLBin Remote Download Image endswith certutil.exe -urlcache "
                 "T1105 bypass evasion rename")
        hits = self.kb.retrieve(query, "red", k=3)
        # a top-3 red doc should cover Rename System Utilities (T1036.003) —
        # whether the curated demo doc or the bulk ATT&CK technique doc.
        self.assertTrue(
            any("T1036.003" in h.techniques for h in hits),
            f"Red should surface T1036.003 tradecraft; got {[h.doc_id for h in hits]}",
        )

    def test_retrieval_is_deterministic(self):
        q = "certutil rename OriginalFileName evasion T1036.003"
        a = self.kb.retrieve(q, "red", k=3)
        b = self.kb.retrieve(q, "red", k=3)
        self.assertEqual([(x.doc_id, x.score) for x in a],
                         [(x.doc_id, x.score) for x in b])

    def test_partitions_are_isolated(self):
        # a purely defensive query shouldn't leak red docs and vice-versa
        blue = self.kb.retrieve("sigma detection rule", "blue", k=5)
        self.assertTrue(all(c.doc_id.startswith(("sigma-",)) for c in blue))

    def test_unmatched_query_returns_nothing(self):
        # tokens that appear in no rule → no positive-score hits
        self.assertEqual(self.kb.retrieve("zzqqxx qwertyzxcv floooberwocky", "blue", k=3), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
