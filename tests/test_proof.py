"""
Proof-layer tests: the evaluator, the adversarial battery, coverage labeling,
and Kartikeya's Gate — all deterministic. Requires pydantic (installed).
Run: python src/run.py --evals
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src import evaluator, governance                                   # noqa: E402
from src.state import (                                                  # noqa: E402
    CoverageLabel, CoverageVerdict, DeployIntent, LogSource,
    SigmaRuleArtifact, TestCorpus,
)


def _rule(detection, level="high"):
    return SigmaRuleArtifact(
        title="t", rule_id="t", yaml_text="", detection=detection,
        logsource=LogSource(category="process_creation", product="windows"), level=level,
    )


class TestEvaluator(unittest.TestCase):
    def test_perfect_rule(self):
        rule = _rule({"s": {"CommandLine|contains": "-urlcache"}, "condition": "s"})
        corpus = TestCorpus(
            positives=[{"Image": "certutil.exe", "CommandLine": "certutil -urlcache x"}],
            negatives=[{"Image": "certutil.exe", "CommandLine": "certutil -hashfile x"}],
        )
        ev = evaluator.evaluate(rule, corpus)
        self.assertTrue(ev.passed)
        self.assertEqual((ev.tp, ev.fn, ev.fp, ev.tn), (1, 0, 0, 1))

    def test_false_negative_flagged(self):
        rule = _rule({"s": {"CommandLine|contains": "NOPE"}, "condition": "s"})
        corpus = TestCorpus(positives=[{"CommandLine": "certutil -urlcache"}], negatives=[])
        ev = evaluator.evaluate(rule, corpus)
        self.assertFalse(ev.passed)
        self.assertEqual(ev.fn, 1)


class TestAdversarial(unittest.TestCase):
    def test_image_only_rule_is_evaded_by_rename(self):
        # Image-only anchor → binary rename must evade (the certutil lesson).
        rule = _rule({
            "img": {"Image|endswith": "\\certutil.exe"},
            "flags": {"CommandLine|contains": "-urlcache"},
            "condition": "img and flags",
        })
        corpus = TestCorpus(positives=[{
            "Image": "C:\\Windows\\System32\\certutil.exe",
            "CommandLine": "certutil.exe -urlcache -f http://e/x x",
        }], negatives=[])
        adv = evaluator.adversarial(rule, corpus)
        self.assertGreater(adv.total, 0)
        self.assertTrue(adv.high_severity_evasions, "rename should be a high-sev evasion")
        self.assertFalse(adv.survived)

    def test_rename_resistant_rule_survives(self):
        rule = _rule({
            "of": {"OriginalFileName": "CertUtil.exe"},
            "flags": {"CommandLine|contains": "-urlcache"},
            "condition": "of and flags",
        })
        corpus = TestCorpus(positives=[{
            "Image": "C:\\Windows\\System32\\certutil.exe",
            "OriginalFileName": "CertUtil.exe",
            "CommandLine": "certutil.exe -urlcache -f http://e/x x",
        }], negatives=[])
        adv = evaluator.adversarial(rule, corpus)
        # rename changes Image but OriginalFileName anchor holds
        self.assertEqual(adv.high_severity_evasions, [])
        self.assertTrue(adv.survived)


class TestGate(unittest.TestCase):
    def test_egress_always_requires_human(self):
        cov = CoverageLabel(verdict=CoverageVerdict.real)
        d = governance.compute_gate(level="low", fp_rate=0.0, coverage=cov, intent=DeployIntent())
        self.assertTrue(d.requires_human)
        self.assertEqual(d.tier, "HUMAN_REQUIRED")

    def test_brittle_floors_blast_radius(self):
        cov = CoverageLabel(verdict=CoverageVerdict.brittle)
        d = governance.compute_gate(level="high", fp_rate=0.0, coverage=cov, intent=DeployIntent())
        self.assertGreaterEqual(d.blast_radius, 0.6)

    def test_approval_token_bound_to_hash(self):
        cov = CoverageLabel(verdict=CoverageVerdict.real)
        d = governance.compute_gate(level="low", fp_rate=0.0, coverage=cov, intent=DeployIntent())
        tok = governance.issue_approval(d, "sha256:abc", "alice")
        self.assertTrue(governance.verify_approval(tok, d, "sha256:abc", "alice"))
        self.assertFalse(governance.verify_approval(tok, d, "sha256:DIFFERENT", "alice"))
        self.assertFalse(governance.verify_approval(tok, d, "sha256:abc", "mallory"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
