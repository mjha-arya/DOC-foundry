"""
Adversarial multi-agent workflow tests — the self-repair loop, engine-verified
red-team merging, and end-to-end convergence. Deterministic and offline.
Run: python src/run.py --evals
"""
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src import graph, run                                                # noqa: E402
from src.providers import get_provider                                    # noqa: E402
from src.state import (                                                    # noqa: E402
    AdversarialResult, CoverageLabel, CoverageVerdict, DeployIntent,
    LogSource, SigmaRuleArtifact,
)

_FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "certutil_t1105.json"


def _rule(detection, level="high"):
    return SigmaRuleArtifact(
        title="t", rule_id="t", yaml_text="", detection=detection,
        logsource=LogSource(category="process_creation", product="windows"), level=level,
    )


class TestLoopTermination(unittest.TestCase):
    """The conditional edge routes back to Blue only while there is room to repair."""

    def _route(self, verdict, rnd, maxr):
        state = {"coverage": CoverageLabel(verdict=verdict), "round": rnd, "max_rounds": maxr}
        return graph.route_after_verdict(state)

    def test_brittle_below_cap_repairs(self):
        self.assertEqual(self._route(CoverageVerdict.brittle, 1, 3), "repair")

    def test_brittle_at_cap_terminates(self):
        # cap reached while still brittle → stop looping, hand to the gate
        self.assertEqual(self._route(CoverageVerdict.brittle, 3, 3), "done")

    def test_real_coverage_terminates_immediately(self):
        self.assertEqual(self._route(CoverageVerdict.real, 1, 3), "done")


class TestRedTeamVerification(unittest.TestCase):
    """A red-team proposal is counted ONLY if the deterministic engine confirms
    the rule fails to fire on it. A proposal the rule catches is discarded."""

    def test_only_engine_verified_proposals_are_merged(self):
        rule = _rule({
            "img": {"Image|endswith": "\\certutil.exe"},
            "flags": {"CommandLine|contains": "-urlcache"},
            "condition": "img and flags",
        })
        empty = AdversarialResult(mutations=[], total=0, evaded=0, evasion_rate=0.0,
                                  high_severity_evasions=[], survived=True)
        state = {
            "rule": rule,
            "adversarial": empty,
            "red_team_raw": [
                {  # renamed binary → rule cannot fire → a REAL evasion
                    "id": "evade", "mutation_class": "renamed-lolbin", "severity": "high",
                    "description": "renamed certutil",
                    "event": {"Image": "C:\\x\\AdobeUpdater.exe", "OriginalFileName": "CertUtil.exe",
                              "CommandLine": "AdobeUpdater.exe -urlcache x"},
                },
                {  # unchanged binary → rule fires → NOT an evasion, must be discarded
                    "id": "caught", "mutation_class": "noop", "severity": "high",
                    "description": "plain certutil",
                    "event": {"Image": "C:\\Windows\\System32\\certutil.exe",
                              "CommandLine": "certutil.exe -urlcache x"},
                },
            ],
        }
        out = graph.node_redteam_merge(state)
        props = {p.id: p for p in out["red_team"]}
        self.assertTrue(props["evade"].verified)
        self.assertFalse(props["caught"].verified)
        # only the verified one is merged into the adversarial result
        self.assertEqual(out["adversarial"].total, 1)
        self.assertFalse(out["adversarial"].survived)  # high-sev evasion present


class TestUnevaluableRule(unittest.TestCase):
    """
    A rule the engine refuses to evaluate is BROKEN and repairable — never a crash,
    and never a pass. Live authoring reaches for constructs the engine won't fake
    support for (`|in` is the one models actually emit); the loop must absorb that
    and re-author, not die mid-run.
    """

    _BAD_RULE = (
        "```yaml\n"
        "title: Unevaluable\n"
        "id: bad-in-modifier\n"
        "logsource: {category: process_creation, product: windows}\n"
        "detection:\n"
        "  sel:\n"
        "    CommandLine|in: ['-urlcache', '-verifyctl']\n"
        "  condition: sel\n"
        "level: high\n"
        "```"
    )

    def _run_with_bad_first_rule(self):
        fx = run._load_fixture(_FIXTURE)
        responses = dict(fx["responses"])
        responses["author"] = self._BAD_RULE          # round 1 authors an un-evaluable rule
        provider = get_provider("fixture", responses)
        init = {
            "raw_threat": fx["raw_threat"], "source_type": fx["source_type"],
            "source_ref": fx["source_ref"], "deploy_intent": DeployIntent(),
            "mode": provider.mode, "corpus_source": "model",
            "round": 0, "max_rounds": 3, "rounds": [], "log": [],
        }
        return graph.build_app(provider).invoke(init, config={"recursion_limit": 40})

    def test_unevaluable_rule_is_broken_then_repaired(self):
        final = self._run_with_bad_first_rule()
        rounds = final["rounds"]
        self.assertEqual(rounds[0].verdict, "broken", "an un-evaluable rule is never scored as covered")
        self.assertEqual(rounds[0].outcome, "repair")
        # It never reached the adversary — there is nothing to attack in a rule that
        # does not run, and a live call there would buy nothing.
        self.assertEqual(rounds[0].redteam_proposed, 0)
        self.assertEqual(rounds[0].battery_evaded, 0)
        self.assertIs(final["coverage"].verdict, CoverageVerdict.real, "round 2 should still converge")

    def test_engine_error_is_handed_to_blue_as_evidence(self):
        final = self._run_with_bad_first_rule()
        joined = " ".join(final["log"])
        self.assertIn("NOT EVALUABLE", joined)
        self.assertIn("|in", joined, "the engine's own message names the offending modifier")

    def test_route_skips_battery_when_unevaluable(self):
        self.assertEqual(graph.route_after_evaluate({"rule_error": "boom"}), "unevaluable")
        self.assertEqual(graph.route_after_evaluate({"rule_error": ""}), "ok")
        self.assertEqual(graph.route_after_evaluate({}), "ok")


class TestConvergence(unittest.TestCase):
    """End-to-end offline: brittle v1 → evidence-driven re-author → real-coverage v2."""

    def _run(self):
        fx = run._load_fixture(_FIXTURE)
        provider = get_provider("fixture", fx["responses"])
        app = graph.build_app(provider)
        init = {
            "raw_threat": fx["raw_threat"], "source_type": fx["source_type"],
            "source_ref": fx["source_ref"], "deploy_intent": DeployIntent(),
            "mode": provider.mode, "corpus_source": "model",
            "round": 0, "max_rounds": 3, "rounds": [], "log": [],
        }
        return app.invoke(init, config={"recursion_limit": 40})

    def test_converges_to_real_coverage_in_two_rounds(self):
        final = self._run()
        rounds = final["rounds"]
        self.assertEqual(len(rounds), 2, "should converge in exactly two rounds")
        self.assertEqual(rounds[0].verdict, "brittle")
        self.assertEqual(rounds[0].outcome, "repair")
        self.assertGreaterEqual(rounds[0].redteam_verified, 1, "round 1 red-team should land a bypass")
        self.assertEqual(rounds[1].verdict, "real-coverage")
        self.assertEqual(rounds[1].outcome, "converged")
        self.assertEqual(rounds[1].redteam_verified, 0, "round 2 red-team bypass must be discarded")
        self.assertIs(final["coverage"].verdict, CoverageVerdict.real)

    def test_final_gate_requires_human(self):
        final = self._run()
        self.assertTrue(final["gate"].requires_human)
        self.assertEqual(final["gate"].tier, "HUMAN_REQUIRED")


if __name__ == "__main__":
    unittest.main(verbosity=2)
