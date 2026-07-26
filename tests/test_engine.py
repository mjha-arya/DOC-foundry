"""
Deterministic-engine tests. Pure stdlib (unittest) so the PROOF core is
verifiable with zero external dependencies. Run: python src/run.py --evals
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.engine import (  # noqa: E402
    evaluate,
    count_matches,
    UnsupportedSigmaFeature,
    SigmaConditionError,
)


class TestFieldMatching(unittest.TestCase):
    def test_equals_case_insensitive(self):
        det = {"sel": {"Image": "C:\\Windows\\System32\\cmd.exe"}, "condition": "sel"}
        self.assertTrue(evaluate(det, {"Image": "c:\\windows\\system32\\CMD.EXE"}))

    def test_cased_modifier_is_exact(self):
        det = {"sel": {"Image|cased": "cmd.exe"}, "condition": "sel"}
        self.assertFalse(evaluate(det, {"Image": "CMD.EXE"}))
        self.assertTrue(evaluate(det, {"Image": "cmd.exe"}))

    def test_contains(self):
        det = {"sel": {"CommandLine|contains": "Invoke-Mimikatz"}, "condition": "sel"}
        self.assertTrue(evaluate(det, {"CommandLine": "powershell -enc ... Invoke-Mimikatz ..."}))
        self.assertFalse(evaluate(det, {"CommandLine": "powershell -enc harmless"}))

    def test_startswith_endswith(self):
        det = {"s": {"Image|startswith": "C:\\Temp\\", "Image|endswith": ".exe"}, "condition": "s"}
        self.assertTrue(evaluate(det, {"Image": "C:\\Temp\\dropper.exe"}))
        self.assertFalse(evaluate(det, {"Image": "C:\\Windows\\dropper.exe"}))

    def test_wildcards(self):
        det = {"s": {"CommandLine": "*-enc*"}, "condition": "s"}
        self.assertTrue(evaluate(det, {"CommandLine": "powershell -enc ZQBj"}))
        self.assertFalse(evaluate(det, {"CommandLine": "powershell -command foo"}))

    def test_value_list_is_or(self):
        det = {"s": {"EventID": [4688, 1]}, "condition": "s"}
        self.assertTrue(evaluate(det, {"EventID": 1}))
        self.assertTrue(evaluate(det, {"EventID": 4688}))
        self.assertFalse(evaluate(det, {"EventID": 4104}))

    def test_all_modifier_is_and(self):
        det = {"s": {"CommandLine|contains|all": ["-enc", "hidden"]}, "condition": "s"}
        self.assertTrue(evaluate(det, {"CommandLine": "ps -enc AAA -windowstyle hidden"}))
        self.assertFalse(evaluate(det, {"CommandLine": "ps -enc AAA"}))

    def test_regex(self):
        det = {"s": {"CommandLine|re": r"\benc(oded)?command\b"}, "condition": "s"}
        self.assertTrue(evaluate(det, {"CommandLine": "powershell -EncodedCommand ZZ"}))

    def test_null_matches_absent(self):
        det = {"s": {"ParentImage": None}, "condition": "s"}
        self.assertTrue(evaluate(det, {"Image": "x.exe"}))
        self.assertFalse(evaluate(det, {"ParentImage": "explorer.exe"}))

    def test_dotted_nested_lookup(self):
        det = {"s": {"Event.System.EventID": 4688}, "condition": "s"}
        self.assertTrue(evaluate(det, {"Event": {"System": {"EventID": 4688}}}))

    def test_multivalued_event_field(self):
        det = {"s": {"Hashes|contains": "MD5=ABC"}, "condition": "s"}
        self.assertTrue(evaluate(det, {"Hashes": ["MD5=ABC", "SHA256=DEF"]}))


class TestConditions(unittest.TestCase):
    def _ids(self):
        return {
            "selection": {"EventID": 1},
            "susp": {"CommandLine|contains": "mimikatz"},
            "filter": {"User": "SYSTEM"},
            "condition": "PLACEHOLDER",
        }

    def test_and_or_not(self):
        det = self._ids()
        det["condition"] = "selection and susp and not filter"
        self.assertTrue(evaluate(det, {"EventID": 1, "CommandLine": "run mimikatz", "User": "alice"}))
        self.assertFalse(evaluate(det, {"EventID": 1, "CommandLine": "run mimikatz", "User": "SYSTEM"}))

    def test_parentheses(self):
        det = self._ids()
        det["condition"] = "(selection or susp) and not filter"
        self.assertTrue(evaluate(det, {"EventID": 99, "CommandLine": "x mimikatz", "User": "bob"}))

    def test_one_of_them(self):
        det = self._ids()
        det["condition"] = "1 of them"
        self.assertTrue(evaluate(det, {"User": "SYSTEM"}))
        self.assertFalse(evaluate(det, {"Nothing": "here"}))

    def test_all_of_glob(self):
        det = {
            "sel_a": {"EventID": 1},
            "sel_b": {"Image|endswith": "cmd.exe"},
            "condition": "all of sel_*",
        }
        self.assertTrue(evaluate(det, {"EventID": 1, "Image": "C:\\cmd.exe"}))
        self.assertFalse(evaluate(det, {"EventID": 1, "Image": "C:\\powershell.exe"}))

    def test_unknown_identifier_raises(self):
        det = {"sel": {"EventID": 1}, "condition": "sel and ghost"}
        with self.assertRaises(SigmaConditionError):
            evaluate(det, {"EventID": 1})


class TestHonestyContract(unittest.TestCase):
    """The engine must refuse to fake support — never silently pass."""

    def test_unsupported_modifier_raises(self):
        det = {"s": {"SourceIp|cidr": "10.0.0.0/8"}, "condition": "s"}
        with self.assertRaises(UnsupportedSigmaFeature):
            evaluate(det, {"SourceIp": "10.1.2.3"})

    def test_aggregation_raises(self):
        det = {"s": {"EventID": 4625}, "condition": "s | count() > 5"}
        with self.assertRaises(UnsupportedSigmaFeature):
            evaluate(det, {"EventID": 4625})


class TestDeterminism(unittest.TestCase):
    def test_count_matches_stable(self):
        det = {"s": {"CommandLine|contains": "evil"}, "condition": "s"}
        events = [{"CommandLine": "evil.exe"}, {"CommandLine": "good.exe"}, {"CommandLine": "so evil"}]
        r1 = count_matches(det, events)
        r2 = count_matches(det, events)
        self.assertEqual(r1, [True, False, True])
        self.assertEqual(r1, r2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
