"""Schema, parsing, timeline and output-integrity tests."""

import contextlib
import copy
import io
import json
import unittest
from pathlib import Path

from src import cli
from src.models import Assessment, Scenario, ValidationError, parse_timestamp
from src.rules import assess

SCENARIOS = Path(__file__).resolve().parent.parent / "scenarios"
SCENARIO_FILES = ("benign.json", "suspicious.json", "strong_evidence.json")


def load_raw(name):
    return json.loads((SCENARIOS / name).read_text(encoding="utf-8"))


class ScenarioFilesTest(unittest.TestCase):
    def test_all_scenarios_load(self):
        for name in SCENARIO_FILES:
            with self.subTest(name=name):
                scenario = Scenario.load(SCENARIOS / name)
                self.assertGreater(len(scenario.events), 0)
                self.assertEqual(scenario.environment.missing_fields(), [])

    def test_events_are_sorted_into_timeline(self):
        # benign.json lists b2 before b1 on purpose.
        scenario = Scenario.load(SCENARIOS / "benign.json")
        self.assertEqual([e.id for e in scenario.events], ["b1", "b2"])

    def test_missing_event_fields_stay_none(self):
        scenario = Scenario.load(SCENARIOS / "suspicious.json")
        s3 = scenario.get_event("s3")
        self.assertIsNone(s3.actor_id)
        self.assertIsNone(s3.response_marker)
        self.assertIsNone(s3.response_size)


class TimestampTest(unittest.TestCase):
    def test_z_suffix(self):
        self.assertEqual(parse_timestamp("2026-09-19T10:00:00Z").utcoffset().total_seconds(), 0)

    def test_offset_ordering(self):
        a = parse_timestamp("2026-09-19T12:00:00+02:00")
        b = parse_timestamp("2026-09-19T10:30:00Z")
        self.assertLess(a, b)

    def test_rejects_invalid_and_naive(self):
        for bad in ("not-a-date", "", "2026-13-01T00:00:00Z", "2026-09-19T10:00:00", 1234):
            with self.subTest(value=bad):
                with self.assertRaises(ValidationError):
                    parse_timestamp(bad)


class InputValidationTest(unittest.TestCase):
    def setUp(self):
        self.raw = load_raw("suspicious.json")

    def assert_invalid(self, data):
        with self.assertRaises(ValidationError):
            Scenario.from_dict(data)

    def test_missing_top_level_keys(self):
        for key in ("environment", "events"):
            data = copy.deepcopy(self.raw)
            del data[key]
            with self.subTest(key=key):
                self.assert_invalid(data)

    def test_events_must_be_list(self):
        self.raw["events"] = {"id": "x"}
        self.assert_invalid(self.raw)

    def test_duplicate_ids(self):
        self.raw["events"][1]["id"] = self.raw["events"][0]["id"]
        self.assert_invalid(self.raw)

    def test_missing_required_event_field(self):
        for key in ("id", "timestamp", "method", "path"):
            data = copy.deepcopy(self.raw)
            del data["events"][0][key]
            with self.subTest(key=key):
                self.assert_invalid(data)

    def test_bad_field_values(self):
        cases = {
            "status": 999,
            "response_size": -1,
            "source_ip": "999.1.1.1",
            "method": "FETCH",
            "path": "no-leading-slash",
            "actor_id": 7,
        }
        for key, value in cases.items():
            data = copy.deepcopy(self.raw)
            data["events"][0][key] = value
            with self.subTest(key=key):
                self.assert_invalid(data)

    def test_status_bool_rejected(self):
        self.raw["events"][0]["status"] = True
        self.assert_invalid(self.raw)

    def test_unknown_event_field_rejected(self):
        self.raw["events"][0]["respons_marker"] = "typo"
        self.assert_invalid(self.raw)

    def test_invalid_marker_semantics(self):
        self.raw["environment"]["response_markers"]["ok"] = "probably_fine"
        self.assert_invalid(self.raw)

    def test_missing_environment_context_is_reported_not_assumed(self):
        del self.raw["environment"]["auth_model"]
        self.raw["environment"]["expected_access"] = None
        scenario = Scenario.from_dict(self.raw)
        self.assertEqual(scenario.environment.missing_fields(), ["expected_access", "auth_model"])
        self.assertIsNone(scenario.environment.auth_model)

    def test_undeclared_marker_has_unknown_semantics(self):
        scenario = Scenario.from_dict(self.raw)
        self.assertIsNone(scenario.environment.marker_semantics("something_new"))
        self.assertIsNone(scenario.environment.marker_semantics(None))
        self.assertEqual(scenario.environment.marker_semantics("access_denied"), "denial")


class AssessmentIntegrityTest(unittest.TestCase):
    def make(self, **overrides):
        values = dict(
            classification="suspicious",
            risk_score=50,
            confidence=50,
            successful=None,
            evidence_event_ids=["s1"],
            reason="r",
            missing_context=[],
            recommended_action="a",
        )
        values.update(overrides)
        return Assessment(**values)

    def test_valid(self):
        self.make().validate({"s1"})

    def test_nonexistent_evidence_id_rejected(self):
        with self.assertRaises(ValidationError):
            self.make(evidence_event_ids=["s1", "ghost"]).validate({"s1"})

    def test_success_claim_requires_evidence(self):
        for value in (True, False):
            with self.subTest(successful=value):
                with self.assertRaises(ValidationError):
                    self.make(successful=value, evidence_event_ids=[]).validate({"s1"})

    def test_invalid_values_rejected(self):
        for overrides in (
            {"classification": "hacked"},
            {"risk_score": 101},
            {"confidence": -1},
            {"successful": "yes"},
        ):
            with self.subTest(overrides=overrides):
                with self.assertRaises(ValidationError):
                    self.make(**overrides).validate({"s1"})

    def test_output_has_exact_schema_keys(self):
        self.assertEqual(
            set(self.make().to_dict()),
            {"classification", "risk_score", "confidence", "successful",
             "evidence_event_ids", "reason", "missing_context", "recommended_action"},
        )


class PlaceholderAssessTest(unittest.TestCase):
    """Aggregation of rule findings into the assessment, and the CLI output around it."""

    SCHEMA_KEYS = {"classification", "risk_score", "confidence", "successful",
                   "evidence_event_ids", "reason", "missing_context", "recommended_action"}

    def assess_file(self, name):
        scenario = Scenario.load(SCENARIOS / name)
        assessment, findings = assess(scenario)
        assessment.validate(scenario.event_ids)
        for finding in findings:
            finding.validate(scenario.event_ids)
        return scenario, assessment, findings

    def test_benign(self):
        scenario, result, findings = self.assess_file("benign.json")
        self.assertEqual(findings, [])
        self.assertEqual(result.classification, "benign")
        self.assertIsNone(result.successful)
        self.assertEqual(result.risk_score, 5)
        # Evidence is every event reviewed, in timeline order.
        self.assertEqual(result.evidence_event_ids, ["b1", "b2"])
        self.assertIn("No rule matched", result.reason)

    def test_suspicious_all_blocked(self):
        scenario, result, findings = self.assess_file("suspicious.json")
        self.assertEqual(result.classification, "suspicious")
        self.assertIs(result.successful, False)
        # 40 for blocked traversal + 15 for the probing burst.
        self.assertEqual(result.risk_score, 55)
        self.assertEqual(result.evidence_event_ids, ["s1", "s2", "s3"])
        self.assertIn("event s3: response marker missing", result.missing_context)
        self.assertIn("whether 192.0.2.10 is an authorized scanner or test client", result.missing_context)
        self.assertIn("probing", result.reason)

    def test_strong_evidence_exposure_supported(self):
        scenario, result, findings = self.assess_file("strong_evidence.json")
        self.assertEqual(result.classification, "malicious")
        self.assertIs(result.successful, True)
        # 85 for supported exposure + 15 for the probing burst, capped at 100.
        self.assertEqual(result.risk_score, 100)
        self.assertEqual(result.evidence_event_ids, ["e1", "e2", "e3"])
        # e2 is still unresolved and stays reported as such.
        self.assertIn("response content for e2 cannot be confirmed", result.missing_context)

    def probing_raw(self, paths, step_seconds=10):
        """benign.json environment with one request per path from one IP."""
        raw = load_raw("benign.json")
        raw["events"] = [
            {
                "id": f"p{i}",
                "timestamp": f"2026-09-19T12:00:{i * step_seconds:02d}Z",
                "actor_id": "user-7",
                "source_ip": "203.0.113.5",
                "method": "GET",
                "path": path,
                "status": 404,
                "response_marker": None,
            }
            for i, path in enumerate(paths)
        ]
        return raw

    def test_probing_alone_is_suspicious_and_unresolved(self):
        # 3 distinct non-traversal paths in 20 s from one IP.
        raw = self.probing_raw(["/api/files/user-7/a.txt", "/api/files/user-8/b.txt", "/api/admin"])
        scenario = Scenario.from_dict(raw)
        result, findings = assess(scenario)
        result.validate(scenario.event_ids)
        self.assertEqual([f.rule_id for f in findings], ["A2"])
        self.assertEqual(result.classification, "suspicious")
        self.assertIsNone(result.successful)
        self.assertEqual(result.risk_score, 20)
        self.assertEqual(result.evidence_event_ids, ["p0", "p1", "p2"])
        self.assertIn("whether 203.0.113.5 is an authorized scanner or test client", result.missing_context)
        self.assertIn("probing", result.reason)

    def test_reason_mentions_probing_only_when_a2_fired(self):
        _, benign, _ = self.assess_file("benign.json")
        self.assertNotIn("probing", benign.reason)
        # One blocked traversal on its own: A1 fires, A2 does not.
        raw = load_raw("suspicious.json")
        raw["events"] = raw["events"][:1]
        single, findings = assess(Scenario.from_dict(raw))
        self.assertEqual([f.rule_id for f in findings], ["A1"])
        self.assertNotIn("probing", single.reason)
        self.assertEqual(single.risk_score, 40)
        self.assertIs(single.successful, False)

    def test_evidence_is_union_of_a1_and_a2_in_timeline_order(self):
        # p1 is the only traversal; the burst covers p0-p2.
        raw = self.probing_raw(["/api/files/user-7/a.txt", "/api/files/../private", "/api/admin"])
        raw["events"].reverse()  # input order must not matter
        scenario = Scenario.from_dict(raw)
        result, findings = assess(scenario)
        result.validate(scenario.event_ids)
        self.assertEqual(result.evidence_event_ids, ["p0", "p1", "p2"])
        # A2 does not change the outcome A1 established (404: unresolved).
        self.assertIsNone(result.successful)
        self.assertNotEqual(result.classification, "malicious")

    def test_events_without_source_ip_are_noted_when_no_burst(self):
        raw = load_raw("benign.json")
        raw["events"][0]["source_ip"] = None
        result, _ = assess(Scenario.from_dict(raw))
        self.assertTrue(any("no source_ip" in note for note in result.missing_context))

    def test_no_placeholder_or_pending_notes_remain(self):
        for name in SCENARIO_FILES:
            with self.subTest(name=name):
                scenario, result, findings = self.assess_file(name)
                for note in result.missing_context:
                    self.assertNotIn("pending", note)
                    self.assertNotIn("not implemented", note)

    def test_missing_environment_lowers_confidence_and_is_surfaced(self):
        raw = load_raw("benign.json")
        complete, _ = assess(Scenario.from_dict(raw))
        raw["environment"]["auth_model"] = None
        incomplete, _ = assess(Scenario.from_dict(raw))
        self.assertIn("environment.auth_model not provided", incomplete.missing_context)
        self.assertLess(incomplete.confidence, complete.confidence)
        self.assertEqual(incomplete.classification, "benign")

    def test_no_events_is_insufficient_data_not_benign(self):
        raw = load_raw("benign.json")
        raw["events"] = []
        result, findings = assess(Scenario.from_dict(raw))
        result.validate(set())
        self.assertEqual(result.classification, "insufficient_data")
        self.assertEqual(result.evidence_event_ids, [])

    def run_cli(self, *args):
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = cli.main(list(args))
        self.assertEqual(code, 0)
        return buffer.getvalue()

    def test_cli_default_json_is_exactly_the_schema(self):
        for name in SCENARIO_FILES:
            with self.subTest(name=name):
                output = json.loads(self.run_cli(str(SCENARIOS / name), "--json-only"))
                self.assertEqual(set(output), self.SCHEMA_KEYS)

    def test_cli_findings_flag_adds_separate_key(self):
        output = json.loads(self.run_cli(str(SCENARIOS / "suspicious.json"), "--json-only", "--findings"))
        self.assertEqual(set(output), self.SCHEMA_KEYS | {"findings"})
        self.assertEqual(
            [(f["rule_id"], f["event_ids"]) for f in output["findings"]],
            [("A1", ["s1"]), ("A1", ["s2"]), ("A1", ["s3"]), ("A2", ["s1", "s2", "s3"])],
        )

    def test_cli_prints_findings_section_between_timeline_and_assessment(self):
        text = self.run_cli(str(SCENARIOS / "suspicious.json"))
        self.assertLess(text.index("Timeline"), text.index("Findings"))
        self.assertLess(text.index("Findings"), text.index("Assessment"))


if __name__ == "__main__":
    unittest.main()
