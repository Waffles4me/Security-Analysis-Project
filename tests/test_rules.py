"""Tests for detection rules A1-A3 and the end-to-end assessment."""

import json
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from src.models import Scenario
from src.rules import (
    assess,
    has_traversal,
    normalize_for_traversal,
    rule_a1_traversal,
    rule_a2_probing,
    rule_a3_exposure,
)

SCENARIOS = Path(__file__).resolve().parent.parent / "scenarios"


class DecodingTest(unittest.TestCase):
    def test_plain_traversal(self):
        self.assertTrue(has_traversal("/api/files/../../private/report"))

    def test_encoded_dots(self):
        self.assertTrue(has_traversal("/api/files/%2e%2e/%2e%2e/private"))

    def test_encoded_slashes_in_query_value(self):
        self.assertTrue(has_traversal("name=..%2F..%2Fprivate%2Freport"))

    def test_double_encoded(self):
        self.assertTrue(has_traversal("%252e%252e%252f"))

    def test_triple_encoded_is_not_decoded(self):
        value = "%25252e%25252e%25252f"
        self.assertFalse(has_traversal(value))
        # Bounded decoding: raw, decoded once, decoded twice - and no further.
        self.assertEqual(
            normalize_for_traversal(value),
            ["%25252e%25252e%25252f", "%252e%252e%252f", "%2e%2e%2f"],
        )

    def test_double_dot_inside_filename_is_not_traversal(self):
        self.assertFalse(has_traversal("/api/files/user-7/report..final.txt"))

    def test_ordinary_path_is_not_traversal(self):
        self.assertFalse(has_traversal("/api/files/user-7/notes.txt"))

    def test_backslash_separators(self):
        self.assertTrue(has_traversal("..\\..\\private"))


class TraversalAttemptA1Test(unittest.TestCase):
    def findings_by_event(self, scenario):
        findings = rule_a1_traversal(scenario)
        for finding in findings:
            finding.validate(scenario.event_ids)
            self.assertEqual(finding.rule_id, "A1")
            self.assertEqual(len(finding.event_ids), 1)
        return {finding.event_ids[0]: finding for finding in findings}

    def test_suspicious_all_blocked(self):
        findings = self.findings_by_event(Scenario.load(SCENARIOS / "suspicious.json"))
        self.assertEqual(sorted(findings), ["s1", "s2", "s3"])
        for finding in findings.values():
            self.assertIs(finding.successful, False)
        self.assertEqual(findings["s1"].details["field"], "path")
        self.assertEqual(findings["s1"].details["blocked_by"], ["status", "marker"])
        self.assertEqual(findings["s1"].missing_context, ())

    def test_403_with_null_marker_is_blocked_by_status_alone(self):
        s3 = self.findings_by_event(Scenario.load(SCENARIOS / "suspicious.json"))["s3"]
        self.assertIs(s3.successful, False)
        self.assertEqual(s3.details["field"], "query")
        self.assertEqual(s3.details["blocked_by"], ["status"])
        self.assertIsNone(s3.details["marker"])
        self.assertIsNone(s3.details["marker_semantics"])
        self.assertEqual(s3.missing_context, ("event s3: response marker missing",))

    def test_details_record_raw_and_matched_form(self):
        s2 = self.findings_by_event(Scenario.load(SCENARIOS / "suspicious.json"))["s2"]
        self.assertEqual(s2.details["raw"], "/api/files/%2e%2e/%2e%2e/private/report")
        self.assertEqual(s2.details["decoded"], "/api/files/../../private/report")
        self.assertEqual(s2.details["status"], 403)
        self.assertEqual(s2.details["marker"], "access_denied")
        self.assertEqual(s2.details["marker_semantics"], "denial")
        self.assertEqual(s2.summary, "Traversal attempt in path; request blocked (403, denial marker 'access_denied').")

    def test_strong_evidence_a1_alone_never_claims_success(self):
        findings = self.findings_by_event(Scenario.load(SCENARIOS / "strong_evidence.json"))
        self.assertEqual(sorted(findings), ["e1", "e2", "e3"])
        self.assertIs(findings["e1"].successful, False)
        # 200 with a generic marker, and even 200 with a protected_content
        # marker, stay unresolved here: exposure is A3's job.
        self.assertIsNone(findings["e2"].successful)
        self.assertIsNone(findings["e3"].successful)

    def test_benign_has_no_findings(self):
        # b2 is "report..final.txt": dots inside a filename are not traversal.
        self.assertEqual(rule_a1_traversal(Scenario.load(SCENARIOS / "benign.json")), [])

    def test_mutation_200_generic_marker_is_no_longer_blocked(self):
        data = json.loads((SCENARIOS / "suspicious.json").read_text(encoding="utf-8"))
        s1 = next(event for event in data["events"] if event["id"] == "s1")
        s1["status"] = 200
        s1["response_marker"] = "ok"
        findings = self.findings_by_event(Scenario.from_dict(data))
        self.assertIsNone(findings["s1"].successful)
        self.assertEqual(findings["s1"].details["blocked_by"], [])
        # The other events are untouched and still blocked.
        self.assertIs(findings["s2"].successful, False)
        self.assertIs(findings["s3"].successful, False)

    def test_missing_status_and_marker_stay_unresolved(self):
        data = json.loads((SCENARIOS / "suspicious.json").read_text(encoding="utf-8"))
        s1 = next(event for event in data["events"] if event["id"] == "s1")
        s1["status"] = None
        s1["response_marker"] = None
        s1_finding = self.findings_by_event(Scenario.from_dict(data))["s1"]
        self.assertIsNone(s1_finding.successful)
        self.assertEqual(
            s1_finding.missing_context,
            ("event s1: response status missing", "event s1: response marker missing"),
        )

    def suspicious_with_s1(self, keep_only_s1=False, **changes):
        data = json.loads((SCENARIOS / "suspicious.json").read_text(encoding="utf-8"))
        next(event for event in data["events"] if event["id"] == "s1").update(changes)
        if keep_only_s1:
            data["events"] = [event for event in data["events"] if event["id"] == "s1"]
        return self.findings_by_event(Scenario.from_dict(data))

    def test_403_with_protected_content_marker_is_a_conflict_not_blocked(self):
        findings = self.suspicious_with_s1(response_marker="private_report_content")
        s1 = findings["s1"]
        self.assertIsNone(s1.successful)
        self.assertEqual(s1.details["conflict"], {
            "status": 403,
            "marker": "private_report_content",
            "marker_semantics": "protected_content",
        })
        self.assertEqual(
            s1.summary,
            "Traversal attempt in path; response contradictory "
            "(403 with marker 'private_report_content', declared protected_content).",
        )
        self.assertEqual(s1.missing_context, (
            "event s1: status 403 and marker 'private_report_content' (declared protected_content) "
            "contradict each other; what was actually returned is unclear",
        ))
        # The other events are untouched and still blocked.
        self.assertIs(findings["s2"].successful, False)
        self.assertIs(findings["s3"].successful, False)

    def test_401_with_protected_content_marker_is_a_conflict(self):
        s1 = self.suspicious_with_s1(status=401, response_marker="private_report_content")["s1"]
        self.assertIsNone(s1.successful)
        self.assertEqual(s1.details["conflict"]["status"], 401)

    def test_2xx_with_denial_marker_is_a_conflict_not_blocked(self):
        s1 = self.suspicious_with_s1(keep_only_s1=True, status=200)["s1"]
        self.assertIsNone(s1.successful)
        self.assertEqual(s1.details["conflict"], {
            "status": 200,
            "marker": "access_denied",
            "marker_semantics": "denial",
        })
        self.assertIn("contradictory", s1.summary)
        self.assertTrue(any("what was actually returned is unclear" in note for note in s1.missing_context))

    def test_blocking_status_with_non_conflicting_marker_stays_blocked(self):
        # denial, generic, undeclared, missing.
        for marker in ("access_denied", "ok", "foo", None):
            for status in (401, 403):
                with self.subTest(status=status, marker=marker):
                    s1 = self.suspicious_with_s1(status=status, response_marker=marker)["s1"]
                    self.assertIs(s1.successful, False)
                    self.assertIsNone(s1.details["conflict"])

    def test_denial_marker_on_other_non_2xx_status_stays_blocked(self):
        for status in (None, 302, 404, 500):
            with self.subTest(status=status):
                s1 = self.suspicious_with_s1(status=status)["s1"]
                self.assertIs(s1.successful, False)
                self.assertEqual(s1.details["blocked_by"], ["marker"])
                self.assertIsNone(s1.details["conflict"])

    def test_unresolved_statuses_never_assert_an_outcome(self):
        for status in (200, 204, 302, 404, 500):
            with self.subTest(status=status):
                data = json.loads((SCENARIOS / "suspicious.json").read_text(encoding="utf-8"))
                s1 = next(event for event in data["events"] if event["id"] == "s1")
                s1["status"] = status
                s1["response_marker"] = "ok"
                self.assertIsNone(self.findings_by_event(Scenario.from_dict(data))["s1"].successful)


class RepeatedProbingA2Test(unittest.TestCase):
    def scenario_with(self, *events):
        """Scenario with the suspicious.json environment and the given
        (offset_seconds, path, source_ip) events, IDs p1, p2, ..."""
        data = json.loads((SCENARIOS / "suspicious.json").read_text(encoding="utf-8"))
        start = datetime(2026, 9, 19, 12, 0, 0, tzinfo=timezone.utc)
        data["events"] = [
            {
                "id": f"p{i}",
                "timestamp": (start + timedelta(seconds=offset)).isoformat(),
                "actor_id": "user-7",
                "source_ip": source_ip,
                "method": "GET",
                "path": path,
                "status": 404,
                "response_marker": None,
            }
            for i, (offset, path, source_ip) in enumerate(events, start=1)
        ]
        return Scenario.from_dict(data)

    def probe(self, scenario, **kwargs):
        findings = rule_a2_probing(scenario, **kwargs)
        for finding in findings:
            finding.validate(scenario.event_ids)
            self.assertEqual(finding.rule_id, "A2")
            # Probing says nothing about exposure.
            self.assertIsNone(finding.successful)
        return findings

    def test_suspicious_one_burst(self):
        findings = self.probe(Scenario.load(SCENARIOS / "suspicious.json"))
        self.assertEqual([f.event_ids for f in findings], [("s1", "s2", "s3")])
        details = findings[0].details
        self.assertEqual(details["source_ip"], "192.0.2.10")
        # s3 has no actor; the missing value is preserved, not dropped.
        self.assertEqual(details["actor_ids"], ["user-7", None])
        self.assertEqual(details["first_timestamp"], "2026-09-19T10:00:00Z")
        self.assertEqual(details["last_timestamp"], "2026-09-19T10:00:09Z")
        self.assertEqual(details["duration_seconds"], 9)
        self.assertEqual(details["count"], 3)
        self.assertEqual(len(details["distinct_paths"]), 3)
        self.assertEqual(details["a1_count"], 3)
        self.assertEqual(
            findings[0].missing_context,
            ("whether 192.0.2.10 is an authorized scanner or test client",),
        )

    def test_strong_evidence_one_burst(self):
        findings = self.probe(Scenario.load(SCENARIOS / "strong_evidence.json"))
        self.assertEqual([f.event_ids for f in findings], [("e1", "e2", "e3")])
        self.assertEqual(findings[0].details["source_ip"], "198.51.100.23")

    def test_benign_no_burst(self):
        # Only 2 events, more than 60 s apart.
        self.assertEqual(self.probe(Scenario.load(SCENARIOS / "benign.json")), [])

    def test_identical_url_repeated_is_a_retry_not_probing(self):
        scenario = self.scenario_with(
            (0, "/api/files/user-7/a.txt", "192.0.2.10"),
            (5, "/api/files/user-7/a.txt", "192.0.2.10"),
            (10, "/api/files/user-7/a.txt", "192.0.2.10"),
        )
        self.assertEqual(self.probe(scenario), [])

    def test_distinct_paths_spread_over_five_minutes(self):
        scenario = self.scenario_with(
            (0, "/api/files/user-7/a.txt", "192.0.2.10"),
            (150, "/api/files/user-7/b.txt", "192.0.2.10"),
            (300, "/api/files/user-7/c.txt", "192.0.2.10"),
        )
        self.assertEqual(self.probe(scenario), [])

    def test_different_sources_are_not_grouped(self):
        scenario = self.scenario_with(
            (0, "/api/files/user-7/a.txt", "192.0.2.10"),
            (5, "/api/files/user-7/b.txt", "192.0.2.11"),
            (10, "/api/files/user-7/c.txt", "192.0.2.12"),
        )
        self.assertEqual(self.probe(scenario), [])

    def test_window_boundary_is_inclusive(self):
        paths = ("/api/files/user-7/a.txt", "/api/files/user-7/b.txt", "/api/files/user-7/c.txt")
        at_boundary = self.scenario_with(*((t, p, "192.0.2.10") for t, p in zip((0, 30, 60), paths)))
        findings = self.probe(at_boundary)
        self.assertEqual([f.event_ids for f in findings], [("p1", "p2", "p3")])
        self.assertEqual(findings[0].details["duration_seconds"], 60)

        just_outside = self.scenario_with(*((t, p, "192.0.2.10") for t, p in zip((0, 30, 61), paths)))
        self.assertEqual(self.probe(just_outside), [])

    def test_bursts_from_one_source_do_not_overlap(self):
        # A window starting at p2 would reach p4 and p5; it must not be reported,
        # because p2 already belongs to the first burst.
        scenario = self.scenario_with(*(
            (t, f"/api/files/user-7/{t}.txt", "192.0.2.10") for t in (0, 20, 40, 70, 80, 90)
        ))
        findings = self.probe(scenario)
        self.assertEqual([f.event_ids for f in findings], [("p1", "p2", "p3"), ("p4", "p5", "p6")])

    def test_events_without_source_ip_are_excluded_and_noted(self):
        scenario = self.scenario_with(
            (0, "/api/files/user-7/a.txt", "192.0.2.10"),
            (5, "/api/files/user-7/b.txt", "192.0.2.10"),
            (7, "/api/files/user-7/x.txt", None),
            (10, "/api/files/user-7/c.txt", "192.0.2.10"),
        )
        findings = self.probe(scenario)
        self.assertEqual([f.event_ids for f in findings], [("p1", "p2", "p4")])
        self.assertTrue(any("p3" in note and "no source_ip" in note for note in findings[0].missing_context))

    def test_events_without_source_ip_never_form_a_burst(self):
        scenario = self.scenario_with(
            (0, "/api/files/user-7/a.txt", None),
            (5, "/api/files/user-7/b.txt", None),
            (10, "/api/files/user-7/c.txt", None),
        )
        self.assertEqual(self.probe(scenario), [])

    def test_thresholds_are_parameters(self):
        scenario = Scenario.load(SCENARIOS / "suspicious.json")
        self.assertEqual(self.probe(scenario, min_requests=4), [])
        # s1 -> s3 spans 9 s, so a 5 s window holds only two events.
        self.assertEqual(self.probe(scenario, window_seconds=5), [])


class PossibleExposureA3Test(unittest.TestCase):
    def raw(self, name="strong_evidence.json"):
        return json.loads((SCENARIOS / name).read_text(encoding="utf-8"))

    def exposure(self, scenario):
        """A3 findings by event ID, using the events A1 flagged as suspicious."""
        suspicious_ids = {eid for f in rule_a1_traversal(scenario) for eid in f.event_ids}
        findings = rule_a3_exposure(scenario, suspicious_ids)
        for finding in findings:
            finding.validate(scenario.event_ids)
            self.assertEqual(finding.rule_id, "A3")
            self.assertEqual(len(finding.event_ids), 1)
        return {finding.event_ids[0]: finding for finding in findings}

    def mutated_e3(self, **changes):
        data = self.raw()
        next(e for e in data["events"] if e["id"] == "e3").update(changes)
        return self.exposure(Scenario.from_dict(data))["e3"]

    def test_strong_evidence(self):
        findings = self.exposure(Scenario.load(SCENARIOS / "strong_evidence.json"))
        # e1 was a 403: no A3 finding, A1 already covers it.
        self.assertEqual(sorted(findings), ["e2", "e3"])
        self.assertIs(findings["e3"].successful, True)
        self.assertEqual(
            findings["e3"].summary,
            "Response carries protected-content marker 'private_report_content'; exposure supported.",
        )
        self.assertEqual(findings["e3"].missing_context, ())
        # 200 with a generic marker: HTTP 200 alone does not prove exposure.
        self.assertIsNone(findings["e2"].successful)
        self.assertEqual(
            findings["e2"].missing_context,
            ("event e2: marker 'ok' is generic; response content unknown",),
        )

    def test_true_appears_only_for_e3_across_all_scenarios(self):
        successes = []
        for name in ("benign.json", "suspicious.json", "strong_evidence.json"):
            findings = self.exposure(Scenario.load(SCENARIOS / name))
            successes += [eid for eid, f in findings.items() if f.successful is True]
        self.assertEqual(successes, ["e3"])

    def test_suspicious_has_no_a3_findings(self):
        # Every traversal attempt got a 403.
        self.assertEqual(self.exposure(Scenario.load(SCENARIOS / "suspicious.json")), {})

    def test_benign_has_no_a3_findings(self):
        # b1/b2 are 200 responses to unflagged requests, and their marker is
        # declared "expected", not "protected_content".
        self.assertEqual(self.exposure(Scenario.load(SCENARIOS / "benign.json")), {})

    def test_mutation_generic_marker_true_to_none(self):
        e3 = self.mutated_e3(response_marker="ok")
        self.assertIsNone(e3.successful)
        self.assertEqual(e3.missing_context, ("event e3: marker 'ok' is generic; response content unknown",))

    def test_mutation_undeclared_marker_true_to_none(self):
        e3 = self.mutated_e3(response_marker="foo")
        self.assertIsNone(e3.successful)
        self.assertEqual(e3.missing_context, ("event e3: marker 'foo' has no declared semantics",))

    def test_mutation_missing_marker_true_to_none(self):
        e3 = self.mutated_e3(response_marker=None)
        self.assertIsNone(e3.successful)
        self.assertEqual(e3.missing_context, ("event e3: no response marker recorded",))

    def test_mutation_no_protected_resource_true_to_none(self):
        for remove in (True, False):
            with self.subTest(removed=remove):
                data = self.raw()
                if remove:
                    del data["environment"]["protected_resource"]
                else:
                    data["environment"]["protected_resource"] = None
                e3 = self.exposure(Scenario.from_dict(data))["e3"]
                self.assertIsNone(e3.successful)
                self.assertEqual(e3.missing_context, ("event e3: protected_resource not defined",))

    def test_expected_or_denial_marker_on_2xx_is_a_contradiction_not_a_verdict(self):
        for marker, semantics in (("own_file_content", "expected"), ("access_denied", "denial")):
            with self.subTest(marker=marker):
                e3 = self.mutated_e3(response_marker=marker)
                self.assertIsNone(e3.successful)
                self.assertEqual(len(e3.missing_context), 1)
                self.assertIn(semantics, e3.missing_context[0])
                self.assertIn("contradicts", e3.missing_context[0])

    def test_non_2xx_and_missing_status_produce_no_finding(self):
        # Even a protected-content marker is not read as exposure here.
        for status in (None, 302, 403, 404, 500):
            with self.subTest(status=status):
                data = self.raw()
                next(e for e in data["events"] if e["id"] == "e3")["status"] = status
                self.assertNotIn("e3", self.exposure(Scenario.from_dict(data)))

    def test_other_2xx_statuses_are_considered(self):
        self.assertIs(self.mutated_e3(status=206).successful, True)

    def test_protected_marker_on_unflagged_event_is_an_unresolved_finding(self):
        data = self.raw("benign.json")
        data["events"][0]["response_marker"] = "private_report_content"  # b2
        findings = self.exposure(Scenario.from_dict(data))
        self.assertEqual(sorted(findings), ["b2"])
        b2 = findings["b2"]
        # Protected content was returned; that the access was improper is not shown.
        self.assertIsNone(b2.successful)
        self.assertIs(b2.details["flagged_by_a1"], False)
        self.assertEqual(
            b2.missing_context,
            ("event b2: whether actor 'user-7' is entitled to the protected resource is not established",),
        )

    def test_unflagged_event_with_unknown_actor_says_so(self):
        data = self.raw("benign.json")
        data["events"][0].update(response_marker="private_report_content", actor_id=None)
        b2 = self.exposure(Scenario.from_dict(data))["b2"]
        self.assertIsNone(b2.successful)
        self.assertEqual(
            b2.missing_context,
            ("event b2: whether the actor (actor_id unknown) is entitled to the protected resource "
             "is not established",),
        )

    def test_unflagged_event_without_protected_resource_is_never_true(self):
        data = self.raw("benign.json")
        data["events"][0]["response_marker"] = "private_report_content"
        del data["environment"]["protected_resource"]
        b2 = self.exposure(Scenario.from_dict(data))["b2"]
        self.assertIsNone(b2.successful)
        self.assertIn("event b2: protected_resource not defined", b2.missing_context)

    def test_unflagged_events_need_2xx_and_a_protected_content_marker(self):
        for changes in ({"status": 403}, {"status": None}, {"response_marker": "ok"},
                        {"response_marker": "foo"}, {"response_marker": None}):
            with self.subTest(changes=changes):
                data = self.raw("benign.json")
                data["events"][0]["response_marker"] = "private_report_content"
                data["events"][0].update(changes)
                self.assertEqual(self.exposure(Scenario.from_dict(data)), {})

    def test_flagged_findings_are_marked_as_flagged(self):
        findings = self.exposure(Scenario.load(SCENARIOS / "strong_evidence.json"))
        self.assertIs(findings["e2"].details["flagged_by_a1"], True)
        self.assertIs(findings["e3"].details["flagged_by_a1"], True)

    def test_a2_only_events_with_protected_marker_are_unresolved_findings(self):
        # Three plain requests form an A2 burst; each returns the protected marker.
        data = self.raw("benign.json")
        template = data["events"][0]
        data["events"] = [
            dict(template, id=f"p{i}", timestamp=f"2026-09-19T12:00:0{i}Z",
                 path=f"/api/files/user-7/{i}.txt", response_marker="private_report_content")
            for i in range(3)
        ]
        scenario = Scenario.from_dict(data)
        self.assertEqual(len(rule_a2_probing(scenario)), 1)
        findings = self.exposure(scenario)
        self.assertEqual(sorted(findings), ["p0", "p1", "p2"])
        for finding in findings.values():
            # Being part of a burst does not make the request an attempt.
            self.assertIsNone(finding.successful)
            self.assertIs(finding.details["flagged_by_a1"], False)


class EndToEndAssessTest(unittest.TestCase):
    """The full 8-field assessment for each scenario, checked against the input events."""

    def run_assess(self, data):
        scenario = Scenario.from_dict(data)
        assessment, findings = assess(scenario)
        # No output may cite an ID that is missing from the input.
        assessment.validate(scenario.event_ids)
        for finding in findings:
            finding.validate(scenario.event_ids)
        input_ids = {event["id"] for event in data["events"]}
        self.assertLessEqual(set(assessment.evidence_event_ids), input_ids)
        return assessment.to_dict()

    def raw(self, name):
        return json.loads((SCENARIOS / name).read_text(encoding="utf-8"))

    def test_benign(self):
        self.assertEqual(self.run_assess(self.raw("benign.json")), {
            "classification": "benign",
            "risk_score": 5,
            "confidence": 60,
            "successful": None,
            "evidence_event_ids": ["b1", "b2"],
            "reason": (
                "No rule matched any of the 2 reviewed event(s): no traversal indicator in any "
                "path or query after bounded decoding, and no burst of varied requests from one source."
            ),
            "missing_context": [],
            "recommended_action": "No action required based on these events.",
        })

    def test_suspicious(self):
        self.assertEqual(self.run_assess(self.raw("suspicious.json")), {
            "classification": "suspicious",
            "risk_score": 55,
            "confidence": 80,
            "successful": False,
            "evidence_event_ids": ["s1", "s2", "s3"],
            "reason": (
                "A1 found traversal attempt(s) in s1, s2, s3. "
                "Blocked: s1 returned 403 with marker access_denied, declared denial; "
                "s2 returned 403 with marker access_denied, declared denial; "
                "s3 returned 403 with no response marker. "
                "Exposure of the protected resource is not supported for these requests. "
                "A2 found repeated requests with path variation, which may be probing: "
                "3 requests from 192.0.2.10 within 9 s (s1, s2, s3). "
                "This alone does not show malicious intent or exposure."
            ),
            "missing_context": [
                "event s3: response marker missing",
                "whether 192.0.2.10 is an authorized scanner or test client",
            ],
            "recommended_action": (
                "Review the source and actor behind the blocked traversal attempts and confirm "
                "whether this was authorized testing. "
                "Confirm whether 192.0.2.10 is an authorized scanner or test client."
            ),
        })

    def test_strong_evidence(self):
        result = self.run_assess(self.raw("strong_evidence.json"))
        self.assertIn("e3", result["evidence_event_ids"])
        self.assertEqual(result, {
            "classification": "malicious",
            "risk_score": 100,
            "confidence": 85,
            "successful": True,
            "evidence_event_ids": ["e1", "e2", "e3"],
            "reason": (
                "A1 found traversal attempt(s) in e1, e2, e3. "
                "Exposure supported (A3): e3 returned 200 with marker private_report_content, "
                "declared protected_content. That marker is tied to the protected resource "
                "(account files of other users and /private reports). "
                "The malicious classification rests on that response marker: it reflects "
                "supported exposure, not proven intent or lack of authorization. "
                "Blocked: e1 returned 403 with marker access_denied, declared denial. "
                "Outcome unresolved: e2 returned 200 with marker ok, declared generic. "
                "The response neither shows blocking nor carries a protected-content marker, and "
                "a status such as 200 alone does not prove that protected content was returned. "
                "A2 found repeated requests with path variation, which may be probing: "
                "3 requests from 198.51.100.23 within 11 s (e1, e2, e3). "
                "This alone does not show malicious intent or exposure."
            ),
            "missing_context": [
                "whether 198.51.100.23 is an authorized scanner or test client",
                "event e2: marker 'ok' is generic; response content unknown",
                "event e3: intent of actor user-7 from source 198.51.100.23 is not established",
                "event e3: whether the access by actor user-7 from source 198.51.100.23 was "
                "authorized (for example sanctioned testing) is not established",
                "response content for e2 cannot be confirmed",
            ],
            "recommended_action": (
                "Confirm server-side what was returned for e3 and whether the request was "
                "authorized (for example sanctioned testing). If it was not authorized, restrict "
                "the source and actor and review how this route handles traversal sequences. "
                "Confirm whether 198.51.100.23 is an authorized scanner or test client."
            ),
        })

    def test_single_exposed_event_is_malicious_with_intent_and_authorization_unresolved(self):
        # e3 alone: no probing burst, no other unresolved event.
        data = self.raw("strong_evidence.json")
        data["events"] = [e for e in data["events"] if e["id"] == "e3"]
        result = self.run_assess(data)
        self.assertEqual(result["classification"], "malicious")
        self.assertIs(result["successful"], True)
        self.assertEqual(result["missing_context"], [
            "event e3: intent of actor user-7 from source 198.51.100.23 is not established",
            "event e3: whether the access by actor user-7 from source 198.51.100.23 was "
            "authorized (for example sanctioned testing) is not established",
        ])
        self.assertIn("supported exposure, not proven intent", result["reason"])
        self.assertTrue(result["recommended_action"].startswith(
            "Confirm server-side what was returned for e3 and whether the request was authorized"
        ))
        # The action must not assert a confirmed vulnerability.
        self.assertNotIn("fix", result["recommended_action"])

    def test_exposed_event_with_unknown_actor_or_source_does_not_name_one(self):
        data = self.raw("strong_evidence.json")
        e3 = next(e for e in data["events"] if e["id"] == "e3")
        e3["actor_id"] = None
        result = self.run_assess(data)
        self.assertEqual(result["classification"], "malicious")
        self.assertIn(
            "event e3: intent of an unknown actor from source 198.51.100.23 is not established",
            result["missing_context"],
        )
        self.assertIn(
            "event e3: whether the access by an unknown actor from source 198.51.100.23 was "
            "authorized (for example sanctioned testing) is not established",
            result["missing_context"],
        )
        for note in result["missing_context"]:
            if note.startswith("event e3:"):
                self.assertNotIn("user-7", note)

        e3["source_ip"] = None
        result = self.run_assess(data)
        self.assertIn(
            "event e3: intent of an unknown actor from an unknown source is not established",
            result["missing_context"],
        )

    def test_malicious_never_has_empty_missing_context(self):
        # Row 1 in every shape the tests build: alone, with a burst, with other events.
        full = self.raw("strong_evidence.json")
        alone = self.raw("strong_evidence.json")
        alone["events"] = [e for e in alone["events"] if e["id"] == "e3"]
        for data in (full, alone):
            result = self.run_assess(data)
            self.assertEqual(result["classification"], "malicious")
            notes = [n for n in result["missing_context"] if n.startswith("event e3:")]
            self.assertTrue(any("intent of" in n for n in notes))
            self.assertTrue(any("was authorized" in n for n in notes))

    def test_strong_evidence_without_e3_is_unresolved(self):
        data = self.raw("strong_evidence.json")
        data["events"] = [e for e in data["events"] if e["id"] != "e3"]
        self.assertEqual(self.run_assess(data), {
            "classification": "suspicious",
            "risk_score": 60,
            "confidence": 50,
            "successful": None,
            "evidence_event_ids": ["e1", "e2"],
            "reason": (
                "A1 found traversal attempt(s) in e1, e2. "
                "Blocked: e1 returned 403 with marker access_denied, declared denial. "
                "Outcome unresolved: e2 returned 200 with marker ok, declared generic. "
                "The response neither shows blocking nor carries a protected-content marker, and "
                "a status such as 200 alone does not prove that protected content was returned."
            ),
            "missing_context": [
                "event e2: marker 'ok' is generic; response content unknown",
                "response content for e2 cannot be confirmed",
            ],
            "recommended_action": (
                "Determine what was actually returned for e2 (server-side logs or response "
                "content summary) before concluding exposure."
            ),
        })

    def test_generic_marker_on_e3_removes_the_exposure_claim(self):
        data = self.raw("strong_evidence.json")
        next(e for e in data["events"] if e["id"] == "e3")["response_marker"] = "ok"
        result = self.run_assess(data)
        self.assertEqual(result["classification"], "suspicious")
        self.assertIsNone(result["successful"])
        self.assertEqual(result["risk_score"], 75)
        self.assertIn("response content for e2, e3 cannot be confirmed", result["missing_context"])

    def test_missing_protected_resource_overrides_to_insufficient_data(self):
        data = self.raw("strong_evidence.json")
        data["environment"]["protected_resource"] = None
        result = self.run_assess(data)
        self.assertEqual(result["classification"], "insufficient_data")
        self.assertIsNone(result["successful"])
        self.assertIn("event e3: protected_resource not defined", result["missing_context"])
        self.assertIn("environment.protected_resource not provided", result["missing_context"])

    def test_missing_response_markers_overrides_to_insufficient_data(self):
        for name in ("suspicious.json", "strong_evidence.json"):
            with self.subTest(name=name):
                data = self.raw(name)
                del data["environment"]["response_markers"]
                result = self.run_assess(data)
                self.assertEqual(result["classification"], "insufficient_data")
                self.assertIsNot(result["successful"], True)
                self.assertIn("environment.response_markers not provided", result["missing_context"])

    def test_override_does_not_apply_without_findings(self):
        data = self.raw("benign.json")
        del data["environment"]["response_markers"]
        data["environment"]["protected_resource"] = None
        result = self.run_assess(data)
        self.assertEqual(result["classification"], "benign")
        self.assertIn("environment.response_markers not provided", result["missing_context"])

    def test_200_with_denial_marker_is_unresolved_not_blocked(self):
        # The denial marker suggests blocking; the 200 contradicts it.
        data = self.raw("suspicious.json")
        data["events"] = data["events"][:1]
        data["events"][0]["status"] = 200
        result = self.run_assess(data)
        self.assertEqual(result["classification"], "suspicious")
        self.assertIsNone(result["successful"])
        self.assertTrue(any("contradicts" in note for note in result["missing_context"]))
        self.assertIn("Contradictory response: s1 returned 200", result["reason"])

    def test_403_with_protected_content_marker_is_unresolved_not_blocked(self):
        data = self.raw("suspicious.json")
        next(e for e in data["events"] if e["id"] == "s1")["response_marker"] = "private_report_content"
        scenario = Scenario.from_dict(data)
        _, findings = assess(scenario)
        self.assertNotIn(True, [f.successful for f in findings])
        a1 = {f.event_ids[0]: f.successful for f in findings if f.rule_id == "A1"}
        self.assertEqual(a1, {"s1": None, "s2": False, "s3": False})

        result = self.run_assess(data)
        self.assertEqual(result["classification"], "suspicious")
        self.assertIsNone(result["successful"])
        # 60 for an unresolved traversal attempt + 15 for the probing burst.
        self.assertEqual(result["risk_score"], 75)
        self.assertIn(
            "Contradictory response: s1 returned 403 with marker private_report_content, "
            "declared protected_content. The status and the marker disagree, so neither blocking "
            "nor exposure is supported.",
            result["reason"],
        )
        self.assertIn("Blocked: s2 returned 403", result["reason"])
        # The wording for an ordinary unresolved response would be false here.
        self.assertNotIn("nor carries a protected-content marker", result["reason"])
        self.assertIn(
            "event s1: status 403 and marker 'private_report_content' (declared protected_content) "
            "contradict each other; what was actually returned is unclear",
            result["missing_context"],
        )

    def test_protected_marker_on_unflagged_request_is_suspicious_not_benign(self):
        data = self.raw("benign.json")
        data["events"][0]["response_marker"] = "private_report_content"  # b2
        scenario = Scenario.from_dict(data)
        _, findings = assess(scenario)
        self.assertEqual([(f.rule_id, f.event_ids, f.successful) for f in findings], [("A3", ("b2",), None)])
        self.assertEqual(self.run_assess(data), {
            "classification": "suspicious",
            "risk_score": 50,
            "confidence": 50,
            "successful": None,
            "evidence_event_ids": ["b2"],
            "reason": (
                "No traversal indicator was found in any path or query after bounded decoding. "
                "Protected-content marker on a request A1 did not flag: b2 returned 200 with "
                "marker private_report_content, declared protected_content. The log does not show "
                "whether the actor was entitled to that content, so improper exposure is neither "
                "supported nor ruled out."
            ),
            "missing_context": [
                "event b2: whether actor 'user-7' is entitled to the protected resource is not established",
            ],
            "recommended_action": (
                "Establish whether the actor behind b2 is entitled to the protected resource "
                "(authorization records for that request)."
            ),
        })

    def test_unflagged_protected_marker_without_protected_resource_is_insufficient_data(self):
        data = self.raw("benign.json")
        data["events"][0]["response_marker"] = "private_report_content"
        del data["environment"]["protected_resource"]
        _, findings = assess(Scenario.from_dict(data))
        self.assertEqual([f.successful for f in findings], [None])
        result = self.run_assess(data)
        self.assertEqual(result["classification"], "insufficient_data")
        self.assertIsNone(result["successful"])
        self.assertIn("event b2: protected_resource not defined", result["missing_context"])
        self.assertIn("environment.protected_resource not provided", result["missing_context"])

    def test_blocked_traversal_plus_unflagged_protected_marker_is_not_reported_blocked(self):
        # Every traversal attempt in suspicious.json is blocked (successful False
        # on its own). One later, unflagged request returns protected content.
        data = self.raw("suspicious.json")
        data["events"].append({
            "id": "s4",
            "timestamp": "2026-09-19T10:05:00Z",
            "actor_id": "user-7",
            "source_ip": "192.0.2.10",
            "method": "GET",
            "path": "/api/files/user-9/report.pdf",
            "status": 200,
            "response_marker": "private_report_content",
        })
        result = self.run_assess(data)
        self.assertEqual(result["classification"], "suspicious")
        self.assertIsNone(result["successful"])
        # 50 for the unflagged protected-content response + 15 for the s1-s3 burst.
        self.assertEqual(result["risk_score"], 65)
        self.assertEqual(result["confidence"], 50)
        self.assertEqual(result["evidence_event_ids"], ["s1", "s2", "s3", "s4"])
        self.assertIn("Blocked: s1 returned 403", result["reason"])
        self.assertIn(
            "s4 returned 200 with marker private_report_content, declared protected_content",
            result["reason"],
        )
        self.assertIn(
            "event s4: whether actor 'user-7' is entitled to the protected resource is not established",
            result["missing_context"],
        )

    def test_unflagged_protected_marker_does_not_change_a_supported_exposure(self):
        data = self.raw("strong_evidence.json")
        data["events"].append({
            "id": "e4",
            "timestamp": "2026-09-19T11:10:00Z",
            "actor_id": None,
            "source_ip": "198.51.100.23",
            "method": "GET",
            "path": "/api/files/user-9/report.pdf",
            "status": 200,
            "response_marker": "private_report_content",
        })
        result = self.run_assess(data)
        self.assertEqual(result["classification"], "malicious")
        self.assertIs(result["successful"], True)
        # Still surfaced, not hidden by the higher row.
        self.assertIn("e4 returned 200", result["reason"])
        self.assertIn(
            "event e4: whether the actor (actor_id unknown) is entitled to the protected resource "
            "is not established",
            result["missing_context"],
        )

    def test_only_strong_evidence_is_ever_malicious_or_successful(self):
        for name in ("benign.json", "suspicious.json"):
            with self.subTest(name=name):
                result = self.run_assess(self.raw(name))
                self.assertNotEqual(result["classification"], "malicious")
                self.assertIsNot(result["successful"], True)


if __name__ == "__main__":
    unittest.main()
