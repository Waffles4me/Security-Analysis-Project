"""Deterministic detection rules.

- A1 traversal attempt  - traversal indicators in path/query after limited,
  controlled decoding. Proves an attempt only; 401/403 or a denial marker
  supports "blocked".
- A2 repeated probing   - several requests from one source in a short window
  with path variations. May be an authorized scanner.
- A3 possible exposure  - a suspicious request whose response carries a marker
  declared as ``protected_content``. HTTP 200 alone never proves exposure. The
  same marker on a request A1 did not flag is reported too, but left unresolved.

``assess`` combines the findings of all three rules using the decision table
written above it.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from typing import Optional
from urllib.parse import unquote

from .models import Assessment, Event, Finding, Scenario

# Characters that delimit a segment in a path or query string.
_SEGMENT_SEPARATORS = re.compile(r"[/?&=]")


def normalize_for_traversal(value: str) -> list[str]:
    """Return the distinct forms checked for traversal: raw, decoded once, decoded twice.

    Decoding is bounded: ``unquote`` is applied at most twice and never looped
    until stable, so a triple-encoded payload is deliberately left encoded.
    Backslashes are treated as path separators in every form.
    """
    decoded_once = unquote(value)
    decoded_twice = unquote(decoded_once)
    forms: list[str] = []
    for form in (value, decoded_once, decoded_twice):
        form = form.replace("\\", "/")
        if form not in forms:
            forms.append(form)
    return forms


def has_traversal(value: str) -> bool:
    """True if any checked form contains ``..`` as a whole path segment.

    ``report..final.txt`` is not traversal: the dots are part of a longer segment.
    """
    return _traversal_form(value) is not None


def _traversal_form(value: str) -> Optional[str]:
    """The first checked form of ``value`` with a ``..`` segment, or ``None``."""
    for form in normalize_for_traversal(value):
        if ".." in _SEGMENT_SEPARATORS.split(form):
            return form
    return None


# Statuses that by themselves show the server refused the request.
BLOCKING_STATUSES = (401, 403)


def rule_a1_traversal(scenario: Scenario) -> list[Finding]:
    """A1: one finding per event whose path or query contains a traversal attempt.

    The finding proves an attempt only. ``successful`` is ``False`` when the
    response shows the request was blocked (401/403, or a marker declared as
    ``denial``) and ``None`` otherwise. A1 never returns ``True``; exposure is
    A3's job.

    When status and marker contradict each other (401/403 with a
    ``protected_content`` marker, or 2xx with a ``denial`` marker) the evidence
    does not support blocking, so the outcome is ``None`` and the conflict is
    recorded in ``details``.
    """
    findings: list[Finding] = []
    for event in scenario.events:
        # Path is checked first; an event yields at most one finding.
        for field_name in ("path", "query"):
            raw = getattr(event, field_name)
            decoded = _traversal_form(raw) if raw is not None else None
            if decoded is not None:
                break
        else:
            continue

        marker = event.response_marker
        semantics = scenario.environment.marker_semantics(marker)

        blocked_by: list[str] = []
        if event.status in BLOCKING_STATUSES:
            blocked_by.append("status")
        if semantics == "denial":
            blocked_by.append("marker")

        missing: list[str] = []
        if event.status is None:
            missing.append(f"event {event.id}: response status missing")
        if marker is None:
            missing.append(f"event {event.id}: response marker missing")
        elif semantics is None:
            missing.append(f"event {event.id}: semantics of response marker {marker!r} not declared")

        # Status and marker disagree: neither signal can be trusted on its own.
        conflict: Optional[dict] = None
        is_2xx = event.status is not None and 200 <= event.status <= 299
        if (event.status in BLOCKING_STATUSES and semantics == "protected_content") or (
            is_2xx and semantics == "denial"
        ):
            conflict = {"status": event.status, "marker": marker, "marker_semantics": semantics}
            missing.append(
                f"event {event.id}: status {event.status} and marker {marker!r} (declared "
                f"{semantics}) contradict each other; what was actually returned is unclear"
            )

        if conflict:
            outcome = f"response contradictory ({event.status} with marker {marker!r}, declared {semantics})"
        elif blocked_by:
            signals = []
            if "status" in blocked_by:
                signals.append(str(event.status))
            if "marker" in blocked_by:
                signals.append(f"denial marker {marker!r}")
            outcome = f"request blocked ({', '.join(signals)})"
        else:
            status_text = "status unknown" if event.status is None else f"status {event.status}"
            outcome = f"outcome unresolved ({status_text})"

        findings.append(Finding(
            rule_id="A1",
            event_ids=(event.id,),
            summary=f"Traversal attempt in {field_name}; {outcome}.",
            successful=False if blocked_by and not conflict else None,
            details={
                "field": field_name,
                "raw": raw,
                "decoded": decoded,
                "status": event.status,
                "marker": marker,
                "marker_semantics": semantics,
                "blocked_by": blocked_by,
                "conflict": conflict,
            },
            missing_context=tuple(missing),
        ))
    return findings


def _request_target(event: Event) -> str:
    """Path plus query, as sent. A null and an empty query are the same target.

    Deliberately not percent-decoded: trying different encodings of one path is
    itself path variation, not a retry of the identical URL.
    """
    return event.path + (f"?{event.query}" if event.query else "")


def _iso(moment: datetime) -> str:
    return moment.isoformat().replace("+00:00", "Z")


def _no_source_note(event_ids: list[str]) -> str:
    return f"event(s) {', '.join(event_ids)} have no source_ip and were excluded from probing analysis"


def rule_a2_probing(scenario: Scenario, window_seconds: int = 60, min_requests: int = 3) -> list[Finding]:
    """A2: bursts of requests from one source with path variation.

    A burst is at least ``min_requests`` events from one ``source_ip`` within
    ``window_seconds`` (inclusive) of the burst's first event, covering at least
    two distinct request targets. Repeating one identical URL is a retry, not
    probing. Bursts from one source never overlap.

    ``successful`` is always ``None``: probing says nothing about exposure, and
    the source may be an authorized scanner.
    """
    by_source: dict[str, list[Event]] = {}
    without_source: list[str] = []
    for event in scenario.events:  # already in timeline order
        if event.source_ip is None:
            without_source.append(event.id)
            continue
        # Canonical form, so two spellings of one IPv6 address group together.
        source = str(ipaddress.ip_address(event.source_ip))
        by_source.setdefault(source, []).append(event)

    a1_event_ids = {eid for finding in rule_a1_traversal(scenario) for eid in finding.event_ids}

    findings: list[Finding] = []
    for source, events in by_source.items():
        start = 0
        while start < len(events):
            first = events[start]
            end = start
            while (
                end + 1 < len(events)
                and (events[end + 1].timestamp - first.timestamp).total_seconds() <= window_seconds
            ):
                end += 1
            burst = events[start:end + 1]
            targets = list(dict.fromkeys(_request_target(e) for e in burst))
            if len(burst) < min_requests or len(targets) < 2:
                start += 1
                continue

            last = burst[-1]
            duration = (last.timestamp - first.timestamp).total_seconds()
            missing = [f"whether {source} is an authorized scanner or test client"]
            if without_source:
                missing.append(_no_source_note(without_source))
            findings.append(Finding(
                rule_id="A2",
                event_ids=tuple(e.id for e in burst),
                summary=(
                    f"{len(burst)} requests from {source} within {duration:g} s "
                    f"across {len(targets)} distinct paths."
                ),
                successful=None,
                details={
                    "source_ip": source,
                    "actor_ids": list(dict.fromkeys(e.actor_id for e in burst)),
                    "first_timestamp": _iso(first.timestamp),
                    "last_timestamp": _iso(last.timestamp),
                    "duration_seconds": duration,
                    "distinct_paths": targets,
                    "count": len(burst),
                    "a1_count": sum(1 for e in burst if e.id in a1_event_ids),
                },
                missing_context=tuple(missing),
            ))
            # Bursts must not overlap: continue after this burst's last event.
            start = end + 1

    # Report bursts in timeline order across sources.
    findings.sort(key=lambda f: scenario.get_event(f.event_ids[0]).timestamp)
    return findings


def rule_a3_exposure(scenario: Scenario, suspicious_ids: set[str]) -> list[Finding]:
    """A3: what the response to a suspicious request says about exposure.

    ``suspicious_ids`` are the events flagged by A1. Events that are only part
    of an A2 burst are not suspicious enough on their own for A3.

    Only 2xx responses are considered; A1 already covers the other statuses.
    ``successful`` is ``True`` only when the marker is declared as
    ``protected_content`` and the environment defines the protected resource.
    Every other 2xx response stays ``None``: HTTP 200 alone never proves
    exposure.

    An event A1 did not flag is examined only when its 2xx response carries a
    ``protected_content`` marker. That finding is always ``None``: the log shows
    protected content was returned, not that the actor was not entitled to it.
    """
    environment = scenario.environment
    findings: list[Finding] = []
    for event in scenario.events:
        if event.status is None or not 200 <= event.status <= 299:
            continue

        marker = event.response_marker
        semantics = environment.marker_semantics(marker)
        flagged = event.id in suspicious_ids
        if not flagged and semantics != "protected_content":
            continue

        successful: Optional[bool] = None
        missing: list[str] = []

        if not flagged:
            if environment.protected_resource is None:
                missing.append("protected_resource not defined")
            actor = "the actor (actor_id unknown)" if event.actor_id is None else f"actor {event.actor_id!r}"
            missing.append(f"whether {actor} is entitled to the protected resource is not established")
        elif marker is None:
            missing.append("no response marker recorded")
        elif semantics is None:
            missing.append(f"marker {marker!r} has no declared semantics")
        elif semantics == "generic":
            missing.append(f"marker {marker!r} is generic; response content unknown")
        elif semantics == "protected_content":
            if environment.protected_resource is None:
                # Without a defined protected resource there is nothing the
                # marker can be shown to expose.
                missing.append("protected_resource not defined")
            else:
                successful = True
        else:  # "expected" or "denial"
            missing.append(
                f"marker {marker!r} is declared {semantics!r}, which contradicts a "
                f"{event.status} response to a suspicious request; what was returned is unclear"
            )

        if successful:
            summary = f"Response carries protected-content marker {marker!r}; exposure supported."
        elif not flagged:
            summary = (
                f"Protected-content marker {marker!r} returned to a request A1 did not flag; "
                "entitlement of the actor not established."
            )
        else:
            summary = f"Suspicious request received {event.status}; exposure not established."

        findings.append(Finding(
            rule_id="A3",
            event_ids=(event.id,),
            summary=summary,
            successful=successful,
            details={
                "flagged_by_a1": flagged,
                "status": event.status,
                "marker": marker,
                "marker_semantics": semantics,
                "protected_resource": environment.protected_resource,
            },
            missing_context=tuple(f"event {event.id}: {note}" for note in missing),
        ))
    return findings


# Risk and confidence are reasoned lab heuristics on a 0-100 scale, NOT
# calibrated probabilities. They only rank the cases against each other:
#   risk 5   no traversal attempt found
#   risk 40  traversal attempted, every attempt blocked
#   risk 50  protected content returned to a request A1 did not flag; whether
#            the actor was entitled to it is not established
#   risk 60  traversal attempted, at least one outcome unresolved
#   risk 85  a traversal attempt returned a protected-content marker
#   +15      a probing burst (A2) was also found, capped at 100. So probing
#            alone is 20, with blocked traversal 55, with unresolved traversal
#            75, with supported exposure 100.
# Confidence is how well the evidence supports the stated classification. It is
# higher when the outcome is decided by explicit evidence (a denial, or a
# protected-content marker) than when it rests on the absence of a match or on
# an unresolved response. Probing alone gets a low value because the source may
# be an authorized scanner. A fixed penalty applies when any environment context
# (a documented field, or the response_markers declarations) is missing.
RISK_NO_FINDINGS = 5
RISK_ALL_BLOCKED = 40
RISK_UNFLAGGED_PROTECTED = 50
RISK_UNRESOLVED = 60
RISK_EXPOSURE = 85
RISK_PROBING_BONUS = 15
CONFIDENCE_NO_FINDINGS = 60
CONFIDENCE_ALL_BLOCKED = 80
CONFIDENCE_UNRESOLVED = 50
CONFIDENCE_UNFLAGGED_PROTECTED = 50
CONFIDENCE_PROBING_ONLY = 50
CONFIDENCE_EXPOSURE = 85
CONFIDENCE_PENALTY_INCOMPLETE_ENVIRONMENT = 20


def _response_signal(event: Event, semantics: Optional[str]) -> str:
    """One event's response, as the deciding signal named in the reason."""
    status = "no recorded status" if event.status is None else str(event.status)
    if event.response_marker is None:
        marker = "no response marker"
    elif semantics is None:
        marker = f"marker {event.response_marker} (semantics not declared)"
    else:
        marker = f"marker {event.response_marker}, declared {semantics}"
    return f"{event.id} returned {status} with {marker}"


def _who(event: Event) -> str:
    """The actor and source of one event, saying so when either is not recorded."""
    actor = "an unknown actor" if event.actor_id is None else f"actor {event.actor_id}"
    source = "an unknown source" if event.source_ip is None else f"source {event.source_ip}"
    return f"{actor} from {source}"


# Decision table, applied in order. "A1 outcome" is per traversal attempt. A
# contradictory response (403 with a protected-content marker, 200 with a denial
# marker) is unresolved in A1 itself, so it never counts as blocked.
#
#   1. any A3 finding True          -> malicious,  successful True
#   2. any A1 outcome unresolved    -> suspicious, successful None
#   3. protected content returned
#      to a request A1 did not flag -> suspicious, successful None
#   4. all A1 outcomes blocked      -> suspicious, successful False
#   5. only A2 findings             -> suspicious, successful None
#   6. no findings                  -> benign,     successful None
#
#   Rule 3 sits above rule 4 so that blocked traversal elsewhere in the log
#   cannot report successful False while protected content went out on
#   another request.
#
#   Override: findings exist, but environment.protected_resource or
#   environment.response_markers is missing -> classification
#   "insufficient_data". Rule 1 is never overridden, and cannot apply here
#   anyway: A3 never returns True without a protected resource and a declared
#   protected_content marker.
#
#   "malicious" (rule 1) means exposure is supported by a protected-content
#   marker. It does not claim intent or missing authorization; both are always
#   listed in missing_context for the exposed event(s).
#
#   A2 never sets "successful" and never makes the classification malicious; it
#   adds risk and the authorized-scanner question.
#   evidence_event_ids is every event cited by a finding, in timeline order
#   (rule 6: every event reviewed).
def assess(scenario: Scenario) -> tuple[Assessment, list[Finding]]:
    """Produce the overall assessment for a validated scenario, plus the findings behind it."""
    environment = scenario.environment
    a1_findings = rule_a1_traversal(scenario)
    a2_findings = rule_a2_probing(scenario)
    a1_ids = [eid for f in a1_findings for eid in f.event_ids]  # timeline order, one per event
    a3_findings = rule_a3_exposure(scenario, set(a1_ids))
    findings = a1_findings + a2_findings + a3_findings

    environment_missing = environment.missing_fields()
    markers_missing = not environment.response_markers
    penalty = CONFIDENCE_PENALTY_INCOMPLETE_ENVIRONMENT if environment_missing or markers_missing else 0

    # Outcome per traversal attempt.
    a1_outcome = {f.event_ids[0]: f.successful for f in a1_findings}
    a3_outcome = {f.event_ids[0]: f.successful for f in a3_findings}
    exposed_ids = [eid for eid in a1_ids if a3_outcome.get(eid) is True]
    unresolved_ids = [eid for eid in a1_ids if a1_outcome[eid] is None and eid not in exposed_ids]
    blocked_ids = [eid for eid in a1_ids if eid not in exposed_ids and eid not in unresolved_ids]
    # Unresolved because status and marker contradict each other.
    conflict_ids = [f.event_ids[0] for f in a1_findings if f.details["conflict"]]
    # Protected-content responses to requests A1 did not flag.
    unflagged_ids = [f.event_ids[0] for f in a3_findings if not f.details["flagged_by_a1"]]

    # Union of every cited event, de-duplicated, in timeline order.
    cited = {eid for f in findings for eid in f.event_ids}
    cited_ids = [event.id for event in scenario.events if event.id in cited]

    def signals(event_ids: list[str]) -> str:
        return "; ".join(
            _response_signal(event, environment.marker_semantics(event.response_marker))
            for event in map(scenario.get_event, event_ids)
        )

    missing: list[str] = []
    for finding in findings:
        for note in finding.missing_context:
            if note not in missing:
                missing.append(note)

    if not scenario.events:
        # Nothing was reviewed, so "benign" would be an unsupported claim.
        classification, risk, confidence, successful = "insufficient_data", 0, 0, None
        evidence: list[str] = []
        reason = "The scenario contains no events, so there is nothing to assess."
        action = "Provide request/response events for the time range under investigation."
        missing.append("no events provided")
    elif not findings:
        # Rule 6.
        classification, successful = "benign", None
        risk, confidence = RISK_NO_FINDINGS, CONFIDENCE_NO_FINDINGS - penalty
        evidence = [event.id for event in scenario.events]
        reason = (
            f"No rule matched any of the {len(evidence)} reviewed event(s): "
            "no traversal indicator in any path or query after bounded decoding, "
            "and no burst of varied requests from one source."
        )
        action = "No action required based on these events."
    elif not a1_findings and not unflagged_ids:
        # Rule 5: activity worth a look, but no attempt on the protected resource was found.
        classification, successful = "suspicious", None
        risk, confidence = RISK_NO_FINDINGS, CONFIDENCE_PROBING_ONLY - penalty
        evidence = cited_ids
        reason = "No traversal indicator was found in any path or query after bounded decoding."
        action = ""
    else:
        evidence = cited_ids
        if a1_ids:
            reason = f"A1 found traversal attempt(s) in {', '.join(a1_ids)}."
        else:
            reason = "No traversal indicator was found in any path or query after bounded decoding."
        if exposed_ids:
            # Rule 1.
            classification, successful = "malicious", True
            risk, confidence = RISK_EXPOSURE, CONFIDENCE_EXPOSURE - penalty
            reason += (
                f" Exposure supported (A3): {signals(exposed_ids)}. That marker is tied to the "
                f"protected resource ({environment.protected_resource}). The malicious "
                "classification rests on that response marker: it reflects supported exposure, "
                "not proven intent or lack of authorization."
            )
            action = (
                f"Confirm server-side what was returned for {', '.join(exposed_ids)} and whether "
                "the request was authorized (for example sanctioned testing). If it was not "
                "authorized, restrict the source and actor and review how this route handles "
                "traversal sequences."
            )
            # The marker supports exposure only. Who did it, why, and whether
            # they were permitted to is not in the log.
            for event in map(scenario.get_event, exposed_ids):
                who = _who(event)
                missing.append(f"event {event.id}: intent of {who} is not established")
                missing.append(
                    f"event {event.id}: whether the access by {who} was authorized "
                    "(for example sanctioned testing) is not established"
                )
        elif unresolved_ids:
            # Rule 2.
            classification, successful = "suspicious", None
            risk, confidence = RISK_UNRESOLVED, CONFIDENCE_UNRESOLVED - penalty
            action = (
                f"Determine what was actually returned for {', '.join(unresolved_ids)} "
                "(server-side logs or response content summary) before concluding exposure."
            )
        elif unflagged_ids:
            # Rule 3. The action is added below, with the reason.
            classification, successful = "suspicious", None
            risk, confidence = RISK_UNFLAGGED_PROTECTED, CONFIDENCE_UNFLAGGED_PROTECTED - penalty
            action = ""
        else:
            # Rule 4.
            classification, successful = "suspicious", False
            risk, confidence = RISK_ALL_BLOCKED, CONFIDENCE_ALL_BLOCKED - penalty
            action = (
                "Review the source and actor behind the blocked traversal attempts and confirm "
                "whether this was authorized testing."
            )

        if blocked_ids:
            reason += f" Blocked: {signals(blocked_ids)}."
            if not exposed_ids and not unresolved_ids and not unflagged_ids:
                reason += " Exposure of the protected resource is not supported for these requests."
        if unresolved_ids:
            plain_ids = [eid for eid in unresolved_ids if eid not in conflict_ids]
            if plain_ids:
                reason += (
                    f" Outcome unresolved: {signals(plain_ids)}. The response neither shows "
                    "blocking nor carries a protected-content marker, and a status such as 200 "
                    "alone does not prove that protected content was returned."
                )
            if conflict_ids:
                reason += (
                    f" Contradictory response: {signals(conflict_ids)}. The status and the marker "
                    "disagree, so neither blocking nor exposure is supported."
                )
            missing.append(f"response content for {', '.join(unresolved_ids)} cannot be confirmed")
        if unflagged_ids:
            # Reported under every rule, so a higher rule does not hide it.
            reason += (
                f" Protected-content marker on a request A1 did not flag: {signals(unflagged_ids)}. "
                "The log does not show whether the actor was entitled to that content, so "
                "improper exposure is neither supported nor ruled out."
            )
            action = (
                f"{action} Establish whether the actor behind {', '.join(unflagged_ids)} is "
                "entitled to the protected resource (authorization records for that request)."
            ).strip()

    if a2_findings:
        risk = min(100, risk + RISK_PROBING_BONUS)
        bursts = "; ".join(
            f"{f.details['count']} requests from {f.details['source_ip']} within "
            f"{f.details['duration_seconds']:g} s ({', '.join(f.event_ids)})"
            for f in a2_findings
        )
        reason += (
            f" A2 found repeated requests with path variation, which may be probing: {bursts}. "
            "This alone does not show malicious intent or exposure."
        )
        sources = list(dict.fromkeys(f.details["source_ip"] for f in a2_findings))
        action = (
            f"{action} Confirm whether {', '.join(sources)} is an authorized scanner or test client."
        ).strip()
    else:
        # A2 findings carry this note themselves; without a burst it is added here.
        without_source = [event.id for event in scenario.events if event.source_ip is None]
        if without_source:
            missing.append(_no_source_note(without_source))

    # Override: findings cannot be interpreted without knowing what is protected
    # and what the response markers mean.
    if findings and classification != "malicious" and (
        environment.protected_resource is None or markers_missing
    ):
        classification = "insufficient_data"
        reason += (
            " The environment does not define the protected resource and/or the meaning of "
            "response markers, so these findings cannot be classified further."
        )
        action = (
            "Provide environment.protected_resource and environment.response_markers, "
            f"then re-run the analysis. {action}"
        ).strip()

    missing.extend(f"environment.{name} not provided" for name in environment_missing)
    if markers_missing:
        missing.append("environment.response_markers not provided")

    assessment = Assessment(
        classification=classification,
        risk_score=risk,
        confidence=confidence,
        successful=successful,
        evidence_event_ids=evidence,
        reason=reason,
        missing_context=missing,
        recommended_action=action,
    )
    return assessment, findings
