"""Input and output models for the API Incident Investigator.

Design rules (from CLAUDE.md):
- Missing facts stay ``None``; they are never replaced with assumed values.
- Invalid input fails loudly with ``ValidationError`` instead of being silently
  coerced or mis-ordered.
- An assessment may only cite event IDs that exist in the loaded input.
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional


class ValidationError(ValueError):
    """Raised when input or output data does not satisfy the documented schema."""


# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

ENVIRONMENT_FIELDS = (
    "service",
    "route_purpose",
    "protected_resource",
    "expected_access",
    "auth_model",
    "deployment",
)

EVENT_FIELDS = (
    "id",
    "timestamp",
    "actor_id",
    "source_ip",
    "method",
    "path",
    "query",
    "request_body",
    "status",
    "response_marker",
    "response_size",
)

REQUIRED_EVENT_FIELDS = ("id", "timestamp", "method", "path")

HTTP_METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}

# Semantics a response marker can carry. Only ``protected_content`` can ever
# support ``successful: true`` for exposure; ``generic`` (and any marker whose
# meaning is not declared) cannot.
MARKER_SEMANTICS = {
    "expected",           # normal content the requester is entitled to
    "denial",             # the server refused the request (e.g. access_denied)
    "generic",            # too generic to show what was returned (e.g. "ok")
    "protected_content",  # uniquely tied to the protected resource
}

CLASSIFICATIONS = {"benign", "suspicious", "malicious", "insufficient_data"}


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _optional_str(data: dict, key: str, where: str) -> Optional[str]:
    value = data.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValidationError(f"{where}: '{key}' must be a string or null, got {type(value).__name__}")
    return value


def _optional_int(data: dict, key: str, where: str) -> Optional[int]:
    value = data.get(key)
    if value is None:
        return None
    # bool is a subclass of int; reject it explicitly.
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValidationError(f"{where}: '{key}' must be an integer or null, got {type(value).__name__}")
    return value


def parse_timestamp(value: Any, where: str = "timestamp") -> datetime:
    """Parse an ISO 8601 timestamp. A timezone is required so ordering is unambiguous."""
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{where}: timestamp must be a non-empty ISO 8601 string")
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValidationError(f"{where}: unparseable timestamp {value!r}") from exc
    if parsed.tzinfo is None:
        raise ValidationError(f"{where}: timestamp {value!r} has no timezone (use e.g. 'Z' or '+00:00')")
    return parsed


# --------------------------------------------------------------------------- #
# Input models
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class Environment:
    """API context. Every field may be ``None``; missing context is reported, not assumed."""

    service: Optional[str] = None
    route_purpose: Optional[str] = None
    protected_resource: Optional[str] = None
    expected_access: Optional[str] = None
    auth_model: Optional[str] = None
    deployment: Optional[str] = None
    # Declared meaning of each response marker, e.g. {"access_denied": "denial"}.
    # A marker that is not declared here has unknown semantics.
    response_markers: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Any) -> "Environment":
        if not isinstance(data, dict):
            raise ValidationError("'environment' must be an object")
        allowed = set(ENVIRONMENT_FIELDS) | {"response_markers"}
        unknown = sorted(set(data) - allowed)
        if unknown:
            raise ValidationError(f"environment: unknown field(s) {unknown}")

        values = {name: _optional_str(data, name, "environment") for name in ENVIRONMENT_FIELDS}

        markers = data.get("response_markers") or {}
        if not isinstance(markers, dict):
            raise ValidationError("environment: 'response_markers' must be an object")
        for marker, meaning in markers.items():
            if meaning not in MARKER_SEMANTICS:
                raise ValidationError(
                    f"environment: marker {marker!r} has invalid semantics {meaning!r}; "
                    f"expected one of {sorted(MARKER_SEMANTICS)}"
                )
        return cls(**values, response_markers=dict(markers))

    def missing_fields(self) -> list[str]:
        """Environment fields that are absent or null."""
        return [name for name in ENVIRONMENT_FIELDS if getattr(self, name) is None]

    def marker_semantics(self, marker: Optional[str]) -> Optional[str]:
        """Declared meaning of a marker, or ``None`` if the marker is absent or undeclared."""
        if marker is None:
            return None
        return self.response_markers.get(marker)


@dataclass(frozen=True)
class Event:
    """One HTTP request/response pair. Optional fields are ``None`` when not observed."""

    id: str
    timestamp: datetime
    method: str
    path: str
    actor_id: Optional[str] = None
    source_ip: Optional[str] = None
    query: Optional[str] = None
    request_body: Optional[str] = None
    status: Optional[int] = None
    response_marker: Optional[str] = None
    response_size: Optional[int] = None

    @classmethod
    def from_dict(cls, data: Any, index: int) -> "Event":
        where = f"events[{index}]"
        if not isinstance(data, dict):
            raise ValidationError(f"{where}: event must be an object")
        unknown = sorted(set(data) - set(EVENT_FIELDS))
        if unknown:
            raise ValidationError(f"{where}: unknown field(s) {unknown}")
        for name in REQUIRED_EVENT_FIELDS:
            if data.get(name) is None:
                raise ValidationError(f"{where}: missing required field '{name}'")

        event_id = data["id"]
        if not isinstance(event_id, str) or not event_id.strip():
            raise ValidationError(f"{where}: 'id' must be a non-empty string")
        where = f"event '{event_id}'"

        method = data["method"]
        if not isinstance(method, str) or method.upper() not in HTTP_METHODS:
            raise ValidationError(f"{where}: unsupported HTTP method {method!r}")

        path = data["path"]
        if not isinstance(path, str) or not path.startswith("/"):
            raise ValidationError(f"{where}: 'path' must be a string starting with '/'")

        source_ip = _optional_str(data, "source_ip", where)
        if source_ip is not None:
            try:
                ipaddress.ip_address(source_ip)
            except ValueError as exc:
                raise ValidationError(f"{where}: invalid source_ip {source_ip!r}") from exc

        status = _optional_int(data, "status", where)
        if status is not None and not 100 <= status <= 599:
            raise ValidationError(f"{where}: HTTP status {status} out of range 100-599")

        response_size = _optional_int(data, "response_size", where)
        if response_size is not None and response_size < 0:
            raise ValidationError(f"{where}: 'response_size' must be >= 0")

        return cls(
            id=event_id,
            timestamp=parse_timestamp(data["timestamp"], where),
            method=method.upper(),
            path=path,
            actor_id=_optional_str(data, "actor_id", where),
            source_ip=source_ip,
            query=_optional_str(data, "query", where),
            request_body=_optional_str(data, "request_body", where),
            status=status,
            response_marker=_optional_str(data, "response_marker", where),
            response_size=response_size,
        )


@dataclass(frozen=True)
class Scenario:
    """Validated input: environment plus events sorted into a timeline."""

    environment: Environment
    events: tuple[Event, ...]  # chronological order

    @classmethod
    def from_dict(cls, data: Any) -> "Scenario":
        if not isinstance(data, dict):
            raise ValidationError("root JSON value must be an object")
        unknown = sorted(set(data) - {"environment", "events"})
        if unknown:
            raise ValidationError(f"unknown top-level field(s) {unknown}")
        if "environment" not in data:
            raise ValidationError("missing top-level 'environment'")
        if "events" not in data:
            raise ValidationError("missing top-level 'events'")
        if not isinstance(data["events"], list):
            raise ValidationError("'events' must be an array")

        environment = Environment.from_dict(data["environment"])
        events = [Event.from_dict(item, i) for i, item in enumerate(data["events"])]

        seen: set[str] = set()
        for event in events:
            if event.id in seen:
                raise ValidationError(f"duplicate event id '{event.id}'")
            seen.add(event.id)

        # Stable sort: events with identical timestamps keep their input order.
        events.sort(key=lambda e: e.timestamp)
        return cls(environment=environment, events=tuple(events))

    @classmethod
    def load(cls, path: str | Path) -> "Scenario":
        try:
            text = Path(path).read_text(encoding="utf-8")
        except OSError as exc:
            raise ValidationError(f"cannot read {path}: {exc.strerror or exc}") from exc
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValidationError(f"{path}: invalid JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}") from exc
        return cls.from_dict(data)

    @property
    def event_ids(self) -> set[str]:
        return {event.id for event in self.events}

    def get_event(self, event_id: str) -> Event:
        for event in self.events:
            if event.id == event_id:
                return event
        raise KeyError(event_id)


# --------------------------------------------------------------------------- #
# Output model
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class Finding:
    """One rule result, tied to the events that support it.

    ``successful`` is the outcome for the exposure objective, under the same
    evidence rules as ``Assessment.successful``.
    """

    rule_id: str                  # "A1" | "A2" | "A3"
    event_ids: tuple[str, ...]
    summary: str                  # one sentence, factual
    successful: Optional[bool]    # outcome for the exposure objective
    details: dict                 # rule-specific facts (matched values etc.)
    missing_context: tuple[str, ...] = ()

    def validate(self, known_event_ids: set[str]) -> None:
        """Check evidence integrity against the loaded input."""
        if not self.event_ids:
            raise ValidationError(f"finding {self.rule_id}: 'event_ids' must not be empty")
        unknown = [eid for eid in self.event_ids if eid not in known_event_ids]
        if unknown:
            raise ValidationError(f"finding {self.rule_id}: event_ids reference nonexistent events: {unknown}")
        # Identity check: 0 and 1 compare equal to False/True but are not valid here.
        if not (self.successful is None or isinstance(self.successful, bool)):
            raise ValidationError(f"finding {self.rule_id}: 'successful' must be true, false or null")

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "event_ids": list(self.event_ids),
            "summary": self.summary,
            "successful": self.successful,
            "details": dict(self.details),
            "missing_context": list(self.missing_context),
        }


@dataclass
class Assessment:
    """The common assessment format.

    ``successful`` is evidence-based for the incident objective (exposure of the
    protected resource): ``True`` only with success evidence, ``False`` only with
    blocking/failure evidence, ``None`` when unresolved. HTTP 200 alone is never
    enough for ``True``.

    ``risk_score`` and ``confidence`` (0-100) are reasoned lab heuristics, not
    calibrated probabilities.
    """

    classification: str
    risk_score: int
    confidence: int
    successful: Optional[bool]
    evidence_event_ids: list[str]
    reason: str
    missing_context: list[str]
    recommended_action: str

    def validate(self, known_event_ids: set[str]) -> None:
        """Check schema and evidence integrity against the loaded input."""
        if self.classification not in CLASSIFICATIONS:
            raise ValidationError(f"invalid classification {self.classification!r}")
        for name in ("risk_score", "confidence"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 100:
                raise ValidationError(f"'{name}' must be an integer from 0 to 100")
        if self.successful not in (True, False, None):
            raise ValidationError("'successful' must be true, false or null")
        if self.successful is not None and not self.evidence_event_ids:
            raise ValidationError("'successful' is asserted without any evidence_event_ids")
        unknown = [eid for eid in self.evidence_event_ids if eid not in known_event_ids]
        if unknown:
            raise ValidationError(f"evidence_event_ids reference nonexistent events: {unknown}")
        if not isinstance(self.missing_context, list):
            raise ValidationError("'missing_context' must be a list")
        if not self.reason.strip() or not self.recommended_action.strip():
            raise ValidationError("'reason' and 'recommended_action' must be non-empty")

    def to_dict(self) -> dict[str, Any]:
        return {
            "classification": self.classification,
            "risk_score": self.risk_score,
            "confidence": self.confidence,
            "successful": self.successful,
            "evidence_event_ids": list(self.evidence_event_ids),
            "reason": self.reason,
            "missing_context": list(self.missing_context),
            "recommended_action": self.recommended_action,
        }
