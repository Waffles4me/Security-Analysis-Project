# API Incident Investigator

A small, local Python tool that analyzes **synthetic** API request/response sequences and produces an evidence-linked security assessment. It never connects to a real API, server or cloud account.

## Definitions

- **Event**: one HTTP request together with its observed response (status, response marker, response size), identified by a unique `id` and a timezone-aware `timestamp`.
- **Suspicious API activity**: a request whose syntax or pattern departs from the route's documented purpose. Examples are path traversal (`../`, including bounded URL-encoded variants) and bursts of similar requests with path variations from one source. Suspicious syntax shows that an **attempt** happened, not that it succeeded.
- **Evidence**: explicit field values of real input events (status, `response_marker`, actor, path), read together with the declared environment. Every conclusion cites the event IDs it relies on.
- **Success (Project B)**: **exposure of the protected resource**. `successful` is:
  - `true` only when the `2xx` response to a suspicious request carries a marker declared as `protected_content`,
  - `false` only when the response shows blocking (e.g. `403` with a `denial` marker),
  - `null` otherwise, including HTTP `200` with a generic, missing or undeclared marker.
- **Unknown**: any fact not present in the input (identity, authorization state, intent, response content) stays `null` and is listed in `missing_context`. It is never assumed.

### Why HTTP 200 does not prove exposure

A `200` only says the server returned *something*. That could be an error page, an empty body, a default file, or the requester's own data. Exposure is supported only when the response marker is declared as uniquely tied to the protected content.

## Input schema

```json
{
  "environment": { "...": "see below" },
  "events": [ { "...": "see below" } ]
}
```

### Environment fields

All fields are optional strings; missing ones are reported in `missing_context`.

| Field | Meaning |
|---|---|
| `service` | API/service being analyzed |
| `route_purpose` | intended use of the route |
| `protected_resource` | resource whose exposure matters |
| `expected_access` | authorization expectation, e.g. `owner only` |
| `auth_model` | how identity/authorization works |
| `deployment` | e.g. `staging` |
| `response_markers` | map of marker → semantics: `expected`, `denial`, `generic`, `protected_content`. Undeclared markers have **unknown** semantics. |

### Event fields

| Field | Required | Type | Notes |
|---|---|---|---|
| `id` | yes | string | unique |
| `timestamp` | yes | string | ISO 8601 with timezone (`Z` or `+hh:mm`) |
| `method` | yes | string | GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS |
| `path` | yes | string | starts with `/` |
| `actor_id` | no | string/null | authenticated identity, `null` if unknown |
| `source_ip` | no | string/null | valid IPv4/IPv6 |
| `query` | no | string/null | filtered/sanitized query string |
| `request_body` | no | string/null | |
| `status` | no | int/null | 100-599; `null` means no response observed |
| `response_marker` | no | string/null | summary marker, used instead of storing sensitive bodies |
| `response_size` | no | int/null | bytes, >= 0 |

Unknown fields are rejected so that typos fail loudly. Events are sorted by timestamp before analysis.

## Output schema

```json
{
  "classification": "benign|suspicious|malicious|insufficient_data",
  "risk_score": 0,
  "confidence": 0,
  "successful": null,
  "evidence_event_ids": [],
  "reason": "...",
  "missing_context": [],
  "recommended_action": "..."
}
```

`risk_score` and `confidence` (0-100) are reasoned lab heuristics, **not calibrated probabilities**. Every ID in `evidence_event_ids` is checked to exist in the input.

## Scenarios (synthetic)

| File | Concept |
|---|---|
| `scenarios/benign.json` | Owner `user-7` reads their own files (`200` + `own_file_content`). Includes a filename containing `..` (`report..final.txt`) as false-positive protection. Events are listed out of order to exercise sorting. |
| `scenarios/suspicious.json` | Traversal attempts toward `/private/report` (plain, encoded, in query), all `403`. `s3` has missing actor, marker and size (missing-data case). |
| `scenarios/strong_evidence.json` | `e1` blocked (`403`); `e2` `200` with generic marker `ok` (unresolved); `e3` `200` with `private_report_content` (supports exposure). |

## Usage

Requires Python 3.10+; standard library only.

```bash
python -m src.cli scenarios/benign.json
python -m src.cli scenarios/suspicious.json --json-only
python -m src.cli scenarios/strong_evidence.json --findings
```

The default output is the timeline, a table of rule findings, and the JSON assessment. `--json-only` prints only the JSON. `--findings` adds the rule findings to the JSON under a separate `findings` key. `examples/output.json` is the `--json-only` output for `scenarios/strong_evidence.json`.

Exit code `2` with an `error:` message means the input failed validation.

## Tests

```bash
python -m unittest discover -s tests
```

## Rules

Each rule is a deterministic function in `src/rules.py` that returns findings. A finding names the rule, the event IDs it relies on, and its own `successful` value for the exposure objective.

### A1 Traversal attempt

Flags an event whose `path` or `query` contains `..` as a whole segment, i.e. the text between separators (`/`, `?`, `&`, `=`, start, end) is exactly `..`. A filename such as `report..final.txt` does not match.

- **Bounded decoding:** each value is checked raw, URL-decoded once, and URL-decoded twice. Decoding never loops, so a triple-encoded payload is not decoded further. Backslashes are treated as `/`.
- **Outcome:** `false` (blocked) when the status is `401` or `403`, or the marker is declared `denial`. `null` in every other case, including `2xx`, `3xx`, `404`, `5xx` and a missing status.
- **Boundary:** A1 shows an attempt. It never returns `true`.

### A2 Repeated probing

Flags a burst of requests from one `source_ip` with path variation.

| Parameter | Default | Meaning |
|---|---|---|
| `window_seconds` | `60` | a burst spans at most this long from its first event; the boundary is inclusive |
| `min_requests` | `3` | minimum number of events in a burst |

- A burst also needs at least **2 distinct** request targets (path plus query, compared as sent). Repeating one identical URL is a retry, not probing.
- Bursts from one source do not overlap. Events without a `source_ip` are excluded and listed in `missing_context`.
- **Outcome:** always `null`. Probing says nothing about exposure, and the source may be an authorized scanner; that question is always added to `missing_context`.

### A3 Possible exposure

Looks at the response to each event that A1 flagged, when its status is `2xx`. Events that are only part of an A2 burst are not examined.

| Response marker | `successful` |
|---|---|
| declared `protected_content`, and `protected_resource` is defined | `true` |
| declared `protected_content`, but `protected_resource` is missing | `null` |
| declared `generic` | `null` |
| missing, or not declared in `response_markers` | `null` |
| declared `expected` or `denial` (contradicts the `2xx`) | `null` |

Non-`2xx` responses produce no A3 finding.

### Decision table

`assess()` combines the findings in this order:

| # | Condition | `classification` | `successful` |
|---|---|---|---|
| 1 | any A3 finding is `true` | `malicious` | `true` |
| 2 | any traversal attempt is unresolved | `suspicious` | `null` |
| 3 | every traversal attempt was blocked | `suspicious` | `false` |
| 4 | only A2 findings | `suspicious` | `null` |
| 5 | no findings | `benign` | `null` |

- **Override:** if there are findings but `protected_resource` or `response_markers` is missing, the classification becomes `insufficient_data`. Row 1 is never overridden.
- **A1 versus A3:** when A3 examined an event, its reading is used, so a `200` with a `denial` marker counts as unresolved, not blocked.
- **A2:** never sets `successful` and never makes the result `malicious`.
- **Evidence:** `evidence_event_ids` is every event cited by a finding, in timeline order. In row 5 it is every event reviewed.

### Risk and confidence values

| Case | `risk_score` | `confidence` |
|---|---|---|
| no findings | 5 | 60 |
| only A2 | 5 | 50 |
| all traversal attempts blocked | 40 | 80 |
| a traversal attempt unresolved | 60 | 50 |
| exposure supported | 85 | 85 |

An A2 burst adds 15 to `risk_score`, capped at 100. Missing environment context (any documented field, or `response_markers`) subtracts 20 from `confidence`.
