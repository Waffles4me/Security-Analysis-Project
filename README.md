# API Incident Investigator

A small, local Python tool that analyzes **synthetic** API request/response sequences and produces an evidence-linked security assessment. It never connects to a real API, server or cloud account.

## The problem

An analyst reviewing API logs has to decide what actually happened, and an attack-looking request does not answer that. A path-traversal payload may have been blocked, and a `200` may have returned nothing sensitive. This tool reads each request together with its response and the declared API context, and separates four cases: an **attempt**, an attempt that was **blocked**, an outcome that is **unknown**, and an **exposure** the evidence supports.

## Definitions

- **Event**: one HTTP request together with its observed response (status, response marker, response size), identified by a unique `id` and a timezone-aware `timestamp`.
- **Suspicious API activity**: a request whose syntax or pattern departs from the route's documented purpose. Examples are path traversal (`../`, including bounded URL-encoded variants) and bursts of similar requests with path variations from one source. Suspicious syntax shows that an **attempt** happened, not that it succeeded.
- **Evidence**: explicit field values of real input events (status, `response_marker`, actor, path), read together with the declared environment. Every conclusion cites the event IDs it relies on.
- **Success (Project B)**: **exposure of the protected resource**. `successful` is:
  - `true` only when the `2xx` response to a traversal attempt carries a marker declared as `protected_content`, and the environment defines `protected_resource`,
  - `false` only when the response shows blocking (e.g. `403` with a `denial` marker),
  - `null` otherwise, including HTTP `200` with a generic, missing or undeclared marker, and a response whose status and marker contradict each other.
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
- **Conflict:** when the status and the marker contradict each other, the outcome is `null`, not `false`. Two combinations count: `401`/`403` with a marker declared `protected_content`, and `2xx` with a marker declared `denial`. The finding's `details.conflict` records the status, the marker and its semantics, the summary says the response is contradictory, and `missing_context` states that what was actually returned is unclear. A `401`/`403` with a `denial`, `generic`, undeclared or missing marker is still blocked, and so is a `denial` marker on any other non-`2xx` status.
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

Looks at `2xx` responses. Non-`2xx` responses produce no A3 finding. Each finding records `flagged_by_a1` in its details, so the two kinds below can be told apart.

**Event flagged by A1** (a traversal attempt): every `2xx` response gets a finding.

| Response marker | `successful` |
|---|---|
| declared `protected_content`, and `protected_resource` is defined | `true` |
| declared `protected_content`, but `protected_resource` is missing | `null` |
| declared `generic` | `null` |
| missing, or not declared in `response_markers` | `null` |
| declared `expected` or `denial` (contradicts the `2xx`) | `null` |

**Event not flagged by A1** (including events that are only part of an A2 burst): a finding is produced only when the marker is declared `protected_content`. Its `successful` is always `null`, never `true`. The log shows that protected content was returned; it does not show that the actor was not entitled to it. `missing_context` names the `actor_id` (or says it is unknown) and states that entitlement is not established. If `protected_resource` is missing, that is noted as well. Any other marker on an unflagged request produces no finding.

### Decision table

`assess()` combines the findings in this order:

| # | Condition | `classification` | `successful` |
|---|---|---|---|
| 1 | any A3 finding is `true` | `malicious` | `true` |
| 2 | any traversal attempt is unresolved | `suspicious` | `null` |
| 3 | protected content returned to a request A1 did not flag | `suspicious` | `null` |
| 4 | every traversal attempt was blocked | `suspicious` | `false` |
| 5 | only A2 findings | `suspicious` | `null` |
| 6 | no findings | `benign` | `null` |

- **What `malicious` means:** exposure of the protected resource is supported by a `protected_content` marker on the response to a traversal attempt. It does not claim who did it, why, or that the access was unauthorized (it may have been sanctioned testing). In row 1, `missing_context` always lists the intent and the authorization of the actor and source of each exposed event as not established, and `recommended_action` asks to confirm both server-side first.
- **Row 3 before row 4:** otherwise blocked traversal elsewhere in the log would report `false` while protected content went out on another request. When a higher row applies, the unflagged response is still named in `reason`, `missing_context` and `recommended_action`.
- **Override:** if there are findings but `protected_resource` or `response_markers` is missing, the classification becomes `insufficient_data`. Row 1 is never overridden.
- **Contradictory responses:** an A1 conflict (`403` with a `protected_content` marker, `200` with a `denial` marker) counts as unresolved, not blocked, and is named separately in `reason`.
- **A2:** never sets `successful` and never makes the result `malicious`.
- **Evidence:** `evidence_event_ids` is every event cited by a finding, in timeline order. In row 6 it is every event reviewed.

### Risk and confidence values

| Case | `risk_score` | `confidence` |
|---|---|---|
| no findings | 5 | 60 |
| only A2 | 5 | 50 |
| all traversal attempts blocked | 40 | 80 |
| protected content returned to a request A1 did not flag | 50 | 50 |
| a traversal attempt unresolved | 60 | 50 |
| exposure supported | 85 | 85 |

An A2 burst adds 15 to `risk_score`, capped at 100. The "only A2" case always has a burst, so its reported `risk_score` is 20. Missing environment context (any documented field, or `response_markers`) subtracts 20 from `confidence`.

## Limitations and false positives

### Limitations

- **No authorization check.** The tool does not compare `actor_id` with `expected_access` or `auth_model`, so it cannot tell entitled access from improper access.
- **Marker declarations are trusted.** The tool never sees a response body; a wrong entry in `response_markers` gives a wrong conclusion.
- **`benign` means no rule matched,** not that nothing happened. A request for another user's file with no `..` and a `generic` or undeclared marker is not examined.
- **A1 reads only `path` and `query`.** `request_body` is validated but never inspected.
- **A1 misses some traversal forms:** `..;/`, `..%00`, overlong UTF-8 such as `%c0%ae`, `....//`, and payloads encoded more than twice.
- **"Blocked" can rest on one signal.** A `401`/`403` with no marker, or a `denial` marker on a `404`, `5xx` or missing status, is reported as `false`.
- **A3 reads only `2xx` responses.** A `protected_content` marker on a `3xx` or other non-`2xx` response is not treated as exposure, and on an unflagged request it produces no finding at all.
- **A2 is one fixed window per `source_ip`.** Probing slower than 3 requests in 60 seconds, or spread across several addresses, is not detected. Events without a `source_ip` are left out.
- **Unused fields.** No rule uses `method`, `response_size` or `request_body`.
- **One verdict per file.** The assessment reports the highest matching row of the decision table; per-event outcomes are in `reason` and in `--findings`.
- **`evidence_event_ids` is broad.** In the `malicious` case it lists every event cited by any finding, not only the ones that support exposure.
- **`risk_score` and `confidence` are fixed heuristics,** not calibrated probabilities.
- **Synthetic input only.** The rules were written and tested against small hand-made scenarios, not real traffic.

### False positives

Benign activity the rules can flag, and why the tool does not over-conclude from it:

- **A legitimate `..` segment** in a path or query value (for example a parameter whose valid value is `..`). A1 reports an attempt only and never returns `true`; exposure still needs a `protected_content` marker.
- **An authorized scanner or test client** triggering A2. A2 never sets `successful`, never makes the result `malicious`, and always puts the authorized-scanner question in `missing_context`.
- **Several users behind one IP** (NAT, proxy) triggering A2. Bursts are grouped by `source_ip` only; the finding's `details.actor_ids` lists the distinct actors so a reader can see this. The result stays `suspicious` / `null`.
- **One user opening three different files within a minute** triggers A2 in the same way, with the same `suspicious` / `null` result and a `risk_score` of 20.
- **An entitled actor reading protected content** through a normal request gives `suspicious` / `null` (row 3), with entitlement listed as not established.
- **Sanctioned testing that does return protected content** is still classified `malicious`, because the classification reflects exposure and not intent. Intent and authorization are always listed in `missing_context` for that case.
