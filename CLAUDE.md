# Project B - API Incident Investigator

## Purpose of this document

This file is an implementation brief for an AI coding agent such as Claude or Codex. It consolidates the requirements in the source PDF for **Project B - API Incident Investigator**, including the shared project rules that also apply to Project B.

The intended implementation is a **small, local, evidence-driven Python security-analysis tool**. It does not connect to a real API, server, cluster, cloud account, or production environment. It analyzes synthetic request/response event data and produces an explainable security assessment grounded in explicit evidence.

## Repository

- GitHub: https://github.com/Waffles4me/Security-Analysis-Project
- Default branch: `main`
- Commit policy: work is committed and pushed **only when the repository owner explicitly asks** (typically at the end of a session/step). Do not commit or push on your own initiative.

---

## 1. Problem the project is intended to solve

Security analysts frequently need to review a sequence of API requests and responses and decide what actually happened.

The central problem is that suspicious request syntax alone does **not** prove exploitation. For example:

- A path-traversal payload may have been attempted but blocked.
- A `403` response may support the conclusion that the specific request was denied.
- A `200` response does **not** by itself prove that protected information was exposed.
- A response may be too generic to determine whether an attack succeeded.
- The same sequence may have a different meaning depending on the authenticated identity, expected permissions, route purpose, deployment, and protected resource.

The program must therefore analyze request/response sequences together with API context and distinguish between:

1. a suspicious **attempt**,
2. an attempt that appears to have been **blocked**,
3. an outcome that is **unknown / insufficiently supported**, and
4. a case where the available evidence supports **successful exposure**.

The system must not infer that an API is vulnerable merely because an attack-like payload appears in a request.

---

## 2. Project goals

The tool should:

- Accept a description of the API environment and a chronological or sortable sequence of HTTP request/response events.
- Parse and validate the input.
- Sort events by timestamp when necessary and present/analyze them as a timeline.
- Detect suspicious API-access patterns using deterministic rules.
- Correlate suspicious requests with the corresponding responses and environmental context.
- Distinguish **attempt**, **blocked attempt**, **possible exposure**, and **insufficient evidence**.
- Produce a structured JSON assessment.
- Link every finding to concrete existing event IDs.
- Preserve uncertainty rather than inventing missing facts.
- Produce at least one written investigation report based on the generated output.
- Be understandable and runnable by another person from the repository README.

The portfolio-level description, after the project is actually completed, may be summarized as:

> Built a Python tool to analyze API request-response sequences, detect suspicious access patterns, and document evidence-based incident assessments.

Do not use that statement before the implementation actually supports it.

---

## 3. Core rules and reasoning constraints

### 3.1 Shared evidence rules

These rules apply throughout the project:

- Input data is **local and synthetic**.
- No real cluster, API server, cloud service, production system, or API credentials are required.
- Every conclusion must point to supporting event evidence.
- Missing facts must remain `unknown`, `null`, or otherwise explicitly unresolved.
- Do **not** invent success, identity, authorization state, intent, or attack outcome.
- Rules produce the baseline findings.
- Claude/Codex may help implement the code or phrase explanations, but the final assessment must be checked against the events.
- The runtime product does **not** need an LLM.
- Demonstration data must not be presented as real production incidents.

### 3.2 Meaning of `successful`

The output field `successful` is specifically evidence-based:

- `true` only when the evidence supports success for the defined incident objective.
- `false` when evidence supports failure/blocking for that objective.
- `null` when the result cannot be determined from available evidence.

For Project B, the success objective may be something such as **exposure of a protected resource**. Therefore, a request returning `200` is not automatically successful unless the response contains reliable evidence of the protected content or another trustworthy success indicator.

### 3.3 Classification output

The common assessment format is:

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

Notes:

- `risk_score` and `confidence` are reasoned lab assessments, **not calibrated statistical probabilities**.
- `evidence_event_ids` must contain IDs of real input events only.
- `missing_context` should explicitly state what information prevents a stronger conclusion.

---

## 4. Required input model

The input should include two top-level concepts: `environment` and `events`.

### 4.1 Environment fields

Recommended/required environment context from the PDF:

```text
service
route_purpose
protected_resource
expected_access
auth_model
deployment
```

Interpretation:

- `service` - API/service being analyzed.
- `route_purpose` - intended meaning or use of the route/API endpoint.
- `protected_resource` - resource whose improper exposure is relevant to the investigation.
- `expected_access` - authorization expectation, for example `owner only`.
- `auth_model` - authentication/authorization model or expected identity model.
- `deployment` - environment such as staging or production-like lab context.

### 4.2 Event fields

Each HTTP event may contain:

```text
id
timestamp
actor_id            # may be null
source_ip
method
path
query                # filtered/sanitized if needed
request_body
status
response_marker
response_size
```

Important privacy rule:

- When response content may contain sensitive information, store a **summary marker** in `response_marker` instead of retaining the complete response body.

### 4.3 Example input shape

```json
{
  "environment": {
    "service": "document-api",
    "deployment": "staging",
    "protected_resource": "account files",
    "expected_access": "owner only"
  },
  "events": [
    {
      "id": "a1",
      "timestamp": "2026-09-19T10:00:00Z",
      "actor_id": "user-7",
      "source_ip": "192.0.2.10",
      "method": "GET",
      "path": "/api/files/../../private/report",
      "status": 403,
      "response_marker": "access_denied",
      "response_size": 87
    }
  ]
}
```

### 4.4 Input ordering

The tool should accept either:

- events already sorted chronologically, or
- events that the program sorts by `timestamp` before analysis.

The displayed/analyzed sequence should be a timeline.

---

## 5. MVP detection rules

Implement the rules incrementally, one at a time.

### A1 - Traversal attempt

**Condition**

Detect a path or parameter containing path-traversal indicators after **limited, controlled decoding**.

Examples of relevant indicators may include directory traversal syntax such as `../`, including controlled encoded variants if implemented safely.

**Conclusion boundary**

- This establishes a **suspicious request / traversal attempt**.
- A `403` status supports the conclusion that that specific request was blocked.
- The presence of the payload alone does not prove the API is vulnerable.

### A2 - Repeated probing

**Condition**

Detect several similar requests from the same source within a short time window, with path variations.

**Conclusion boundary**

- This can indicate probing or scanning.
- It may also be an authorized scanner.
- Environmental/contextual information is therefore required before treating it as malicious activity.

### A3 - Possible exposure

**Condition**

A suspicious request receives a response containing a **unique marker associated with the protected resource**.

**Conclusion boundary**

- Only a reliable/meaningful response marker supports exposure.
- HTTP `200` alone does **not** prove exposure.
- A generic marker with `200` may still require `successful: null`.
- A unique protected-content marker may support `successful: true` for exposure of that content.

---

## 6. Required demonstration scenarios

The repository must include three synthetic API scenarios.

### `scenarios/benign.json`

Normal activity.

Expected concept:

- The account owner requests their own file.
- Response status is `200`.
- Response contains the expected marker.
- Should not trigger a simple false positive.

### `scenarios/suspicious.json`

Suspicious but blocked / not proven successful.

Expected concept:

- Traversal attempt toward a private path.
- Response status `403`.
- `response_marker` indicates access denied.
- The attempt exists.
- `successful` should be `false` for that request because blocking is supported by evidence.

### `scenarios/strong_evidence.json`

A scenario designed to demonstrate the difference between ambiguous and stronger evidence.

Expected concept:

- Suspicious request receives `200`.
- If the response marker is generic, success remains unresolved (`successful: null`).
- If the marker uniquely indicates the protected resource/content, the evidence may support `successful: true` for exposure of that content.

The implementation should make this distinction visible and explainable.

---

## 7. Recommended repository architecture

Use the following repository layout unless there is a strong implementation reason to adjust it:

```text
README.md
src/
  cli.py
  models.py
  rules.py
scenarios/
  benign.json
  suspicious.json
  strong_evidence.json
tests/
  test_rules.py
investigations/
  case-01.md
examples/
  output.json
```

### Suggested responsibility of each file

#### `src/models.py`

- Input schema/data models.
- Environment model.
- Event model.
- Output/assessment model if appropriate.
- Field-level validation.
- Timestamp parsing.
- Missing-value handling.

#### `src/rules.py`

- Deterministic rule implementation.
- One function/class per detection rule when practical.
- Evidence correlation.
- Rule results must reference existing event IDs.
- Logic that distinguishes attempt, blocked activity, unknown outcome, and supported exposure.

#### `src/cli.py`

- Load a JSON scenario/input file.
- Validate the schema.
- Sort events chronologically.
- Run rules.
- Produce/display the timeline.
- Emit the final JSON assessment.
- Return useful errors for invalid input.

#### `tests/test_rules.py`

- Unit tests for all MVP rules.
- Positive and negative cases.
- Missing-data cases.
- Evidence-change tests.
- False-positive protection.

#### `investigations/case-01.md`

A human-readable investigation report based on actual generated output. It should explain:

- observed activity,
- evidence,
- classification,
- success determination,
- missing context,
- limitations,
- recommended next investigative action.

#### `examples/output.json`

Representative valid output matching the documented result schema.

---

## 8. Recommended flow of work for Claude or Codex

The source document explicitly recommends small, reviewable tasks rather than asking the AI agent to implement everything at once.

### Step 1 - Define the problem before coding

Write short definitions in the README for:

- what an event is,
- what constitutes suspicious API activity,
- what counts as evidence,
- what constitutes success for Project B,
- what remains unknown when evidence is incomplete.

**Gate before continuing:**

The definitions must be concise, internally consistent, and match the example scenarios.

### Step 2 - Build input schema and scenarios

Create the three synthetic JSON scenario files.

Then implement or design:

- schema/models,
- parser,
- timestamp handling,
- missing-data representation.

**Gate before continuing:**

- Every field is defined.
- Timestamps validate correctly.
- At least one missing-information case is represented/documented.
- Input can be loaded and shown as a timeline.

### Step 3 - Implement rules incrementally

Add **one rule at a time**.

For each rule:

1. implement the rule,
2. add/update tests,
3. inspect the rule's evidence IDs,
4. verify it distinguishes attempt/suspicion/success appropriately,
5. inspect edge cases before implementing the next rule.

Use Claude/Codex to explain code and identify edge cases, but do not blindly accept generated changes.

**Gate before continuing:**

- Returned event IDs exist in the input.
- The rule does not overclaim success.
- The rule preserves uncertainty where required.

### Step 4 - Test and run

Run tests for:

- normal/benign activity,
- suspicious activity,
- strong evidence,
- missing input/context.

Then intentionally change evidence in a scenario and verify that the result changes predictably.

**Gate before continuing:**

No invented information. Evidence changes produce logically expected output changes.

### Step 5 - Investigation and publication

- Generate/inspect final output.
- Write the investigation report from the actual output.
- Complete the README.
- Perform a code review.
- Re-run the whole project from the documented commands.

**Final gate:**

A person who did not write the project should be able to run it and understand the conclusion. The author should be able to explain every major rule, result, limitation, and evidence boundary.

### AI-agent working style

When using Claude/Codex:

- Give it small tasks.
- Show it an input example and expected result.
- Review generated diffs/changes.
- Run tests yourself after each meaningful change.
- Do not make an LLM dependency part of the runtime product unless intentionally extending beyond the MVP.

---

## 9. Input verification requirements

Input verification must happen before the analysis rules are trusted.

At minimum verify:

### Structure

- Root JSON is valid.
- `environment` exists and has documented fields or explicitly allowed missing values.
- `events` exists and is an array/list.

### Event identity

- Every event has an `id`.
- IDs should be unique.
- Findings may only reference IDs that actually exist.

### Timestamp verification

- Every required timestamp is parseable.
- Events can be sorted chronologically.
- Invalid timestamps should produce a clear validation failure rather than silent mis-ordering.

### HTTP/event field validation

Validate or safely handle:

- `method`
- `path`
- filtered `query`
- `request_body`
- `status`
- `response_marker`
- `response_size`
- `actor_id`
- `source_ip`

Do not treat absence of an optional field as evidence for a fact.

### Controlled decoding

For traversal detection, decoding must be **limited and controlled**. The implementation should not repeatedly/unboundedly decode input in a way that changes semantics unpredictably.

### Missing context

A missing-data case must be supported and documented. Missing information should flow through to the assessment rather than being silently replaced with assumptions.

### Privacy

Do not require full sensitive response bodies if a summary/semantic `response_marker` is sufficient for the investigation.

---

## 10. Output verification requirements

Every generated assessment should be verified against the following constraints.

### Schema correctness

Output should include the common assessment fields:

```text
classification
risk_score
confidence
successful
evidence_event_ids
reason
missing_context
recommended_action
```

### Classification values

`classification` must be one of:

```text
benign
suspicious
malicious
insufficient_data
```

### Evidence integrity

- Every ID in `evidence_event_ids` must exist in the loaded input.
- The stated reason must be supportable from those events and the declared environment.
- The tool must not cite nonexistent events.

### Success integrity

- `successful: true` requires actual success evidence for the defined target.
- `successful: false` requires evidence of blocking/failure.
- `successful: null` is required when outcome is unresolved.
- `200` alone cannot set successful exposure to `true`.

### Missing-context integrity

If the tool cannot determine success or classification strongly enough, it should state what information is missing in `missing_context`.

### Risk/confidence interpretation

`risk_score` and `confidence` must be explainable heuristic/lab values. Do not describe them as statistically calibrated probabilities unless calibration is separately implemented and validated.

---

## 11. Testing and acceptance requirements

### Required test command

The repository should support:

```bash
python -m unittest discover -s tests
```

The command must pass.

### README execution test

The run command documented in `README.md` must work against all three example scenario files.

### Scenario coverage

Tests must cover:

- benign activity,
- suspicious activity,
- strong evidence,
- missing data/context.

### Evidence mutation test

At least one test should modify a single relevant event/evidence item and verify that the assessment changes predictably.

Examples:

- change `403` + `access_denied` to another response and verify blocking is no longer asserted,
- replace a unique protected-content marker with a generic marker and verify `successful` changes from `true` to `null`,
- remove necessary context and verify missing context is surfaced.

### False-positive protection

The repository must include a legitimate/benign scenario that prevents a simplistic rule such as "any file access" or "any unusual path" from being automatically classified as malicious.

### No unsupported assertions

Tests should explicitly protect against claims that are not justified by input evidence.

---

## 12. Investigation-report requirements

At least one investigation report should be included under `investigations/`.

The report should be derived from the program output rather than manually contradicting it.

It should make clear:

- what request/payload was observed,
- what response occurred,
- the meaning of the HTTP status,
- the meaning/reliability of the response marker,
- which event IDs support the conclusion,
- whether exposure was successful, blocked, or unknown,
- what context is missing,
- what the next investigation step should be,
- what limitations or false-positive possibilities remain.

A reviewer/interviewer should be able to ask why a `200` did or did not prove exposure, and the author should be able to answer using the code and evidence model.

---

## 13. README requirements

The README should make the project independently runnable and explainable.

At minimum document:

- project purpose,
- threat/problem being modeled,
- input schema,
- event fields,
- environment fields,
- output schema,
- meaning of `successful`,
- MVP rules A1/A2/A3,
- the three example scenarios,
- setup/run command,
- test command,
- important limitations,
- false-positive considerations,
- why HTTP `200` does not automatically prove data exposure.

---

## 14. Scope boundaries

### In scope for MVP

- Python implementation.
- CLI.
- Local synthetic JSON inputs.
- Three deterministic detection rules.
- Three demonstration scenarios.
- Evidence-linked JSON output.
- Automated tests.
- README.
- One investigation report.

### Explicitly not required for MVP

- Connection to a live API.
- Real production data.
- Cloud credentials.
- API keys.
- Live cluster/server integration.
- LLM inference at product runtime.
- Full attack-detection platform or SIEM integration.

### Optional extension

The source document suggests **API authorization context** as an optional extension for Project B after the MVP is stable.

Any extension must be tested and must not break the MVP.

---

## 15. Suggested implementation principles for the coding agent

These points follow directly from the project requirements and should guide implementation decisions:

1. **Evidence first.** Detection output should be reproducible from explicit fields and event IDs.
2. **Separate detection from conclusion.** A traversal payload proves an attempt, not successful exploitation.
3. **Make uncertainty first-class.** `null` is a valid and required result when evidence is insufficient.
4. **Context matters.** Identity, authorization expectations, route meaning, protected resource, and deployment can change the interpretation of the same HTTP request.
5. **Responses matter as much as requests.** Project B is about request-response correlation, not payload matching alone.
6. **Markers must have semantics.** A response marker should be documented as generic, denial-related, expected, or uniquely tied to protected content.
7. **Do not overfit the three scenarios.** Rules should be reusable and testable, while remaining within the intentionally small MVP scope.
8. **Keep the code explainable.** This is a portfolio/interview project; simple transparent rules are preferable to opaque complexity.

---

## 16. Definition of done

Project B can be considered complete when all of the following are true:

- The repository has the recommended core structure.
- The CLI loads and validates input.
- Events are sorted/displayed as a timeline.
- A1, A2, and A3 are implemented.
- All three required scenarios exist and run.
- The output follows the required assessment schema.
- Every alert/finding references real event IDs.
- Missing information results in `successful: null` when appropriate and explains the missing context.
- The benign scenario avoids a simple false positive.
- `python -m unittest discover -s tests` passes.
- The README run instructions work on all three example files.
- One investigation report is included.
- Changing a relevant piece of evidence changes the result predictably.
- Another person can run the project and understand the conclusion.
- The author can explain the rules, scenarios, tests, false-positive risks, and why `200` alone is not proof of exposure.

---

## 17. Primary reference topics

The source PDF points to these subjects for further reading:

- OWASP API Security
- Python `unittest`

MITRE ATT&CK T1059 is also listed in the document, but it is more directly relevant to the process/command-investigation project than to the core API Incident Investigator MVP.

---

## 18. Current progress

Last updated: 2026-10-07. Update this section when a step from section 8 is completed.

### Workflow status (section 8)

| Step | Status |
|---|---|
| 1. Define the problem | Done. Definitions are in `README.md`. |
| 2. Input schema and scenarios | Done. `src/models.py`, three scenario files, timeline in the CLI. |
| 3. Rules, one at a time | Done. A1, A2 and A3 are in `src/rules.py`, combined by `assess()` using the decision table written above it. |
| 4. Test and run | Done. `python -m unittest discover -s tests` passes (84 tests), including evidence-mutation tests. |
| 5. Investigation and publication | In progress. See below. |

### Done in step 5

- `examples/output.json` generated from `scenarios/strong_evidence.json`.
- README documents the rules, A2 parameters, decision table, risk/confidence values and CLI flags.
- Rules reviewed against sections 3, 5, 10 and 11.

### Still to do

- `investigations/case-01.md`: not written. The repository owner writes it from the actual tool output.
- README has no limitations / false-positive section yet (required by section 13).
- Final code review and a clean re-run from the README commands.

### Known evidence gaps found in review (not fixed)

1. A `protected_content` marker on a request that A1 did not flag (e.g. a non-traversal request for another user's file) produces no finding, so the result is `benign`.
2. A `403` with a `protected_content` marker is reported as blocked (`successful: false`) although the evidence conflicts.
3. `malicious` is assigned from a response marker alone; intent and authorization are not established, and `missing_context` can be empty in that case.
4. A3 does not compare `actor_id` with `expected_access` / `auth_model` (the optional authorization-context extension in section 14).
5. In the malicious case `evidence_event_ids` lists every cited event, not only the ones that support exposure.
6. A1 does not inspect `request_body` and does not match `..;/`.

### Current results

| Scenario | classification | successful | risk_score | confidence |
|---|---|---|---|---|
| `benign.json` | benign | null | 5 | 60 |
| `suspicious.json` | suspicious | false | 55 | 80 |
| `strong_evidence.json` | malicious | true | 100 | 85 |
