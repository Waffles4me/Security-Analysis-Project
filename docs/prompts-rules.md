# Build prompts: rules A1, A2, A3

These are step-by-step prompts for an AI coding agent (Claude or Codex). Send them **one at a time, in order**. After each one:

- review the diff,
- run `python -m unittest discover -s tests` yourself,
- run the CLI on all three scenarios.

Only move on when the step's "Done when" list holds.

---

## Prompt 0: Session preamble (send once at the start)

```
Read CLAUDE.md fully. We are implementing detection rules A1, A2, A3 one at a
time in small steps. Current state: src/models.py (Environment, Event,
Scenario, Assessment with validation), src/rules.py (placeholder assess()),
src/cli.py, three scenarios, tests/test_models.py, and skipped placeholders in
tests/test_rules.py.

Standing constraints for every step:
- Standard library only. No LLM at runtime.
- Findings may only cite event IDs that exist in the loaded scenario.
- successful=True only with a response marker declared "protected_content";
  successful=False only with blocking evidence; otherwise None.
- HTTP 200 alone never sets successful=True.
- Missing facts stay None and are surfaced in missing_context, never assumed.
- Do not edit scenario files unless the step says so.
- Do only the step I give you, then stop and summarize the diff.
Reply "ready" and wait for the first step.
```

---

## Rule A1: Traversal attempt

### Prompt A1.1: Finding model and controlled decoding

```
Step A1.1. Do not implement any rule yet.

1. In src/models.py add a frozen dataclass Finding:
   rule_id: str            # "A1" | "A2" | "A3"
   event_ids: tuple[str, ...]
   summary: str            # one sentence, factual
   successful: Optional[bool]   # outcome for the exposure objective
   details: dict           # rule-specific facts (matched values etc.)
   missing_context: tuple[str, ...] = ()
   Add a validate(known_event_ids) method that rejects empty event_ids,
   unknown IDs, and successful not in (True, False, None).

2. In src/rules.py add normalize_for_traversal(value: str) -> list[str]:
   - Return the distinct forms checked: [raw, decoded_once, decoded_twice].
   - Use urllib.parse.unquote at most TWICE. Never loop until stable.
   - In each form, replace "\" with "/".
3. Add has_traversal(value: str) -> bool. It is true if any form contains
   ".." as a whole path segment: the segment between separators ("/", "?",
   "&", "=", start, end) is exactly "..".

Tests (tests/test_rules.py, new class DecodingTest):
- "/api/files/../../private/report" -> True
- "/api/files/%2e%2e/%2e%2e/private" -> True
- "name=..%2F..%2Fprivate%2Freport" -> True
- "%252e%252e%252f" (double-encoded) -> True
- "%25252e%25252e%25252f" (triple-encoded) -> False, and
  normalize_for_traversal returns exactly 3 forms (bounded decoding)
- "/api/files/user-7/report..final.txt" -> False
- "/api/files/user-7/notes.txt" -> False
- "..\\..\\private" -> True
Do not remove the existing skipped placeholders yet.
```

**Done when:** all tests pass, decoding is clearly bounded at 2, and `report..final.txt` does not match.

### Prompt A1.2: The A1 rule

```
Step A1.2. Implement rule A1 in src/rules.py as rule_a1_traversal(scenario)
-> list[Finding]. Emit one Finding per event whose path OR query has
traversal (use has_traversal).

Outcome for each finding (the "successful" field):
- False (blocked) if status is 401 or 403, or the marker's declared
  semantics is "denial". Record which signal was used in details["blocked_by"].
  A 403 with a null marker counts as blocked by status alone. Note in
  missing_context that the response marker is missing.
- None (unresolved) in every other case, including 2xx, 3xx, 404, 5xx,
  and status null. A1 never returns True; exposure is A3's job.
details must include: "field" ("path" or "query"), "raw", "decoded"
(the form that matched), "status", "marker", "marker_semantics".
summary example: "Traversal attempt in path; request blocked (403)."

Replace the skipped A1 placeholder class with real tests:
- suspicious.json: findings for s1, s2, s3. All successful=False.
  s3 has the "response marker missing" missing_context.
- strong_evidence.json: e1 False, e2 None, e3 None (A1 alone).
- benign.json: zero findings (false-positive protection, b2).
- Mutation: copy suspicious.json, change s1 to status 200 + marker "ok",
  and assert s1's finding becomes successful=None.
- Every finding validates against scenario.event_ids.
```

**Done when:** A1 never outputs `True`, the benign scenario has no findings, and the mutation test passes.

### Prompt A1.3: Wire A1 into the assessment and CLI

```
Step A1.3. Update assess(scenario) in src/rules.py to use A1 findings. Also
return the findings list: assess returns (Assessment, list[Finding]).
Update cli.py and the existing tests that call assess.

Aggregation for now (A2/A3 come later; keep it simple and explainable):
- No findings -> classification "benign", successful None,
  evidence_event_ids = all event IDs reviewed, reason says no rule matched,
  risk 5, confidence based on whether environment context is complete.
- Findings, all blocked -> "suspicious", successful False,
  evidence = the A1 event IDs, risk 40.
- Findings, any unresolved -> "suspicious", successful None, risk 60,
  missing_context includes "response content for <ids> cannot be confirmed".
- Always append environment.missing_fields() to missing_context.
- Remove the "rules not implemented" text. Keep a note that A2/A3 are pending.
Document the risk/confidence numbers as heuristics in a comment.

CLI: print a "Findings" section (rule, event IDs, successful, summary)
between the timeline and the JSON. Add a --findings flag that includes
findings in the JSON output under a separate "findings" key. The default
JSON must stay exactly the 8-field assessment schema.

Update PlaceholderAssessTest to match: benign -> "benign",
suspicious -> "suspicious"/False, strong_evidence -> "suspicious"/None.
```

**Done when:** the CLI runs on all 3 scenarios, the default JSON has exactly the 8 schema keys, and every cited ID exists.

### Prompt A1.4: A1 review (no code changes)

```
Step A1.4. Review only, do not change code. List edge cases for A1 and say
for each whether the current code handles it correctly:
- traversal in request_body
- mixed case "%2E%2e"
- "..;/" and "%c0%ae" (overlong UTF-8)
- path "/.." at the end
- 401 vs 403 vs 404 meaning
- 302 redirect after traversal
Recommend which (if any) are worth fixing within MVP scope, and why.
```

---

## Rule A2: Repeated probing

### Prompt A2.1: The A2 rule

```
Step A2.1. Implement rule_a2_probing(scenario, window_seconds=60,
min_requests=3) -> list[Finding] in src/rules.py.

Definition:
- Group events by source_ip. Events with source_ip null are excluded, and
  this is noted in missing_context if any exist.
- A probing burst is >= min_requests events from one source within
  window_seconds of the first event in the burst, with >= 2 DISTINCT
  normalized paths (path + query). Repeating the identical URL is a retry,
  not probing.
- Use a sliding window over the sorted timeline. Emit one Finding per burst.
  Bursts from the same source must not overlap: after emitting, continue
  after the burst's last event.
- successful is always None. Probing says nothing about exposure.
- details: source_ip, actor_ids (list, None preserved), first/last
  timestamp, duration_seconds, distinct_paths, count, how many are also A1.
- missing_context always includes "whether <ip> is an authorized scanner
  or test client".

Replace the skipped A2 placeholders with tests:
- suspicious.json -> one burst [s1, s2, s3] from 192.0.2.10.
- strong_evidence.json -> one burst [e1, e2, e3].
- benign.json -> no burst (only 2 events, > 60 s apart).
- 3 identical URLs within 10 s -> no finding.
- 3 distinct paths spread over 5 minutes -> no finding.
- Same 3 events but different source IPs -> no finding.
- The window boundary is inclusive at exactly 60 s. Test it.
```

**Done when:** the A2 tests pass and the A1 tests are unchanged.

### Prompt A2.2: Wire A2 into the assessment

```
Step A2.2. Add A2 to assess().
- A2 raises risk_score by a documented amount (e.g. +15, capped at 100).
- A2 never sets successful and never by itself makes the classification
  "malicious".
- A2 alone (no A1) -> "suspicious", successful None, with the
  authorized-scanner question in missing_context.
- evidence_event_ids is the union of A1 and A2 IDs, de-duplicated, in
  timeline order.
- The reason mentions probing only when A2 fired.
Add a test that builds a scenario with 3 non-traversal distinct paths in
20 s from one IP. Expect "suspicious", successful None, and A2 IDs cited.
```

---

## Rule A3: Possible exposure

### Prompt A3.1: The A3 rule

```
Step A3.1. Implement rule_a3_exposure(scenario, suspicious_ids: set[str])
-> list[Finding]. suspicious_ids = event IDs flagged by A1. A2-only
events are NOT suspicious enough on their own for A3.

For each suspicious event with a 2xx status:
- marker semantics "protected_content" -> successful True,
  summary "Response carries protected-content marker <m>; exposure supported."
- semantics "generic" -> successful None, missing_context
  "marker '<m>' is generic; response content unknown"
- marker null -> None, "no response marker recorded"
- marker not declared in environment.response_markers -> None,
  "marker '<m>' has no declared semantics"
- semantics "expected" or "denial" on a 2xx -> None, explain the
  contradiction in missing_context.
Non-2xx statuses produce no A3 finding (A1 already covers them).
Also: if environment.protected_resource is None, no finding may be True.
Downgrade to None with missing_context "protected_resource not defined".

Replace the skipped A3 placeholders with tests:
- strong_evidence: e3 -> True, e2 -> None, e1 -> no A3 finding.
- suspicious: no A3 findings.
- benign: no A3 findings, even though b1/b2 are 200 (they are not
  suspicious).
- Mutation: e3 marker -> "ok" makes True become None.
- Mutation: e3 marker -> undeclared "foo" makes it None.
- Mutation: remove protected_resource makes e3 None.
- A protected_content marker on a NON-suspicious event -> no A3 finding.
```

**Done when:** `True` appears only for `e3` and every mutation test passes.

### Prompt A3.2: Final aggregation

```
Step A3.2. Finalize assess() with all three rules. Use this decision table,
in order:
1. Any A3 True -> "malicious", successful True, evidence = A3 True IDs plus
   the related A1/A2 IDs, high risk.
2. Any A1 finding unresolved (None) -> "suspicious", successful None,
   missing_context from A1/A3.
3. All A1 findings blocked -> "suspicious", successful False.
4. Only A2 -> "suspicious", successful None.
5. No findings -> "benign", successful None.
Override: if protected_resource or response_markers is missing AND there
are findings, set classification "insufficient_data" unless rule 1 already
applies (rule 1 cannot apply, because A3.1 forbids True without
protected_resource).
Write the table as a comment above assess(). Build the reason from the
findings, naming the event IDs and the deciding signal (e.g. "e3 returned
200 with marker private_report_content, declared protected_content").

Add end-to-end tests asserting the full 8-field output per scenario:
- benign -> benign / None
- suspicious -> suspicious / False
- strong_evidence -> malicious / True, evidence includes e3
- strong_evidence with e3 removed -> suspicious / None (e2 unresolved)
- Assert no output ever cites an ID missing from the input.
```

### Prompt A3.3: Final review and artifacts

```
Step A3.3.
1. Review all rules against CLAUDE.md sections 3, 5, 10 and 11. List any
   place where the code could claim more than the evidence supports.
2. Generate examples/output.json from:
   python -m src.cli scenarios/strong_evidence.json --json-only
3. Update README: replace "Rules (planned)" with the implemented rules, the
   A2 window parameters, the decision table, and remove the WIP status note.
Do not write investigations/case-01.md yet. I will write it from the output.
```
