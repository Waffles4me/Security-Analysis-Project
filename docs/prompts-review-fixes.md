# Review-fix prompts: from the final code review to publication

These prompts continue from `docs/prompts-finish.md`. That file's stages 1, 3 and 4 are done. What is left is the open findings from the V1 code review (listed in CLAUDE.md section 18) and the investigation report.

Send them **one at a time, in order**. After each one:

- review the diff,
- run `python -m unittest discover -s tests` yourself,
- run the CLI on all three scenarios.

Only move on when the step's "Done when" line holds. If you start a new agent session partway through, send Prompt 0 again first.

| Stage | Prompts | Who writes |
|---|---|---|
| Orientation | 0 | agent reads, changes nothing |
| 1. Fix the review findings | X1, X2, X3, X4 | agent |
| 1b. Optional fixes that change `suspicious.json` output | X5 | agent, only if you want them |
| 2. Investigation report | R1, R2 from `docs/prompts-finish.md` | **you** write `case-01.md` |
| 3. Final check and commit | V2 from `docs/prompts-finish.md`, then C1 | agent |

Write the report **after** stage 1 (and 1b if you send it), so it quotes the final output.

---

## Prompt 0: Initiation and orientation (send once per session)

```
You are joining a small Python project that is almost finished. Before I give
you any task, get oriented. Do not change any file in this step.

The project is "API Incident Investigator": a local, standard-library-only
tool that reads a synthetic JSON log of API requests and responses and decides
what the evidence supports. Its whole point is to never claim more than the
log shows: an attack-looking request proves only an attempt, and an HTTP 200
does not prove that protected data was returned. It is a portfolio project, so
the code must stay simple enough for me to explain every rule in an interview.

Read, in this order:
1. CLAUDE.md, fully. Section 18 is the current progress. It has a list
   "Open findings from the final code review"; those are what the next steps
   fix. Sections 3, 9, 10 and 11 are the evidence and validation rules you
   will be held to.
2. README.md, especially "Rules", the decision table and "Limitations and
   false positives".
3. src/models.py, src/rules.py, src/cli.py.
4. tests/test_models.py and tests/test_rules.py.
5. The three files in scenarios/.

Then run:
  python -m unittest discover -s tests
  python -m src.cli scenarios/benign.json
  python -m src.cli scenarios/suspicious.json
  python -m src.cli scenarios/strong_evidence.json --findings

Reply with a short orientation report:
- the test count and whether all pass (CLAUDE.md section 18 says 101; tell
  me if you see something else),
- the classification and "successful" value for each scenario,
- the six rows of the decision table in your own words,
- anything in the code that contradicts CLAUDE.md or the README.

Standing constraints for every later step:
- Standard library only. No LLM at runtime.
- Findings and assessments may only cite event IDs that exist in the input.
- successful=True needs a response marker declared "protected_content" on a
  2xx response to a request A1 flagged; successful=False needs blocking
  evidence; everything else is None.
- Missing facts stay None and are listed in missing_context. Never assume
  identity, authorization, intent or outcome.
- Invalid input ends in a ValidationError with a clear message (CLI exit
  code 2), never in a Python traceback and never in silent coercion.
- Do not edit the three scenario files. Build variants inside tests.
- The output for the three scenario files must stay exactly as it is unless
  a step says it may change. If your change alters it, stop and tell me.
- When a step changes behaviour that an existing test asserts, change that
  test on purpose and tell me which one and why. Do not work around it.
- Keep README.md true: if a step changes a rule, the decision table, the
  input rules or a limitation, update that part of the README in the same
  step. Remove a limitation from the README when a step fixes it.
- Do not commit or push. I will ask for that explicitly.
- Do only the step I give you, then stop and summarize the diff, list any
  choice you made that the step left open, and show the test result.

After the report, wait for the first step.
```

**Done when:** the report matches what you see when you run the same commands, and no file changed.

---

## Stage 1: Fix the review findings

### Prompt X1: Contradictory responses the conflict check misses

```
Step X1. Fix open review findings 1 and 3 from CLAUDE.md section 18.

Background: rule_a1_traversal records a "conflict" when a response's status
and marker contradict each other, and then reports successful=None. Today it
knows two conflicts: 401/403 with a marker declared "protected_content", and
2xx with a marker declared "denial". Two cases slip through.

Problem A (a false sentence in the output). Take strong_evidence.json reduced
to e3 and change e3's status to 404 (or 302, or 500). The marker is still
"private_report_content", declared "protected_content". The result is
"suspicious" / None, which is right, but the reason says: "The response
neither shows blocking nor carries a protected-content marker". It does carry
one. The same false sentence appears when e3's status is null.

Problem B (blocked on conflicting evidence). Take suspicious.json reduced to
s1 and change its marker to "own_file_content", declared "expected". Status
stays 403. The result is successful=False with confidence 80. A 403 that
carries content the requester is entitled to is contradictory, not blocked.

What I want:
- Extend the conflict check in rule_a1_traversal to:
    * 401/403 with a marker declared "protected_content" or "expected",
    * any other non-2xx status with a marker declared "protected_content",
    * 2xx with a marker declared "denial" (as today).
  A conflict gives successful=None, fills details["conflict"], and adds the
  existing "contradict each other; what was actually returned is unclear"
  note, exactly as the two existing conflicts do.
- A missing status with a "protected_content" marker is not a conflict (there
  is no status to contradict). It stays None. But assess() must not use the
  "nor carries a protected-content marker" sentence for it. Give that case
  wording that is true: the marker is present, no status was recorded.
- After this step, the sentence "The response neither shows blocking nor
  carries a protected-content marker" may only be printed for events whose
  marker is not declared "protected_content".
- Unchanged: 401/403 with a "denial", "generic", undeclared or missing marker
  is still False.

Tests:
- e3 alone with status 404, 302 and 500: A1 finding None with the conflict
  recorded; the reason contains "Contradictory response" and does not contain
  "nor carries a protected-content marker".
- e3 alone with status null: None; the reason does not contain "nor carries a
  protected-content marker".
- s1 alone with 403 + "own_file_content": A1 finding None, conflict recorded,
  assessment "suspicious" / None.
- The three scenario files give exactly the same output as before.
- No case in this step produces True.

Update the README: the "Conflict" bullet in the A1 section, and the
limitation "A3 reads only 2xx responses" if its wording is affected.
```

**Done when:** no input makes the tool say a protected-content marker is absent when it is present, and a 403 with an `expected` marker gives `successful: null`.

### Prompt X2: Missing response data and empty strings

```
Step X2. Fix open review findings 2 and 4 from CLAUDE.md section 18. Both are
cases where something missing is treated as if it were known.

Problem A (missing responses read as a clean result). Take benign.json and
set every event's status and response_marker to null. No rule matches, so the
result is "benign", confidence 60, missing_context [], and the recommended
action is "No action required based on these events." Nothing in the output
says that no response was recorded.

What I want for A, in the "no findings" branch of assess() only:
- List in missing_context each event that has no status, and each event that
  has a status but no response marker. Use the same "event X: ..." style as
  the other notes. One note per event is fine; do not merge them.
- If any such note was added, subtract a fixed amount from confidence. Reuse
  the existing 20-point penalty constant if it reads naturally, or add a
  named constant next to it. Apply the penalty once, not per event, and
  document it in the README risk/confidence section.
- If any such note was added, the recommended action must not say "No action
  required". It should ask for the missing response data for the named
  events.
- The classification stays "benign": it still means "no rule matched". The
  README limitation "benign means no rule matched" already says this.
- benign.json unchanged must give exactly the same output as before: every
  event there has a status and a marker.

Problem B (empty strings count as defined). Take strong_evidence.json and set
"protected_resource": "". The result is "malicious" / True, and the reason
says "tied to the protected resource ()". An empty actor_id likewise prints
"intent of actor  from source ...".

What I want for B, in src/models.py:
- Reject, with a ValidationError that names the field, an empty or
  whitespace-only string in: every environment field in ENVIRONMENT_FIELDS,
  every key of response_markers, and the event fields actor_id and
  response_marker. The caller must write null (or omit the field) to say
  "unknown".
- Do not reject an empty "query" or "request_body": an empty query string is
  a real request.
- This follows the rule at the top of models.py: invalid input fails loudly
  and is never silently coerced.

Tests:
- A: benign.json with all statuses and markers null: "benign", confidence
  lower than 60, one note per event in missing_context, and the action does
  not contain "No action required".
- A: benign.json with one event's marker null and its status kept: one note,
  for that event only.
- A: benign.json unchanged: the existing exact-match test still passes
  without edits.
- B: one test per rejected field with "" and with "   ", and one test that
  query "" and request_body "" are still accepted.
- B: strong_evidence.json with "protected_resource": "" raises
  ValidationError instead of returning True.

Update the README: the "Input schema" section (say that empty strings are
rejected and null means unknown) and the risk/confidence section.
```

**Done when:** a log with no recorded responses no longer says "No action required" with an empty `missing_context`, and `""` can never stand in for a defined value.

### Prompt X3: Input validation that crashes or passes silently

```
Step X3. Fix open review findings 6 and 7 from CLAUDE.md section 18. Change
src/models.py and tests only; no rule changes.

CLAUDE.md section 9 requires a clear validation failure for invalid input.
These inputs break that today. Reproduce each one first, then fix it.

1. "response_markers": {"ok": ["generic"]} raises a TypeError traceback,
   because the list is tested for membership in a set. Want: a
   ValidationError saying the marker's semantics must be one of the allowed
   strings.
2. "response_markers" set to [], 0, "" or false is accepted and treated as
   "no markers", because of the "or {}" fallback. Want: only a missing key or
   null means "not provided"; any other non-object value is a
   ValidationError.
3. A scenario file that is not valid UTF-8 raises a UnicodeDecodeError
   traceback from Scenario.load. Want: a ValidationError naming the file,
   so the CLI prints "error: ..." and exits with code 2.
4. A UTF-8 file that starts with a byte-order mark is rejected as invalid
   JSON. PowerShell's ">" writes such files, so a Windows user will hit this.
   Want: the file loads normally.
5. Assessment.validate accepts 1 and 0 for "successful", because 1 == True.
   Finding.validate already does the strict check. Want: the same strict
   check in Assessment.validate (only True, False or None).

Tests:
- One test per item above. For 3 and 4 write the file into a temporary
  directory (tempfile) and delete it afterwards; do not add files to the
  repository.
- Add a CLI test that a nonexistent path returns exit code 2 and prints a
  line starting with "error:" to stderr, and one that the non-UTF-8 file
  does the same. There is no test of the error exit code today.
- The three scenario files load and give exactly the same output as before.

Update the README "Input schema" section if any documented input rule
changed (the byte-order mark and the response_markers type are worth one
line each).
```

**Done when:** none of the five inputs produces a traceback or is silently accepted, and the CLI error path has a test.

### Prompt X4: Wording, dead code and tests that do not test

```
Step X4. Fix open review findings 8, 9 and 10 from CLAUDE.md section 18.
Small cleanups; no rule or decision-table changes.

1. A2 wording. rule_a2_probing counts distinct request targets (path plus
   query), but its summary says "across N distinct paths" and its details
   key is "distinct_paths". With one path and three different queries it
   reports "3 distinct paths", which is wrong. Change the summary to say
   "distinct request targets" and rename the key to "distinct_targets".
   This changes the A2 summary text in the --findings output and in the
   findings table. It must not change the 8-field assessment for any
   scenario; confirm that.
2. Dead code. format_timeline in src/cli.py computes a "widths" variable it
   never uses. Remove it.
3. A2 runs rule_a1_traversal a second time only to fill details["a1_count"],
   which nothing reads. Remove a1_count and that call, unless you find a
   reader of it; tell me what you found.
4. Stale tests in tests/test_models.py:
   - Rename the class PlaceholderAssessTest to a name that says what it
     tests (aggregation of findings and the CLI output).
   - Delete test_no_placeholder_or_pending_notes_remain: it searches for the
     strings "pending" and "not implemented", which no code emits, so it
     cannot fail.
5. In tests/test_rules.py, test_malicious_never_has_empty_missing_context
   checks two inputs but its name says "never". Rename it to say what it
   checks.
6. Missing tests. Add:
   - a test that examples/output.json, parsed as JSON, equals the current
     assessment for scenarios/strong_evidence.json. This file went stale
     once already when the output text changed.
   - a test that the default CLI output (no flags) for each of the three
     scenario files contains the "Timeline", "Findings" and "Assessment"
     headings in that order. Today only suspicious.json is checked.
7. Two limitations are not in the README yet. Add one line each to
   "Limitations and false positives":
   - event IDs are not restricted, so an ID containing ", " makes the
     comma-separated lists in "reason" ambiguous;
   - which ISO 8601 spellings a timestamp may use (beyond the plain
     "2026-09-19T10:00:00Z" form) depends on the Python version, because
     parsing uses datetime.fromisoformat.

If item 1 changed examples/output.json's source output, regenerate the file
with:
  python -m src.cli scenarios/strong_evidence.json --json-only
written as UTF-8 without a byte-order mark. It should not need to change,
because that output has no findings in it; tell me either way.
```

**Done when:** the tests still pass with the stale ones gone and the new ones added, and the 8-field output of all three scenarios is unchanged.

---

## Stage 1b (optional): fixes that change the `suspicious.json` output

Send X5 only if you want these. Both are correct by the project's own rules, but the first one changes the output of `scenarios/suspicious.json`, so two exact-match tests change on purpose.

### Prompt X5: Unknown actor on a traversal attempt; denial marker with no status

```
Step X5. Fix open review finding 5 from CLAUDE.md section 18, and one item
that the README currently lists as a limitation. This step IS allowed to
change the output for scenarios/suspicious.json.

Problem A (unknown actor not reported). In suspicious.json, s3 is a traversal
attempt with "actor_id": null. missing_context mentions only s3's missing
marker, while the recommended action says "Review the source and actor
behind the blocked traversal attempts". A missing identity must be listed.

What I want for A:
- rule_a1_traversal adds a missing_context note when the flagged event has
  no actor_id, and another when it has no source_ip, in the same
  "event X: ..." style as its other notes.
- Nothing else about the finding changes: an unknown actor is not evidence
  for or against blocking.

Problem B (blocked with no response observed). Take suspicious.json reduced
to s1 and set "status": null, keeping the marker "access_denied". The result
is successful=False and the reason says "Blocked: s1 returned no recorded
status". The README says a null status means no response was observed, so
there is nothing to support "blocked".

What I want for B:
- In rule_a1_traversal, a marker declared "denial" supports blocking only
  when a status was recorded. With a null status the outcome is None, and
  the existing "response status missing" note explains why.
- Unchanged: a "denial" marker on a recorded non-2xx status (404, 500, ...)
  is still False. That stays documented as a limitation.

Tests:
- A: suspicious.json unchanged now has the s3 actor note in missing_context.
  Update the two tests that assert the exact old output and tell me which:
  EndToEndAssessTest.test_suspicious in tests/test_rules.py, and the
  suspicious test in the aggregation class in tests/test_models.py if it is
  affected. Classification, successful, risk_score, confidence and
  evidence_event_ids must not change.
- A: an A1 finding for an event with a null source_ip carries the source
  note.
- B: s1 alone with status null + "access_denied": A1 finding None,
  assessment "suspicious" / None.
- B: s1 alone with status 500 + "access_denied": still False.
- benign.json and strong_evidence.json give exactly the same output as
  before.

Update the README: the A1 "Outcome" bullet, the "Blocked can rest on one
signal" limitation (it no longer includes a missing status), and the
scenario description for suspicious.json if it lists what s3 demonstrates.
```

**Done when:** `suspicious.json` lists s3's unknown actor in `missing_context`, its classification and `successful` are unchanged, and a `denial` marker with no status no longer gives `false`.

---

## Stage 2: Investigation report

Use prompts **R1** and **R2** from `docs/prompts-finish.md` unchanged.

1. Send R1 to get a fresh fact sheet. The output text changed since the last one if you sent X1 or X5, so do not reuse an old fact sheet.
2. Write `investigations/case-01.md` yourself from that fact sheet.
3. Send R2 and correct the report until its first list is empty.

---

## Stage 3: Final check and commit

Send prompt **V2** from `docs/prompts-finish.md` unchanged. When it reports every line of CLAUDE.md section 16 as met, send C1.

### Prompt C1: Commit and push

```
Step C1. Commit and push the finished work.

1. Run python -m unittest discover -s tests and the three README usage
   commands one more time. Stop and tell me if anything fails.
2. Show me git status and git diff --stat. List every file that will be in
   the commit. Do not add files that are not part of the project (editor
   settings, caches, temporary output).
3. Commit to main with a message that says what changed and why, in the
   style of the existing history, and push to origin.
4. Reply with the commit hash and confirm that git status is clean and the
   branch is up to date with origin/main.
```

**Done when:** `git status` is clean and GitHub shows the commit.
