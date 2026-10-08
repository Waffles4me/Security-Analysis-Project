# Finish prompts: evidence gaps, report, README, final review

These prompts take the project from "rules implemented" to the definition of done in CLAUDE.md section 16. They continue from `docs/prompts-rules.md`.

Send them **one at a time, in order**. After each one:

- review the diff,
- run `python -m unittest discover -s tests` yourself,
- run the CLI on all three scenarios.

Only move on when the step's "Done when" line holds. If you start a new agent session partway through, send Prompt 0 again first.

| Stage | Prompts | Who writes |
|---|---|---|
| Orientation | 0 | agent reads, changes nothing |
| 1. Fix the three evidence gaps | F1, F2, F3 | agent |
| 2. Investigation report | R1, R2 | **you** write `case-01.md`; the agent prepares facts and checks your draft |
| 3. README limitations | D1 | agent |
| 4. Final review and clean run | V1, V2 | agent |

Gaps 4, 5 and 6 in CLAUDE.md section 18 are not fixed by these prompts. They are documented as limitations in D1.

---

## Prompt 0: Initiation and orientation (send once per session)

```
You are joining a small Python project partway through. Before I give you any
task, get oriented. Do not change any file in this step.

The project is "API Incident Investigator": a local, standard-library-only
tool that reads a synthetic JSON log of API requests and responses and decides
what the evidence supports. Its whole point is to never claim more than the
log shows: an attack-looking request proves only an attempt, and an HTTP 200
does not prove that protected data was returned. It is a portfolio project, so
the code must stay simple enough for me to explain every rule in an interview.

Read, in this order:
1. CLAUDE.md, fully. Section 18 is the current progress and lists six known
   evidence gaps. Sections 3, 10 and 11 are the evidence rules you will be
   held to.
2. README.md, especially "Rules" and the decision table.
3. src/models.py, src/rules.py, src/cli.py.
4. tests/test_models.py and tests/test_rules.py.
5. The three files in scenarios/.

Then run:
  python -m unittest discover -s tests
  python -m src.cli scenarios/benign.json
  python -m src.cli scenarios/suspicious.json
  python -m src.cli scenarios/strong_evidence.json --findings

Reply with a short orientation report:
- the test count and whether all pass (CLAUDE.md section 18 says 84; tell me
  if you see something else),
- the classification and "successful" value for each scenario,
- in your own words, what rule_a1_traversal, rule_a2_probing,
  rule_a3_exposure and assess() each decide,
- anything in the code that contradicts CLAUDE.md or the README.

Standing constraints for every later step:
- Standard library only. No LLM at runtime.
- Findings and assessments may only cite event IDs that exist in the input.
- successful=True needs a response marker declared "protected_content";
  successful=False needs blocking evidence; everything else is None.
- Missing facts stay None and are listed in missing_context. Never assume
  identity, authorization, intent or outcome.
- Do not edit the three scenario files unless a step says so. Build variants
  inside tests instead.
- When a step changes behaviour that an existing test asserts, change that
  test on purpose and tell me which one and why. Do not work around it.
- Keep README.md true: if a step changes a rule or the decision table, update
  that part of the README in the same step.
- Do not commit or push. I will ask for that explicitly.
- Do only the step I give you, then stop and summarize the diff, list any
  choice you made that the step left open, and show the test result.

After the report, wait for the first step.
```

**Done when:** the report matches what you see when you run the same commands, and no file changed (`git status` is clean).

---

## Stage 1: Fix the three evidence gaps

Fix these before writing the report. The report must match the tool's output, so a fix made afterwards would force a rewrite.

### Prompt F1: Protected content returned to a request A1 did not flag

```
Step F1. Fix known gap 1 from CLAUDE.md section 18.

The problem: rule_a3_exposure only looks at events that A1 flagged. If
user-7 sends a normal-looking request (no "..") for another user's file and
gets 200 with a marker declared "protected_content", no rule fires and the
assessment says "benign", risk 5, "No action required". That is the tool
claiming more than the evidence supports: protected content was returned and
nobody checked whether the actor was entitled to it.

What I want:
- A3 also emits a finding for an event that A1 did NOT flag, when its status
  is 2xx and its marker is declared "protected_content" and
  environment.protected_resource is defined.
- That finding has successful=None, never True. The log shows protected
  content was returned; it does not show the access was improper. Its
  missing_context says that whether the actor (name the actor_id, or say it
  is unknown) is entitled to the protected resource is not established.
- details must let a reader tell the two kinds of A3 finding apart, e.g. a
  boolean saying whether the request was flagged by A1.
- Findings for A1-flagged events behave exactly as today.

Decision table: add a row between "any traversal attempt is unresolved" and
"every traversal attempt was blocked":
  protected content returned to an unflagged request -> "suspicious",
  successful None.
It must sit above the "all blocked" row, otherwise blocked traversal
elsewhere in the log would report successful=False while protected content
went out on another request. When it is the only thing found, use risk 50 and
confidence 50, and document both next to the other heuristic values. The
reason must name the event, its status and its marker, the same way the
other rows do.

Tests:
- benign.json with one event's marker changed to "private_report_content":
  one A3 finding, successful None, assessment "suspicious" / None, the
  entitlement question in missing_context, and never "benign".
- The same mutation with protected_resource removed: no True anywhere, and
  the result follows the existing insufficient_data override.
- suspicious.json plus one extra unflagged 200 event carrying the protected
  marker: overall successful is None, not False.
- benign.json unchanged still gives "benign" with zero findings. Its markers
  are declared "expected", so this fix must not touch it.
- strong_evidence.json still gives "malicious" / True.
Three existing tests in PossibleExposureA3Test assert the old behaviour
(protected marker on a non-suspicious event gives no finding, and A2-only
events are not examined). Change them to the new behaviour and tell me.

Update the README: the A3 section, the decision table and the risk table.
```

**Done when:** the mutated benign scenario is no longer `benign`, the untouched benign scenario still is, and `True` still appears only for `e3`.

### Prompt F2: Conflicting status and marker must not read as "blocked"

```
Step F2. Fix known gap 2 from CLAUDE.md section 18.

The problem: rule_a1_traversal sets successful=False when the status is 401
or 403, or when the marker is declared "denial". It does not notice when the
two signals disagree. A 403 that carries a marker declared
"protected_content" is reported as blocked, and so is the overall assessment.
CLAUDE.md section 3.2 allows False only when the evidence supports blocking.
Here the evidence conflicts, so the honest answer is None.

What I want, in rule_a1_traversal:
- Treat these as a conflict: a 401/403 status with a marker declared
  "protected_content"; and a 2xx status with a marker declared "denial".
- On a conflict, successful is None, details records the conflict in a way a
  reader can see (which status, which marker, which semantics), the summary
  says the response is contradictory, and missing_context says what was
  actually returned for that event is unclear.
- A 401/403 with a "denial", "generic", undeclared or missing marker stays
  False, exactly as today. So does a non-2xx, non-401/403 status with a
  "denial" marker.

assess() currently handles the 2xx + denial case by letting A3's reading
override A1's. Once A1 reports None itself, check whether that override is
still needed. Remove it only if every existing end-to-end test still passes
without it; otherwise keep it and tell me why.

Tests:
- suspicious.json with s1 changed to marker "private_report_content" (status
  stays 403): s1's A1 finding is None with the conflict recorded; the
  assessment is "suspicious" / None; s2 and s3 are still False.
- suspicious.json reduced to s1 with status 200 and marker "access_denied":
  A1 finding None.
- suspicious.json unchanged: all three findings still False and the
  assessment still "suspicious" / False.
- No case in this step produces True.

Update the README A1 section to describe the conflict case.
```

**Done when:** a 403 with the protected marker gives `successful: null`, and the unchanged suspicious scenario still gives `false`.

### Prompt F3: "Malicious" must say what it does not establish

```
Step F3. Fix known gap 3 from CLAUDE.md section 18.

The problem: decision row 1 sets classification "malicious" from one fact, a
protected-content marker on the response to a traversal-shaped request. That
supports exposure. It does not show who did it, whether they were permitted
to (a sanctioned test, for example), or why. CLAUDE.md section 3.1 says not
to invent intent or authorization state. Today a single exposed event with no
probing burst gives "malicious" with an empty missing_context, and the
recommended action tells the reader to fix the route as if a vulnerability
were confirmed.

Keep "malicious" as the classification value for row 1 and keep
successful=True. Change what surrounds it:
- Whenever row 1 applies, missing_context always contains two notes: that
  the intent of the actor/source is not established, and that whether the
  access was authorized (for example sanctioned testing) is not established.
  Name the actor_id and source_ip from the exposed event(s), or say they are
  unknown when they are None.
- The reason states that the classification rests on the response marker
  and reflects supported exposure, not proven intent.
- The recommended action asks the reader to confirm server-side what was
  returned and whether the request was authorized, before anything else. It
  must not assert that the route is vulnerable.
- No other decision row changes.

Tests:
- strong_evidence.json reduced to e3 alone: still "malicious" / True, and
  missing_context is non-empty and contains both notes.
- strong_evidence.json with e3's actor_id set to null: the notes say the
  actor is unknown and do not name one.
- The full strong_evidence.json end-to-end test: update its expected
  8-field output to the new text.
- suspicious.json and benign.json outputs are byte-for-byte unchanged.

Update the README: in "Definitions" or next to the decision table, say in
one or two sentences what "malicious" means in this tool and what it does
not claim.
```

**Done when:** no input can produce `malicious` with an empty `missing_context`, and the other two scenarios' outputs did not change.

---

## Stage 2: Investigation report

You write `investigations/case-01.md` yourself. The agent only prepares the facts and then checks your draft, so the report stays yours and stays tied to the real output.

### Prompt R1: Regenerate the output and prepare a fact sheet

```
Step R1. Do not create investigations/case-01.md. I will write it.

1. Regenerate examples/output.json from:
     python -m src.cli scenarios/strong_evidence.json --json-only
   Write it as UTF-8 without a byte-order mark and confirm it parses and has
   exactly the 8 schema keys.
2. Run:
     python -m src.cli scenarios/strong_evidence.json --findings
3. In your reply (not in a file), give me a fact sheet for the report. For
   each item in CLAUDE.md section 12, quote the exact value from the output
   that answers it and name the output field or finding it came from:
   - what request/payload was observed, per event
   - what response occurred, per event
   - what each HTTP status means here
   - what each response marker is declared as, and how far it can be trusted
   - which event IDs support the conclusion
   - whether exposure was successful, blocked or unknown, per event and
     overall
   - what context is missing (copy missing_context verbatim)
   - the recommended next step (copy recommended_action verbatim)
   - limitations and false-positive possibilities that apply to this case
4. Add a short section "Questions an interviewer could ask", with the answer
   to each taken from the code or the output. Include: why did e2's 200 not
   prove exposure, and why did e3's?

Use only what the tool printed and what the scenario file contains. If
something section 12 asks for is not in the output, say it is not available
instead of filling it in.
```

**Done when:** every value in the fact sheet can be found in the CLI output you ran yourself.

### Prompt R2: Check my report against the output

```
Step R2. I have written investigations/case-01.md. Review it. Do not rewrite
it and do not edit the file.

Run:
  python -m src.cli scenarios/strong_evidence.json --findings
Then compare the report with that output and with
scenarios/strong_evidence.json. Give me three lists:

1. Statements in the report that the output or the scenario does not
   support, or that contradict them. Quote the sentence, say what the
   evidence actually shows, and suggest the smallest correction.
2. Items from CLAUDE.md section 12 that the report does not cover.
3. Places where the report presents the synthetic data as a real incident,
   or describes risk_score/confidence as probabilities.

Check every event ID, status, marker and number in the report against the
output. If the report is consistent, say so plainly; do not invent problems.
```

**Done when:** list 1 is empty after your corrections.

---

## Stage 3: README limitations

### Prompt D1: Limitations and false-positive section

```
Step D1. README.md has no limitations or false-positive section, and
CLAUDE.md section 13 requires both. Add them. Change no code.

Add a section "Limitations and false positives" after "Rules". Write it for
a reader who has not seen the code and wants to know when not to trust the
output. Cover:

Limitations (things the tool cannot see or does not check). Verify each one
against the current code before writing it, and leave out any that an
earlier step fixed:
- A3 does not compare actor_id with expected_access or auth_model, so it
  cannot tell entitled access from improper access.
- A1 reads only path and query, not request_body.
- A1 does not match "..;/", overlong UTF-8 such as "%c0%ae", "....//", or
  payloads encoded more than twice.
- The tool trusts the marker declarations in the environment; a wrong
  declaration gives a wrong conclusion.
- "benign" means no rule matched, not that nothing happened.
- In the malicious case evidence_event_ids lists every cited event, not
  only the ones that support exposure.
- risk_score and confidence are heuristics, not calibrated probabilities.
- Any other limit you find in the code. Tell me which ones you added.

False positives (benign activity the rules can flag), each with the reason
the tool does not over-conclude from it:
- a legitimate ".." segment in a path or query value,
- an authorized scanner or test client triggering A2,
- a client with several users behind one IP triggering A2.

Also check that the README covers every item in the CLAUDE.md section 13
list. Report any that are missing or out of date, and fix those.

Keep it short: one line per limitation, no repetition of the rules section.
Then run the commands in "Usage" and "Tests" exactly as written and confirm
they work.
```

**Done when:** every limitation listed is true of the current code, and every item in CLAUDE.md section 13 is in the README.

---

## Stage 4: Final review and clean run

### Prompt V1: Final code review (no code changes)

```
Step V1. Review only. Do not change any file.

Review src/models.py, src/rules.py, src/cli.py and both test files against
CLAUDE.md sections 3, 9, 10 and 11. I want a list of real problems, ordered
by how much they matter, each with the file and line, a concrete input that
triggers it, and what the tool outputs versus what it should output.

Look specifically for:
- any path to successful=True without a marker declared "protected_content",
- any path to successful=False without blocking evidence,
- any output that can cite an event ID not in the input,
- any place a missing field is treated as evidence of something,
- any reason or recommended_action text that states more than the cited
  events support,
- decoding that is not bounded,
- behaviour that only works because of the three scenario files (overfit),
- tests that pass without really checking the thing their name claims,
- code that is harder to explain than it needs to be.

Confirm each problem by running the input before you report it. Separate
"confirmed" from "suspected". If you find nothing in a category, say so.
Finish with a recommendation: which problems to fix before publication and
which to document as limitations.
```

**Done when:** you have decided, for each reported problem, whether to fix it (send a small fix prompt in the F1–F3 style) or add it to the README limitations.

### Prompt V2: Clean run, definition of done, progress update

```
Step V2. Final check before publication.

1. From a clean state, follow README.md exactly as a new user would: run
   every command in "Usage" and "Tests" as written, on all three scenario
   files. Report each command and whether it worked. If a documented command
   fails or the output differs from what the README says, fix the README (or
   tell me if the code is what is wrong).
2. Confirm examples/output.json equals the current output of
     python -m src.cli scenarios/strong_evidence.json --json-only
   and regenerate it if it does not.
3. Confirm investigations/case-01.md still agrees with that output. Do not
   edit the report; list any mismatch for me.
4. Go through CLAUDE.md section 16 line by line. For each line say "met",
   with the file, test or command that shows it, or "not met", with what is
   missing. Do not mark a line met on the strength of intent.
5. Update CLAUDE.md section 18: the date, the workflow status table, the
   "Still to do" list, the known-gaps list (remove what was fixed, keep what
   was documented as a limitation and say so), the test count, and the
   results table.

Do not commit or push. End with the list of files changed in this step and
anything that still blocks the definition of done.
```

**Done when:** every line of CLAUDE.md section 16 is marked met with evidence. Then ask for the commit.
