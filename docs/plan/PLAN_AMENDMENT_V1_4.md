# Plan Amendment `plan-v1.4` (2026-11-06)

Amends TA-13 for VS-1 by pointer. Frozen artifacts and digests are unchanged.

**Founder decisions, 2026-11-06, given in the Claude Code session.** First, "Amend, run a subset": a plan amendment runs every case that fits V1, lists each excluded case with its reason, and
keeps the 1,329 mechanics vectors. Then, asked whether resolving rules captured from the donor's pipeline counts as that subset, with no case run through V1 to a matching outcome: "Accept,
state it plainly". These record instructions. They are not signatures or clinical sign-offs.

## Why

TA-13 requires the donor's spec006 P00-conformant subset to pass at 100%. Run as written, its cases need the donor's tool registry, slot layer and a patient-caregiver role, which V1 does not
serve. Building those to run the cases would add code V1 otherwise does not need.

## TA-13 for VS-1, as amended

| Clause | Test | Status under this amendment |
|---|---|---|
| Mechanics | 1,329 vectors from the donor's `evaluate_precedence`: `tests/t13_parity.rs` | Kept |
| Fixture subset | For 12 of the 17 cases, the rules the donor's own pipeline fired resolve to the donor's state, with rules and states pinned: `tests/t13_fixture_subset.rs` | **Narrowed:** resolution only |
| Request level | All 17 question texts through `ask` return a pinned refusal with no text: `headless_ask.rs` | New. Pins Ask's behaviour, and is not parity |
| Lexical emergency | A dedicated test: lexical symptoms never yield `EMERGENCY_NOTICE` | Unchanged |
| Exactly one `TerminalOutcome` | `ask` returns one by type. `evaluate_precedence` can return `NoRuleFired` or an action, and Ask maps those | Unchanged |
| UI renders no percentage | A scan of the view's labels and source for percent text. Nothing is rendered in this test, and it would not catch a value computed at runtime | Weaker than the clause reads |
| DAL metric vectors to 1e-12 | WP-11, with T14 | **Unchanged and not met:** still owed at WP-11 |

## What this shows, stated plainly

The included cases show little beyond the mechanics vectors. Every one fires one rule or none, so they cannot exercise precedence or conflicts: mutants of those pass the subset, and only
the vectors catch them. What they add is that real rule identities and precedences from the donor's pipeline pass through unchanged.

| Included cases | Fired by the donor | What it means for V1 |
|---|---|---|
| 9 | Only `SCAFFOLD::TOOL_LAYER`, the donor's tool layer | V1 has no such layer, so these mean nothing end to end |
| 2 | `R006-DOSAGE-INTENT-INCOMPLETE-V1`, a policy rule | V1 does not detect this |
| 1 | No rule | The donor answers. The port returns `NoRuleFired`, because a commit needs its own proof |

## What this gives up

- **No case runs through V1 to a matching outcome by design.** No Rust code reads a case's request or context. The port resolves rules the donor's pipeline chose, and does not detect them.
- **The same question mostly gets a different outcome.** Ask refuses inside its closed grammar where the donor routes, asks for more or answers. Six cases share the donor's `ABSTAIN`, but through the grammar gate, not the donor's
  tool-failure logic, so those matches show nothing about that logic.
- **Injection and spoofing are not shown.** Reason codes are not compared or kept: `INJECTION_ATTEMPT_SUPPRESSED`, `SPOOFED_TOOL_RESULT_REJECTED`, `TOOL_UNAVAILABLE`, `TOOL_TIMEOUT` and `EVIDENCE_NOT_RESOLVED` are all dropped. The
  injection and spoof cases keep their names, but test neither behaviour here.
- **The fixtures are pinned, not re-derived.** CI cannot rerun the generator, which needs a donor checkout, so the tables in the tests are what catch a changed fixture.

## Excluded, with reasons

| Case | Reason |
|---|---|
| `emergency-keyword-en` | Lexical emergency, excluded by TA-13 as frozen |
| `emergency-keyword-ar-msa` | Lexical emergency, excluded by TA-13 as frozen |
| `ambiguous-risk-fails-toward-escalation-not-answer` | Lexical emergency in the donor's result |
| `injection-suppressed-emergency-preserved` | Lexical emergency in the donor's result |
| `severe-pattern-escalates` | A symptom-phrase regex requiring `ESCALATE`, which P00 guard 2 forbids. TA-13 names only emergency cases, but requires a P00-conformant subset |

The donor's `edge-conflicts.json` holds no cases.

## Obligations

- TA-13's WP-11 clause stands: full TA-13 needs the DAL vectors.
- When V1 gains a tool layer or trigger detection, add a real request-level comparison. None exists now.
- A rendered test for the no-percentage clause belongs with TA-20's end-to-end suite.

## Status

This narrows TA-13 for VS-1 only. It does not pass M1, and it makes no clinical claim about any case or outcome. The fixture texts are test inputs from the donor, and are not medical information.
