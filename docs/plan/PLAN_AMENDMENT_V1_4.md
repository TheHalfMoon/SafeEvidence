# Plan Amendment `plan-v1.4` (2026-11-06)

Amends TA-13 for VS-1 by pointer. Frozen artifacts and digests are unchanged.

**Founder decision, 2026-11-06, given in the Claude Code session:** "Amend, run a subset". Option text: a plan amendment runs every case that fits V1, lists each
excluded case with its reason, and keeps the 1,329 mechanics vectors. This records an instruction. It is not a signature or a clinical sign-off.

## Why

TA-13 requires the donor's spec006 P00-conformant subset to pass at 100%. Run as written, its cases need the donor's tool registry, slot layer and a
patient-caregiver role, which V1 does not serve. Building those to run the cases would add code V1 otherwise does not need.

## TA-13 for VS-1, as amended

| Clause | Test | Status under this amendment |
|---|---|---|
| Mechanics | 1,329 vectors from the donor's `evaluate_precedence`: `tests/t13_parity.rs` | Kept |
| Fixture subset | For 13 of the 17 cases, the rules the donor's own pipeline fired resolve to the donor's state: `tests/t13_fixture_subset.rs` | **Narrowed:** resolution only |
| Request level | All 17 question texts through `ask` end in one refusal with a reason, with no text and no emergency notice: `headless_ask.rs` | New |
| Lexical emergency | A dedicated test: lexical symptoms never yield `EMERGENCY_NOTICE` | Unchanged |
| Exactly one `TerminalOutcome` | `ask` returns one by type. `evaluate_precedence` can return `NoRuleFired` or an action, so Ask maps those | Unchanged |
| UI renders no percentage | Desktop frontend tests | Unchanged |
| DAL metric vectors to 1e-12 | WP-11, with T14 | **Unchanged and not met:** still owed at WP-11 |

## What this gives up

- **Same outcome at request level is not required.** The port does not detect triggers. The donor's pipeline chooses the rules, and the port only resolves them. Given the same question, Ask
  refuses inside its closed grammar where the donor routes, asks for more or escalates. For example, the donor answers `no-requested-tool-plain-answer`, and its `severe-pattern-escalates` and
  `missing-slot-asks-more-en` return `ESCALATE` and `ASK_MORE`. Ask's detection of those patterns is not implemented.
- **Most included cases fire one rule,** so they show the port honours real rule identities and precedences, not hard conflicts. Conflict behaviour comes from the mechanics vectors.
- The tool-routing cases mean nothing end to end until V1 has a tool layer.

## Excluded, with reasons

| Case | Reason |
|---|---|
| `emergency-keyword-en` | Lexical emergency, excluded by TA-13 as frozen |
| `emergency-keyword-ar-msa` | Lexical emergency, excluded by TA-13 as frozen |
| `ambiguous-risk-fails-toward-escalation-not-answer` | Lexical emergency in the donor's result |
| `injection-suppressed-emergency-preserved` | Lexical emergency in the donor's result |

The donor's `edge-conflicts.json` holds no cases.

## Obligations

- TA-13's WP-11 clause stands: full TA-13 needs the DAL vectors.
- Re-run the request-level comparison when V1 gains a tool layer or trigger detection.

## Status

This narrows TA-13 for VS-1 only. It does not pass M1, and it makes no clinical claim about any case or outcome.
