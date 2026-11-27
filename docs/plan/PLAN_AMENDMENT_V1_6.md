# Plan Amendment `plan-v1.6` (2026-11-07)

Settles the open item `plan-v1.5` left before M1 exit: retrieval did not select the evidence. Frozen artifacts and digests are unchanged.

**Founder decision, 2026-11-07, given in the Claude Code session.** Asked how VS-1a should handle evidence chosen by metadata across the whole corpus, against the frozen path where retrieval leads to the evidence, the founder chose "Retrieval cites, guards see all". This records an instruction. It is not a signature or a clinical sign-off.

## What changes

- **Citing:** only reports lexical retrieval found can be cited in an answer, as the frozen VS-1 path expects.
- **Guards:** the conflict, retraction, rights and applicability checks still decide on metadata across the whole corpus. A contradiction or retraction that retrieval misses still blocks or abstains.
- **A missed applicable report** is listed among the exclusions with `EVIDENCE_INSUFFICIENT` and a plain reason.
- **No citable report:** if retrieval found none of the applicable reports, Ask abstains with `EVIDENCE_INSUFFICIENT`.

## What this gives up

- An answer can cite fewer reports than the corpus holds, when lexical retrieval misses some. The funnel and the exclusions show how many.
- Retrieval quality now affects which reports an answer cites. TA-09's synthetic set shows only that the harness works, so it says nothing about how often that happens on real abstracts.
- **Measured on TA-09's synthetic set:** 6 of its 30 questions now answer differently. q04, q09, q25 and q28 cite one report instead of two, and q23 and q27 abstain where they answered. The other 24 are unchanged. That set is easy by construction, so these numbers mean little for real abstracts.

## Known limits

- With no population in the question, an earlier guard asks for one first. If retrieval then finds none of the matching reports, the person gives the population and still gets an abstention. That ask-for-more did not change the answer, which the decision contract asks it to.
- The funnel's applicable and independent-study counts include reports retrieval missed, so they can be larger than what the brief cites. This is conservative, and the exclusions list each missed report.
- The desktop view shows a missed report's code, not its plain reason, so it looks like any other `EVIDENCE_INSUFFICIENT`.
- `bench/ta09/REGISTRATION.md` and `plan-v1.5` say retrieval does not affect answers. They were true when written and stay as they are. This amendment supersedes them.

## Status

This scopes VS-1 only, and makes no clinical claim. It closes the item `plan-v1.5` left open, and changes no threshold.
