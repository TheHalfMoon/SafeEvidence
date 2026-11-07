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

## Status

This scopes VS-1 only, and makes no clinical claim. It closes the item `plan-v1.5` left open, and changes no threshold.
