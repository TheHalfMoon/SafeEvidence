# Plan Amendment `plan-v1.5` (2026-11-07)

Records founder rulings on VS-1 scope by pointer. Frozen artifacts and digests are unchanged.

**Founder decisions, 2026-11-07, given in the Claude Code session.** Each answered a question put to the founder. These record instructions. They are not signatures or clinical sign-offs, and this amendment closes no rights, clinical, trust or regulatory gate.

| Question | Answer |
|---|---|
| Is `plan-v1.1` in force? | "Ratify now" |
| Does VS-1's TA-20 include the shell checklist? | "Ask flow now, checklist at M4" |
| Can a synthetic set satisfy TA-09 for VS-1a? | "Synthetic, labelled as such" |
| What replaces Codex in the M1 exit review? | "Separate agent reviews plus OCR" |

## `plan-v1.1` is in force

The founder ratified it as owner. Its header said it was not in force until merged with the reviews in its §F, and §F asks for an independent review of its final text. **No independent human review exists.** The reviews recorded are AI agent reviews, and the founder ruled on that basis. EXT-06 stays open.

Its §E applies §C's ordering only once it is in force, and the §C steps ran before this ratification. This records that, and does not rewrite it.

## TA-20 for VS-1

VS-1's TA-20 is the Ask flow, funnel, span jump and outcome display in the end-to-end suite, on Windows and Ubuntu, as WP-18a and the VS-1 done list say. Deep Review open, pack import and the shell checklist stay with WP-18 at M4. The reason: WP-18a's own acceptance is the Ask subset, and the ledger's stricter reading had no basis in the work packets.

WebView storage is checked before M1 exit anyway, on Linux and Windows. Run 42344969326, incognito with automation on, shows a build leaving files in its data directory.

**An engineering call, not a founder ruling:** the Linux end-to-end window is not incognito, because wry turns automation off for an incognito window. So VS-1 does not show the shipped Linux window running the Ask flow, and this amendment leaves that owed at WP-18. The founder can overrule it.

## TA-09 for VS-1a

A pre-registered synthetic set satisfies "BM25 measured on held-out set" for VS-1a, because EXT-02 excludes real corpora. "Held out" means that nothing in BM25 or Ask is tuned on it: its queries and labels are not used to set any parameter, and a change made after seeing its result is reported as such. It is labelled by study so double counting can show up, without settling the study-labelled question `plan-v1.1` §D leaves open.

- It proves the harness and records a baseline. **It is not a claim about retrieval quality**, and every report of it says so.
- The set's digest is fixed before the first measurement.
- Measuring on rights-admitted data stays owed before any dense or rerank promotion under TA-09.
- Retrieval supplies only a funnel count to Ask today, so this measures a component that does not yet affect answers.

**Open before M1 exit:** the frozen VS-1 path is FTS5 retrieval with funnel counts leading to evidence spans, and here metadata picks the evidence. Before M1 exit, either retrieval selects the evidence or the founder rules to accept the difference.

## M1 exit review

The plan names Codex, Opus and OCR. The founder barred Codex on 2026-11-05. The M1 exit review is at least two separate agent reviews, as `docs/GAP_REVIEW.md` asks, each starting without the other's findings, with OCR's rules applied, recorded on the PR. It is labelled as AI-only. It does not satisfy EXT-06, which stays open. The option the founder chose also says that EXT-06 blocks any release claim, which is stricter than `docs/PLAN_FREEZE.md`, where it blocks P01 closure.

## TA-05 for VS-1: an engineering reading, not a founder ruling

No document defines TA-05's VS-1 subset, except the work packets' VS-1 text, "vault open/commit/restart". The founder can overrule this reading.

| TA-05 or WP-03 clause | For VS-1 |
|---|---|
| Kill at every commit point, restart yields the last committed state | Kept. "Every commit point" means just after each acknowledged commit, and during a run of commits, through the vault's open API. A kill inside SQLite's own commit is not targeted |
| Plaintext residue scan of WAL and temp files = 0 hits | Kept, including a killed store |
| Donor tests pass unchanged, except the adapted journal-kill test | Kept. Each other changed donor test is listed as a difference |
| Disk-full leaves no partial commit | **Not carried:** owed at WP-03's full TA-05 |
| Restore into a clean directory verifies | **Not carried:** owed at WP-03's full TA-05 |
| Key loss | **Not carried:** owed at WP-03. The desktop command refuses a lost key today, and there is no recovery path |

## Status

This scopes VS-1 only. It does not pass M1, and it lowers no threshold beyond what is stated above. TA-21 is unchanged: `plan-v1.1` §C says VS-1a's capture is not a TA-21 pass, and T05 returns before VS-1 is done.
