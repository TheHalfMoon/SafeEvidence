# M0 Founder Decision Packet (2026-11-05)

State: **REQUEST ONLY. NOT APPROVED. NOT SIGNED. NO_ADMISSIONS unchanged.**
Prepared by Claude Opus 5.5 at `main` `1a10bc59e452c6486aced95227fa1e8be53bad20`.

This packet is an agent-prepared request. Its merge, its commit signature and
any CI result are not a founder decision. A decision takes effect only as in §3.

## 1. Why engineering is stopped at documentation

`docs/PLAN_FREEZE.md` §4 authorizes only the G01a baseline and documentation.
Every work packet needs EXT-01 (signed rights rows) and EXT-02 (signed scope
extension). The founder's implementation directive of 2026-11-05 grants broad
routine authority and states a source-rights declaration. By its own terms that
declaration is "not automatic documentary verification", and it instructs that
authorizations be obtained "through real, documented decisions".

## 2. Decisions requested

### D1 — EXT-02 synthetic scope extension

Permit, beyond stdlib-only G01a: third-party dependencies and admitted founder
copies; synthetic data only; a workspace separate from the unchanged G01a crate;
toolchain re-pin for C16. Name the accountable engineering owner.

Stays excluded: patient data, clinical claims, model weights, real corpora, signed
packs, live network fetch, release. The 41 P1 findings and Issues #3, #4 and #5
are unaffected.

### D2 — EXT-01 rights owner and first rows

Name the rights owner. For each row in §4, confirm or refuse its exact scope.

### D3 — Review rule for implementation PRs

`main` requires 0 approving reviews today, while the written waiver covers the
planning freeze only. A sole founder cannot approve their own PRs on GitHub. Choose:
extend the waiver to implementation PRs, with required CI plus recorded agent/tool
review; or restore a human review requirement, which stops merges until a reviewer
exists. Neither choice satisfies EXT-06.

### D4 — Publication of private donor code

ottari (T03, T30) is private, and copying it into this public Apache-2.0 repository
publishes that code and its paths. EXT-08 approved stating status and SHAs with
paths withheld, and nothing wider. Choose: approve publishing the exact slices, or
keep them out, in which case WP-03 needs a different route and VS-1 cannot complete
as planned.

## 3. How a decision becomes effective (G01a precedent)

1. Founder states the decision in their own words, bound to this packet's commit.
2. The instruction is recorded verbatim on Issue #17 (scope) or #5 (rights), marked
   as a record of the instruction rather than a signature.
3. A separate governance PR carries the change, with a GitHub-verified signature
   and the founder's own DCO `Signed-off-by`, then passes exact-head and post-merge
   CI.

Agents using this machine's configured signing key and GitHub login do not create a
founder decision by doing so. No agent adds the founder's `Signed-off-by` without
the decision in step 1.

## 4. Candidate rows (all state `CANDIDATE`, none admitted)

Pins checked to resolve through the GitHub API on 2026-11-05. Root license from the
GitHub API; per-file and transitive review is **not done**.

| ID | Source @ pin | Root license | Contributor identities needing the owner's confirmation | Open items |
|---|---|---|---|---|
| T01, T11, T12, T36 | `AbdulazizShehri/MedScale` @ `5c33d77c` | Apache-2.0 | `TheHalfMoon`, `AbdulazizShehri`, `engineering`, `development`, `MedScale Agent` | npm closure for T36; T11 pin differs from the older candidate |
| T03, T30 | `TheHalfMoon/ottari` @ `73706029` | Apache-2.0 | Provided to the founder in session; not published | D4; `rust-version` 1.98.1 (C16); path list is private |
| T13 | `TheHalfMoon/commandMed` @ `51f73ec0` | Apache-2.0; NOTICE present | `TheHalfMoon`, `AbdulazizShehri`, `commandMed CI Repair` | Oracle data is never shipped |
| T17 | `maziyarpanahi/openmed` @ `8440bdac` | Apache-2.0; NOTICE present | External project with many contributors; public-license route | Span logic and tests only; NOTICE carried |
| Crates | `rusqlite`, `tauri` closures | Per crate | Public-license route | Closure rows do not exist; `cargo deny` not yet run |

Plan dependency: frozen WP-00 also lists T05, T07, T14 and T15. Omitting them here
relies on the VS-1a scope reduction proposed in
`docs/reviews/EGM_PLAN_CHALLENGE_2026-11-05.md` §4, which needs `plan-v1.1`. Until
then, these rows alone do not satisfy WP-00 as frozen.

Founder decision needed for all founder-owned rows: whether `TheHalfMoon` and
`AbdulazizShehri` are the same rightsholder, and who is behind the other identities.
The register states that a common GitHub identity is not itself a documented transfer.

## 5. Not requested here

Issue #4 (clinical charter), Issue #3 (41 owners), EXT-05 (key custody), EXT-06
(independent G01a review), EXT-07 (model weights) and EXT-09 (regulatory). They remain
open and block their dependents, including clinical evaluation and release.
