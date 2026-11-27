# SafeEvidence Donor Rights Register

Status: `P00_BINDING`

Founder statement: permission has been asserted for all discussed source-code
donors. This register does not deny that assertion. It makes the permission
basis auditable before copying bytes into SafeEvidence.

## Admission basis

- `PUBLIC_LICENSE`
- `FOUNDER_OWNED`
- `SEPARATE_PERMISSION_ASSERTED`
- `SEPARATE_PERMISSION_VERIFIED`
- `REFERENCE_ONLY_PENDING_RIGHTS`
- `DENIED`

Code, models, datasets, terminology, publications, fonts and other assets are
tracked separately.

## Candidate discovery register (NOT an import allowlist)

| Source | Current planning basis | Default allowed mode before further record |
|---|---|---|
| TheHalfMoon/MedScale | PUBLIC_LICENSE / founder-controlled sibling | COPY_BOUNDED / DEPEND after slice review |
| TheHalfMoon/DAL | PUBLIC_LICENSE / founder-controlled sibling | COPY_BOUNDED |
| TheHalfMoon/commandMed | PUBLIC_LICENSE / founder-controlled sibling | ORACLE_COPY / COPY_BOUNDED |
| TheHalfMoon/MESC | founder-controlled sibling; exact file licenses required | REFERENCE / COPY after slice record |
| TheHalfMoon/Morize | founder-controlled sibling; exact file licenses required | REFERENCE / COPY after slice record |
| TheHalfMoon/ottari | founder-controlled sibling; exact file licenses required | COPY_BOUNDED after slice record |
| TheHalfMoon/kernux | founder-controlled sibling; exact file licenses required | COPY_BOUNDED after slice record |
| TheHalfMoon/Signthos | AGPL public tree plus founder permission assertion | REFERENCE until separate permission/relicense record is attached |
| AbdulazizShehri/SafeOCR | Apache-2.0 at inspected state | COPY_BOUNDED after dependency/model review |
| maziyarpanahi/openmed | public license plus per-data/model gates | COPY_BOUNDED / DEPEND; restricted assets excluded |
| xberg-io/xberg | public license plus transitive/native/model review | DEPEND / VENDOR after feature/rights closure |
| docling-project/docling.rs | public license plus model review | DEPEND / VENDOR after feature/rights closure |
| fastembed-rs | PUBLIC_LICENSE | DEPEND / VENDOR |
| ncbi/MedCPT | code basis recorded separately from model weights | REFERENCE / ARTIFACT_IMPORT after model-card admission |
| ASReview | PUBLIC_LICENSE | WORKER / COPY_BOUNDED |
| SYNERGY | dataset terms tracked separately | BENCHMARK after item/data-rights review |
| UniFFI | PUBLIC_LICENSE with covered-file obligations | DEPEND |
| tough / rust-tuf | PUBLIC_LICENSE | DEPEND after conformance qualification |
| cqframework CQL | PUBLIC_LICENSE | WORKER / REFERENCE |
| HL7/ebm | standards/reference terms | REFERENCE / EXPORT_CROSSWALK |
| SciFact | code/data terms tracked separately | BENCHMARK / CODE_REFERENCE |
| MultiVerS | public repo; exact code/model rights required | BENCHMARK_ONLY until admitted |
| evidence-surveillance/es3 | public license at inspected revision | COPY_BOUNDED / REFERENCE |
| trialstreamer | founder asserts separate permission; no public license observed | REFERENCE_ONLY_PENDING_RIGHTS until permission reference is recorded |
| robotreviewer | GPL public tree; founder asserts separate permission | BENCHMARK/WORKER until separate permission or GPL distribution decision is recorded |
| RRnlp | code/model rights reviewed separately | BENCHMARK / MODEL_ARTIFACT_IMPORT after admission |
| Evidence Inference | code/data/publication rights separate | BENCHMARK / COPY_BOUNDED after data-rights review |
| PICOX | notebook/data/model rights separate | BENCHMARK / REFERENCE |
| statsmodels | PUBLIC_LICENSE | DEPEND / VENDOR_SELECTED |
| metafor | copyleft R package | DEVELOPMENT_ORACLE / OPTIONAL_WORKER subject to distribution decision |
| Slint | custom/GPL/commercial choices | DEPEND only after selected license/attribution record |
| Tauri | public permissive license | DEPEND candidate |
| Iroh | exact adopted license/revision required | DEPEND candidate after transport qualification |

## Exact-slice import admission ledger

Product admissions are recorded and validated in
`docs/evidence/source_admissions.json` (`tools/governance/source_admission_check.py`).
The table below records only the G01a baseline, which holds NO_ADMISSIONS. No row
in the candidate discovery table
certifies redistributability or permits an automatic vendor/copy operation.

Before the first imported byte, add one admission row per exact component to the
JSON ledger above. The columns below remain the review checklist for each row:

| Admission ID | Repo | Full source SHA | Exact paths / content digests | Owner and contributor authority | Verified governing code license or separate-grant reference | Mode and compatibility analysis | Required notices / copyleft or attribution | Transitive code/native library | Model weights/tokenizers | Dataset/publication text | Terminology/assets/fonts | Export/redistribution territories and conditions | Security/test owner | State |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| NONE | not yet imported | — | — | — | — | — | — | — | — | — | — | — | — | NO_ADMISSIONS |

Each entry is either CANDIDATE, RIGHTS_UNKNOWN, VERIFIED_ALLOWED,
REFERENCE_ONLY, or DENIED. Only VERIFIED_ALLOWED plus required notices
and transitive review permits copy/vendor/distributed worker.

For FOUNDER_OWNED code, establish contributor ownership/consent scope and
allowable relicensing; common GitHub identity is not in itself a documented
transfer of other contributors' rights. For SEPARATE_PERMISSION_VERIFIED,
record a durable grant reference naming the actual rightsholder and
code/revisions, allowed modification, combination, publication, commercial
use, sublicensing if applicable, and notice conditions. An asserted but
unverified grant is deny-for-copy.

A GPL/AGPL source may still be used through a qualified distribution route
that follows its license; it must not be silently relicensed to Apache-2.0.
Worker separation alone does not waive applicable license obligations.

Model weights, benchmark corpora, trial article PDFs/abstracts, UMLS/RxNorm
restricted terms, native binaries, fonts and assets have their own decisions
even when their wrapper source is permissively licensed.

### Priority donor corrections

- `trialstreamer`: REFERENCE_ONLY_PENDING_RIGHTS until a public license or
  specific documented separate permission is verified.
- `robotreviewer`: GPL-governed code; BENCHMARK/REFERENCE until a compliant
  distribution decision or verified alternate license.
- `Signthos`: AGPL-governed public code and founder permission assertion;
  reference only until all rights holders/contributors' applicable scope and
  compatible grant/distribution route are verified.
- `Slint`: shell candidate; record the selected license/distribution mode and
  all attribution obligations before admission.

## Import rule

No external source with `SEPARATE_PERMISSION_ASSERTED` or
`REFERENCE_ONLY_PENDING_RIGHTS` may be copied into the Apache-2.0 product tree
until the repository records a documentary permission reference or an allowed
public-license path.

A permission record must identify:
- rightsholder/grant source;
- covered repository/revision or scope;
- allowed modification/redistribution/rebranding;
- sublicensing/combined-work constraints where relevant;
- required notices.

Public code permission never implies permission for model weights, datasets,
terminology or publication content.

## Phase gates

P01 establishes license scanning, exact source-pin capture, SBOM and notice
generation plus a reviewed/approved first-import allowlist. A single
rights owner must sign the actual component row; a project-wide founder
assertion alone is not an import event.

Every subsequent transplant PR must cite an admission ID and immutable
revision, with evidence that code, models, third-party assets and tests match
the approved scope. A component that changes revision/dependencies is
re-admitted; unknown terms fail closed. This is an engineering compliance
gate, not a legal opinion.
