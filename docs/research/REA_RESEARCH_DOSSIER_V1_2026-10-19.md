# SafeEvidence REA Research Dossier — V1 (frozen research input)

Date of observation: 2026-10-19 (UTC capture times recorded per evidence row).
Status: **RESEARCH_BASELINE_V1** — public-surface and anonymous-flow evidence only.
Supersedes nothing; extends `REA_COMPETITOR_DOSSIER_2026-10-19.md` (PR #44, macOS run).

This dossier is planning input. It does not support any comparative,
clinical-performance or superiority claim about SafeEvidence or any competitor.

## 1. Method and evidence classes

| Class | Meaning |
|---|---|
| `REA_OBSERVED` | Captured by the official `morluto/rea` CLI (`rea-agents@6.7.0`, `inspect-web-page`, passive CDP, 4 s window, accessibility text) on an isolated headless Microsoft Edge 155 profile, Windows host. Raw JSON + SHA-256 in `docs/research/rea-2026-10-19-windows/`. |
| `REA_OBSERVED_MAC` | Same CLI, founder's macOS run (PR #44), raw JSON in `docs/research/rea-2026-10-19/`. |
| `BROWSER_OBSERVED` | Observed by the agent in the Claude desktop built-in browser (real browser profile, anonymous, no sign-in) by running a realistic **non-patient, population-level** research query and reading rendered page text/accessibility tree. Contemporaneous notes: `docs/research/rea-2026-10-19-windows/BROWSER_OBSERVATION_LOG.md` (SHA-256 in `SHA256SUMS`); third-party page text is not redistributed, so these rows are reproducible by re-running the recorded URL/query rather than by an archived capture. |
| `VENDOR_DOC` | Vendor's own public documentation or blog. A claim, not verified behavior. |
| `INFERRED` | Architecture/design conclusion drawn by SafeEvidence planning. |
| `BLOCKED` | Observation attempted and refused (HTTP 403, CAPTCHA, or authentication). |

Rules applied: no authentication was created or bypassed; no CAPTCHA or bot
control was circumvented (no user-agent spoofing); no private API was called;
no proprietary server code was obtained. Public website JavaScript is **not**
the product's source code. No reusable source code exists for any Tier 1/2
product: all are closed-source commercial services (OpenEvidence, Scite,
Elicit, GRADEpro GDT, Consensus, DynaMed) or a closed database service
(Epistemonikos; its *database content* is CC BY 3.0 per its footer, which is a
data-source finding, not code).

Standard scenario used everywhere it was accessible (synthetic, population level, no patient):

> *In adults with type 2 diabetes, do SGLT2 inhibitors reduce hospitalization for heart failure compared with placebo?*

## 2. Evidence register

| ID | Target | Class | Evidence id / locator | Result |
|---|---|---|---|---|
| R-OE-1 | openevidence.com home | REA_OBSERVED → BLOCKED | `ev_981b12a688e4a7a0a4a614c95c2413bc430335fbb4d46698e78c8189f3fd7582` | Headless capture served a **DataDome CAPTCHA**; not bypassed. |
| R-OE-2 | openevidence.com ask flow | BROWSER_OBSERVED → BLOCKED | built-in browser, 2026-10-19 | "Ask a medical question" box renders; submitting the standard scenario redirected to `auth.openevidence.com` (Sign Up). No answer observed. |
| R-OE-3 | EvidenceGrade launch post (2026-07-09) | VENDOR_DOC (+ REA_OBSERVED_MAC page capture `ev_a466c925…`) | openevidence.foundation blog | Method described in §3.1. |
| R-SC-1 | scite.ai home | REA_OBSERVED → BLOCKED | `ev_6eb6af4ebe8e71102228dcdcab5b62fbd5d5592f2f04a5f83d320de617c5524b` | CloudFront 403 to headless (same as macOS run). |
| R-SC-2 | scite.ai report for DOI 10.1056/NEJMoa1504720 (EMPA-REG OUTCOME) | BROWSER_OBSERVED | `/reports/empagliflozin-cardiovascular-outcomes-and-mortality-NyAPrP` | Anonymous Smart Citation report rendered; §3.2. |
| R-EL-1 | elicit.com home | REA_OBSERVED | `ev_3520be8be1e691eea27b40bba98bdcf5998158daab1966238382f97bf082e628` | 1,673 accessibility nodes, 8 scripts; release feed lists Research Agent (2026-08-04), Routines (2026-09-30), API+MCP (2026-07-15). |
| R-EL-2 | Elicit app | BLOCKED | `elicit.com/users/auth?show=signin` | All research workflows require sign-in. |
| R-EL-3 | Systematic Literature Reviews page | VENDOR_DOC | elicit.com/solutions/literature-review | Workflow + accuracy claims, §3.3. |
| R-GP-1 | gradepro.org home | REA_OBSERVED | `ev_535482315d063c5085c20ac95fb99e1a476ffd8925594f3481dd54c625830ab6` | Marketing surface: SoF, EtD, Recommendation Map, offline-tolerant work claim. |
| R-GP-2 | GRADEpro key features help article | REA_OBSERVED_MAC | `ev_a09edf8ae1b20d5b7d807878d5735b63dd69b8ee627612e20635955ccac8a7e8` | Feature taxonomy, §3.4. GDT application itself requires an account (not inspected). |
| R-CO-1 | consensus.app home | REA_OBSERVED | `ev_7a37fdc6dd12a8886c44ae8eb6a53268dc509556a9a3f81b5f76a8eb1ea5333a` | Medical Mode / Deep Search entry points. |
| R-CO-2 | Consensus standard scenario | BROWSER_OBSERVED | `consensus.app/search/do-sglt2-inhibitors-reduce-hospitalization-for-hea/BbOslbq7T76xgA31MbwlVA/` | Full anonymous answer; §3.5 (strongest observed failure-mode evidence). |
| R-EP-1 | epistemonikos.org home | REA_OBSERVED → BLOCKED | `ev_447df37e26a196d8a7f963abdda1e63ed653d460bf669072eb55ff949041051b` | CloudFront 403 to headless. |
| R-EP-2 | Epistemonikos search + document | BROWSER_OBSERVED | search `q=sglt2 heart failure hospitalization type 2 diabetes`; document `2ca75f7c1b8e81fa39cf92fa48ae7b242cf2f88d` | §3.6. |
| R-DY-1 | dynamed.com home | REA_OBSERVED | `ev_f6e66ccc8ce787a9a5af50f6bd270ef213220dc47558ef407d8adeb43fbbb4f1` | Dyna AI / Classic Search, Recent Alerts, "Potentially Practice-Changing" filter, EBM nav; cookie banner (not accepted). Content subscription-gated. |
| R-DY-2 | DynaMed product page | VENDOR_DOC | about.ebsco.com/…/dynamed | "seven-step evidence-based methodology", daily systematic literature surveillance, alerts when topics change. |

A separate OpenEvidence `analyze-web-bundle` attempt in PR #44 exhausted Node
heap; it was not re-run (no new evidence expected from a marketing bundle).

## 3. Product findings

### 3.1 OpenEvidence — EvidenceGrade (VENDOR_DOC; app BLOCKED)

Documented method: gradeability pre-filter → per-paper scoring on Quality
(design relative to best-achievable design for the question type), Certainty
(precision: CI width, effect size, sample size) and Relevance (PICO match) →
body-level grade with deference to a current guideline / high-quality SR when
present, design ceiling (RCT → A, observational → B unless best-achievable),
GRADE-style upgrades/downgrades → letter **A–D with ± modifiers, U = unable
to grade**. The vendor states grades may be "gentler" than formal Cochrane
review and that EvidenceGrade is not a substitute for a systematic review.
Retrieval is described as a curated most-relevant set, not exhaustive search.

Lessons for SafeEvidence (INFERRED):
- Adopt: gradeability gate; question-type-relative design ceiling; explicit
  `U`/unable state (maps to SafeEvidence `ABSTAIN` reason codes); deference to
  existing expert synthesis *with recorded override reasons*.
- Improve: a grade over a curated subset can be overstated when retrieval is
  not exhaustive — SafeEvidence must show the retrieval coverage that produced
  the grade and keep certainty, applicability and model confidence separate
  (existing P00 rule). No single letter grade without its per-domain reasons.
- Gap: no observed answer; physician UX, citation rendering and follow-up
  behavior remain **unverified** (authenticated follow-up required).

### 3.2 Scite — Smart Citations (BROWSER_OBSERVED)

Observed on EMPA-REG OUTCOME (NEJM 2015): facets Supporting **341**,
Mentioning **11,278**, Contrasting **32**, Unclassified **623**; section
facets (Introduction 2,264 / Discussion 1,651 / Results 287 / Other 9,959);
Self-cite 182 vs Independent 12,641; publication-type facet including
Preprint 304; "Cited by 12,800 publications (12,274 citation statements)".
Each statement shows excerpt, section, label and a per-statement
"confidence NN%". Assistant actions ("Summarize citations") require login.

Observed failure mode: the two top "contrasting" statements (99% and 98%)
were (a) a post hoc analysis contrasting a *hypothesized* RAS-inhibitor
synergy from "previous literature", and (b) a single-centre open-label
observational study that found no CV-mortality difference while stating it
was not designed to assess CV outcomes. Neither refutes the cited trial's
primary result.

Lessons (INFERRED): citation-statement stance ≠ evidence against the finding.
SafeEvidence keeps a separate `CitationContext` signal (supporting /
contrasting / mentioning, section, self-cite) as *discovery and alerting*
input only, and never lets it change claim support, certainty or
contradiction status without design-weighted appraisal of the citing study.
Retraction/correction awareness must come from Crossref/Retraction Watch and
PubMed publication types (already planned in P03), not citation counts.

### 3.3 Elicit — Research Agent and systematic review (VENDOR_DOC; app BLOCKED)

Documented pipeline: protocol refinement → search across PubMed,
ClinicalTrials.gov and a 138M-paper corpus (+ user uploads) → screening with
autosuggested criteria, "PRISMA-auditable" exclusion reasons, per-criterion
scores and supporting quotes, dual review (two humans + AI, or AI as second
reviewer) → extraction with quote/figure support from text, tables and
figures → reports over up to 200 papers with sentence-level citations and a
methods section with PRISMA flow → Routines for living updates (2026-09-30).
Vendor accuracy claims (99.5% screening recall, 96% extraction accuracy) are
**not independently verified** here.

Lessons (INFERRED): copy the *workflow shape* (protocol → search log →
screening log with reasons → extraction with quotes → PRISMA counts → living
update), which SafeEvidence can assemble from MedOrigin `litdb` (screening
log, ExclusionReason, PRISMA summary), ASReview (prioritisation) and
statsmodels (pooling). Differentiate with local-first execution, study-level
dedup across reports, design-specific appraisal, and refusal to pool
non-independent results.

### 3.4 GRADEpro (REA_OBSERVED marketing/help; app BLOCKED)

Feature taxonomy: Evidence (SoF) tables, Evidence-to-Decision frameworks,
multiple-intervention approach, adolopment, PanelVoice, guideline document
editor, question/outcome generation, interactive SoF, decision aids,
Recommendation Map, publication platform. No public code.

Lessons (INFERRED): SafeEvidence implements GRADE *structures* (per-outcome
certainty with the five downgrade domains and three upgrade domains, SoF row
schema, EtD criteria) as data contracts aligned to the HL7 EBMonFHIR
`CertaintyOfEvidence`, `RiskOfBias`, `RecommendationRating` and
`ComparativeEvidenceReport` profiles (T26 in the transplant matrix). Ratings
are **human-authored or human-confirmed**; automated proposals are labelled
as proposals. EtD/recommendation authoring is out of V1 scope.

### 3.5 Consensus — Pro answer and Consensus Meter (BROWSER_OBSERVED)

Observed on the standard scenario:
- 4-step "Pro" pipeline with a funnel (papers *Retrieved* → *Eligible after
  deduplication* → *Included*); 20 abstracts/PDFs read.
- Headline: "Yes … ~28–33%" reduction; **Consensus Meter Yes 94% / Possibly
  6% / Mixed 0% / No 0%, N = 17** with an on-page caveat that it "may not be
  a perfect reflection of the current science".
- "Evidence Strength | Claim" table labelled all three claims **Strong**,
  including a claim resting on real-world **observational** data.
- Reference rank 1 (Annals of Internal Medicine 2022 SR) has a key takeaway
  about adults **without diabetes** with heart failure and is counted **Yes**
  for a type 2 diabetes question; DAPA-HF (HFrEF regardless of diabetes) also
  counted Yes.
- At least 9 of the 17 voters are systematic reviews/meta-analyses of the
  same cardiovascular outcome trials, each counted as an **independent vote**.
- Per-paper badges: study type, "Rigorous Journal" (SciScore percentile),
  supporting-quote count, citation graph, cite.

Lessons (INFERRED): this is direct evidence for three SafeEvidence
invariants already in P00 — (1) PICO/population applicability must be
checked per source before it contributes; (2) reports/reviews are not
independent studies (Study/Report/overlap model, P00 Study Independence
Contract); (3) evidence strength must be design- and domain-specific, never
a label on a vote count. SafeEvidence will not ship a vote-count meter.

### 3.6 Epistemonikos (BROWSER_OBSERVED)

Observed: results faceted into Broad Syntheses (2), **Systematic Reviews
(118)**, Structured Summaries (0), Primary Studies (64) for one question;
RIS export per record; "Create your own Matrix (Beta)". A 2025 systematic
review first added **Dec 12, 2025** still showed "Evidence related with this
article: (not yet available)" with 0 linked primary studies on 2026-10-19.
Footer states database content is licensed **CC BY 3.0 Unported**; an API exists.

Lessons (INFERRED): the review↔primary-study matrix is the right model for
overlap control, but curation lag means SafeEvidence must compute overlap
itself from included-study lists (citation parsing + PMID/NCT linkage) and
show `OVERLAP_UNKNOWN` when it cannot. Epistemonikos content is a candidate
metadata source subject to attribution and terms review (P03 source-rights
row; not admitted).

### 3.7 DynaMed (REA_OBSERVED home; VENDOR_DOC)

Observed navigation: Dyna AI vs Classic Search, Recent Alerts, Specialties,
Drug Resources, Calculators, EBM, "Potentially Practice-Changing" filter,
CME. Vendor claims daily surveillance and topic-change alerts. Content is
subscription-gated; levels-of-evidence rendering not observed this run.

Lessons (INFERRED): "what changed" alerting and practice-changing flags map to
SafeEvidence's current-validity overlay (P03) and living surveillance (P18);
SafeEvidence surfaces *why* an answer's validity epoch changed (new trial,
retraction, guideline supersession) with source links.

## 4. Feature-by-feature competitor matrix

Legend: ● observed, ◐ vendor-documented only, ○ not found, ✕ blocked/not inspectable.
SafeEvidence column = **planned** (not built), with the owning work packet.

| Capability | OpenEvidence | Scite | Elicit | GRADEpro | Consensus | Epistemonikos | DynaMed | SafeEvidence plan (WP) |
|---|---|---|---|---|---|---|---|---|
| Natural-language clinical question → answer | ✕ (auth) | ◐ (login) | ✕ (auth) | ○ | ● | ○ | ◐ | WP-07..WP-12, WP-11a |
| Sentence/claim-level citation | ✕ | ● statement excerpts | ◐ | ○ | ● paper-level + quotes | ○ | ◐ | span-level `EvidenceSpan` + AnswerProofManifest (WP-08, WP-12) |
| Claim-to-span entailment check | ✕ | ○ (stance only) | ◐ | ○ | ○ | ○ | ○ | WP-08 verifier + SciFact/MultiVerS benchmarks |
| Evidence certainty grade | ◐ A–D/U | ○ | ○ | ◐ GRADE (human) | ● "Strong" labels | ○ | ◐ | GRADE-structured, per outcome, human-confirmed (WP-10) |
| Design-specific appraisal | ◐ | ○ | ○ | ◐ | ○ observed misuse | ○ | ◐ | design profiles RoB 2 / ROBINS-I / QUADAS / AMSTAR 2 structures (WP-10) |
| PICO applicability per source | ◐ relevance axis | ○ | ◐ | ◐ | ✕ observed failure | ○ | ◐ | WP-09 applicability gate |
| Study/report dedup & overlap | ○ | ○ | ◐ | ○ | ✕ observed failure | ● matrix (lagging) | ○ | WP-05 Study/Report model + overlap |
| Supporting/contrasting citation context | ○ | ● | ○ | ○ | ○ | ○ | ○ | discovery-only signal (F35, deferred); never changes support (WP-08) |
| Retraction/correction awareness | ○ | ◐ | ○ | ○ | ○ | ○ | ◐ | WP-04 Crossref/Retraction Watch overlay |
| Screening with reasons + PRISMA | ○ | ○ | ◐ | ○ | ● funnel counts | ○ | ○ | WP-14 (MedOrigin litdb + ASReview) |
| Structured extraction with quotes | ○ | ○ | ◐ | ○ | ○ | ○ | ○ | WP-15 (proposal-only extractors) |
| Meta-analysis | ○ | ○ | ○ | ◐ (imports) | ○ | ○ | ○ | WP-16 (statsmodels worker; refuse non-independent pooling) |
| SoF / EtD | ○ | ○ | ○ | ◐ | ○ | ○ | ○ | SoF export V1 (WP-10); EtD deferred |
| Living updates / alerts | ○ | ◐ | ◐ Routines | ○ | ○ | ○ | ◐ | WP-04 overlay + WP-17 surveillance |
| Abstain / unable-to-grade | ◐ U grade | ○ | ○ | ○ | ○ | ○ | ○ | first-class TerminalOutcome (WP-11a, WP-11) |
| Local-first / offline | ○ | ○ | ○ | ◐ "regardless of internet disruptions" | ○ | ○ | ◐ mobile app | core invariant (all WPs) |
| Arabic/English | ○ | ○ | ○ | ○ | ○ | ◐ multilingual | ◐ language selector | WP-06, WP-19 bilingual gates |
| Exportable reproducible audit | ○ | ◐ export | ◐ share link | ◐ | ◐ share | ● RIS | ○ | EvidenceSnapshot + export (WP-12, WP-14) |

## 5. Coverage gaps (explicit, not filled by inference)

1. OpenEvidence answer UX, citation rendering, EvidenceGrade display, follow-ups — requires a legitimately verified clinician account (founder/clinician-operated).
2. Elicit Research Agent, screening/extraction UI, PRISMA output — requires an Elicit account.
3. GRADEpro GDT project/SoF/EtD editing — requires a GRADEpro account.
4. Scite assistant and alerts — requires login.
5. DynaMed topic pages, levels-of-evidence labels, Dyna AI — requires subscription.
6. Consensus Medical Mode and Deep Search with filters — not run (one Pro query only, to avoid usage-limit side effects).

These are tracked as **REA-FOLLOWUP-01..06** in `docs/PLAN_FREEZE.md`; none
blocks the architecture freeze because SafeEvidence's differentiators are
defined by its own contracts, not by competitor internals.

## 6. What SafeEvidence should reproduce or improve (traceable)

| # | Requirement | Evidence | WP |
|---|---|---|---|
| L1 | Gradeability gate + explicit unable-to-grade outcome | R-OE-3 | WP-10, WP-11 |
| L2 | Design ceiling relative to question type, with per-domain reasons | R-OE-3, R-GP-2 | WP-10 |
| L3 | Never count overlapping reviews/reports as independent | R-CO-2, R-EP-2 | WP-05 |
| L4 | Per-source PICO applicability before contribution | R-CO-2 | WP-09 |
| L5 | No vote-count meter; categorical, reasoned outcome | R-CO-2 | WP-11, WP-18 |
| L6 | Citation stance is discovery only | R-SC-2 | WP-08 (rule); F35 deferred signal |
| L7 | Retrieval funnel counts shown with every answer | R-CO-2, R-EL-3 | WP-07, WP-12 |
| L8 | Screening log with reasons, PRISMA counts, shareable audit | R-EL-3 | WP-14 |
| L9 | Quote-backed extraction, proposals until confirmed | R-EL-3 | WP-15 |
| L10 | Change alerts tied to validity epochs | R-DY-2, R-EL-1 | WP-04, WP-17 |
| L11 | GRADE/SoF structures aligned to EBMonFHIR for export | R-GP-2 | WP-10 |
