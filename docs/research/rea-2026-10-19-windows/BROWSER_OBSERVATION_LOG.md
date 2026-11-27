# Browser observation log — 2026-10-19

Contemporaneous notes written by the agent while observing the pages in the
Claude desktop built-in browser (anonymous, no sign-in). Full page text and
screenshots are intentionally **not** redistributed here because they contain
third-party copyrighted summaries and paper text; every observation can be
re-run from the recorded URLs and query. Counts and labels below were read
from the rendered page/accessibility tree at observation time.

2026-10-19 built-in browser (Claude desktop pane), anonymous, Windows host.
OpenEvidence https://www.openevidence.com/ : landing renders "Ask a medical question" box; submitting the SGLT2/HF population question redirected to https://auth.openevidence.com (Sign Up). Headless REA capture got DataDome CAPTCHA. => auth-gated; no answer observed.
Consensus: query "Do SGLT2 inhibitors reduce hospitalization for heart failure in adults with type 2 diabetes?" -> https://consensus.app/search/do-sglt2-inhibitors-reduce-hospitalization-for-hea/BbOslbq7T76xgA31MbwlVA/
 - Pro mode, 4 steps; funnel Retrieved/Eligible/Included counts shown (PRISMA-like).
 - Meter: Yes 94% Possibly 6% Mixed 0% No 0%, N=17; caveat text shown.
 - Answer headline: ~28-33% reduction; table "Evidence Strength | Claim" labels all 3 claims Strong, including a claim from real-world observational data.
 - Reference list rank 1: Zou 2022 Ann Intern Med, takeaway about adults WITHOUT diabetes -> counted Yes.
 - Rank 12 DAPA-HF (HFrEF regardless of diabetes) counted Yes; rank 8 DELIVER Unknown.
 - >=9 of 17 are systematic reviews/meta-analyses of overlapping CVOTs; each counted as a separate vote.
 - Per-paper badges: study type (Meta-Analysis), "Rigorous Journal" (SciScore), N supporting quotes, Explore graph, Cite.
Scite (headless REA 403; real browser pane loads anonymously): https://scite.ai/reports/10.1056/nejmoa1504720 -> /reports/empagliflozin-cardiovascular-outcomes-and-mortality-NyAPrP (EMPA-REG OUTCOME, NEJM 2015)
 - Facets: Citation Types Supporting 341 / Mentioning 11,278 / Contrasting 32 / Unclassified 623; Paper Sections (Introduction 2,264, Discussion 1,651, Results 287, Other 9,959); Relationship Self Cite 182 / Independent 12,641; Publication types incl. Preprint 304; "Cited by 12,800 publications (12,274 citation statements)".
 - Each citation statement: excerpt, section, label (supporting/contrasting/mentioning), per-statement "confidence: NN%".
 - Top "contrasting" (99%) statements: (a) Scholtes 2019 post hoc analysis contrasts a hypothesized RASi synergy in "previous literature", not the EMPA-REG primary result; (b) Ku 2021 open-label single-centre observational study notes no CV mortality difference while stating it was not designed/powered for CV outcomes.
 => observed: "contrasting" label = citing-sentence stance, not evidence-weighted refutation of the cited finding; small underpowered designs appear as contrasts.
 - "Summarize citations" / "Help me understand this report" assistant entry points; Export report; Add to collection; Log In / Start Free Trial gating for assistant.
Epistemonikos (headless REA 403; real browser loads anonymously): search "sglt2 heart failure hospitalization type 2 diabetes"
 - Category facets: Broad Syntheses (2), Systematic Reviews (118), Structured Summaries (0), Primary Studies (64); 184 results; per-record RIS export; "Without references" vs "Loading references information".
 - => 118 indexed systematic reviews for one question: demonstrates redundant overlapping reviews that must not be counted as independent evidence.
 - Document 2ca75f7c1b8e81fa39cf92fa48ae7b242cf2f88d (Joher 2025 Cureus SR/MA of six RCTs): "First added on: Dec 12, 2025"; "Evidence related with this article: (not yet available)" with 0 broad syntheses / 0 SRs / 0 primary studies linked; "Create your own Matrix Beta".
 - => observed curation lag: review-to-primary-study links absent ~10 months after addition.
 - Footer: database licensed CC BY 3.0 Unported; Epistemonikos API; Multilinguality; Terms acceptance banner (not accepted).
