// Bilingual English and Arabic UI catalogue and RTL/LTR keyboard navigation helpers (WP-19 / TA-22).
// Arabic literals are encoded as ASCII Unicode escapes to preserve repository source hygiene.

import { FUNNEL_STAGES, OUTCOMES, REASONS, type Funnel, type Outcome, type Reason } from "./ask-view.ts";
import { CERTAINTY_LEVELS, type CertaintyKey } from "./workstation-types.ts";

export type Locale = "en" | "ar";
export type WorkstationTab = "ask" | "evidence" | "review" | "packs" | "privacy";

export const WORKSTATION_TABS: readonly WorkstationTab[] = [
  "ask",
  "evidence",
  "review",
  "packs",
  "privacy",
];

export function directionForLocale(locale: Locale): "ltr" | "rtl" {
  return locale === "ar" ? "rtl" : "ltr";
}

/**
 * WAI-ARIA tablist keyboard movement: in LTR `ArrowRight` advances and `ArrowLeft` moves back;
 * in RTL `ArrowLeft` advances and `ArrowRight` moves back.
 */
export function nextTabForKey(
  current: WorkstationTab,
  key: string,
  dir: "ltr" | "rtl",
): WorkstationTab | null {
  const index = WORKSTATION_TABS.indexOf(current);
  if (index < 0) return null;
  if (key === "Home") return WORKSTATION_TABS[0] ?? null;
  if (key === "End") return WORKSTATION_TABS[WORKSTATION_TABS.length - 1] ?? null;
  const forwardKey = dir === "rtl" ? "ArrowLeft" : "ArrowRight";
  const backwardKey = dir === "rtl" ? "ArrowRight" : "ArrowLeft";
  if (key === forwardKey) {
    return WORKSTATION_TABS[(index + 1) % WORKSTATION_TABS.length] ?? null;
  }
  if (key === backwardKey) {
    return WORKSTATION_TABS[(index - 1 + WORKSTATION_TABS.length) % WORKSTATION_TABS.length] ?? null;
  }
  return null;
}

export type UiCatalogue = {
  skipToMain: string;
  askHeading: string;
  workstationHeading: string;
  sectionsNavLabel: string;
  switchLocaleButton: string;
  fixtureNotice: string;
  tabs: Record<WorkstationTab, string>;
  questionLabel: string;
  checkingButton: string;
  askButton: string;
  failurePrefix: string;
  askedLabel: string;
  alreadyCommitted: string;
  justCommitted: string;
  citationsHeading: string;
  showCitedSpanPrefix: string;
  sourceHeadingPrefix: string;
  versionPrefix: string;
  traceHeading: string;
  excludedHeading: string;
  loadingOverview: string;
  evidenceHeading: string;
  totalDocsLabel: string;
  independentStudiesLabel: string;
  colDocId: string;
  colStudyId: string;
  colPopulation: string;
  colStanding: string;
  colRights: string;
  colDigest: string;
  reviewHeading: string;
  protocolHeading: string;
  protocolVersionLabel: string;
  auditEventsLabel: string;
  spanAuditLabel: string;
  offsetProjectionLabel: string;
  extractionsHeading: string;
  colOutcome: string;
  colEstimate: string;
  colSpan: string;
  colState: string;
  colQuote: string;
  appraisalHeading: string;
  certaintyLabel: string;
  packsHeading: string;
  validityEpochLabel: string;
  rightsGrantLabel: string;
  packIdLabel: string;
  admissibleDocsHeading: string;
  excludedPackHeading: string;
  privacyHeading: string;
  networkPostureLabel: string;
  httpClientsLabel: string;
  vaultDomainLabel: string;
  schemaDigestLabel: string;
  storeEstablishedLabel: string;
  recordDoctorLabel: string;
  mimeQuarantineLabel: string;
  recoveryEnvelopeLabel: string;
  privateDataReadyLabel: string;
  residualRiskHeading: string;
  incognitoDefaultLabel: string;
  outboundOptInLabel: string;
  clinicalAuthorizedLabel: string;
  yesValue: string;
  noValue: string;
  outcomes: Record<Outcome, string>;
  reasons: Record<Reason, string>;
  funnelLabels: Record<keyof Funnel, string>;
  certaintyLevels: Record<CertaintyKey, string>;
};

const EN_FUNNEL = Object.fromEntries(FUNNEL_STAGES) as Record<keyof Funnel, string>;

export const UI_TEXT: Record<Locale, UiCatalogue> = {
  en: {
    skipToMain: "Skip to main content",
    askHeading: "SafeEvidence Ask",
    workstationHeading: "SafeEvidence Workstation",
    sectionsNavLabel: "Workstation views",
    switchLocaleButton: "\u0627\u0644\u0639\u0631\u0628\u064A\u0629 (RTL)",
    fixtureNotice: "Invented engineering fixture. Not medical information.",
    tabs: {
      ask: "Ask",
      evidence: "Evidence & Sources",
      review: "Deep Review",
      packs: "Packs & Validity",
      privacy: "Privacy & Diagnostics",
    },
    questionLabel: "Question",
    checkingButton: "Checking",
    askButton: "Ask",
    failurePrefix: "No answer is shown: ",
    askedLabel: "Asked: ",
    alreadyCommitted: "Already committed as proof",
    justCommitted: "Just committed as proof",
    citationsHeading: "Citations",
    showCitedSpanPrefix: "Show the cited span in ",
    sourceHeadingPrefix: "Source ",
    versionPrefix: ", version ",
    traceHeading: "What was considered",
    excludedHeading: "Excluded",
    loadingOverview: "Loading verified workstation state...",
    evidenceHeading: "Canonical Evidence & Study Registry",
    totalDocsLabel: "Corpus reports",
    independentStudiesLabel: "Active independent primary studies",
    colDocId: "Report ID",
    colStudyId: "Study ID",
    colPopulation: "Population",
    colStanding: "Standing",
    colRights: "Rights",
    colDigest: "SHA-256 prefix",
    reviewHeading: "Deep Review Protocol, Extraction & GRADE Appraisal",
    protocolHeading: "Locked Review Protocol",
    protocolVersionLabel: "Protocol version",
    auditEventsLabel: "Hash-chained audit events",
    spanAuditLabel: "Opaque span-overlap audit",
    offsetProjectionLabel: "Verified scalar-offset adapter formats",
    extractionsHeading: "Quote-Anchored Structured Extractions",
    colOutcome: "Outcome",
    colEstimate: "Anchored estimate",
    colSpan: "Scalar span",
    colState: "Governance state",
    colQuote: "Verbatim source quote",
    appraisalHeading: "GRADE Summary of Findings",
    certaintyLabel: "GRADE certainty",
    packsHeading: "Offline Evidence Packs & Validity Epoch",
    validityEpochLabel: "Active validity epoch",
    rightsGrantLabel: "Rights grant version",
    packIdLabel: "Admissible pack manifest",
    admissibleDocsHeading: "Admitted into offline pack",
    excludedPackHeading: "Excluded from pack build",
    privacyHeading: "Local-First Privacy & Trust Posture",
    networkPostureLabel: "Runtime network mode",
    httpClientsLabel: "Core HTTP client libraries present",
    vaultDomainLabel: "Vault cryptographic domain",
    schemaDigestLabel: "Proof-store schema digest",
    storeEstablishedLabel: "Encrypted local vault established",
    recordDoctorLabel: "Append-only record-semantics doctor verified",
    mimeQuarantineLabel: "Hostile-MIME magic-byte quarantine active",
    recoveryEnvelopeLabel: "Argon2id recovery envelope enrolled",
    privateDataReadyLabel: "Private-data readiness authorized",
    residualRiskHeading: "Open OS-level residual-risk classes",
    incognitoDefaultLabel: "Ephemeral WebView profile default",
    outboundOptInLabel: "Saved-query outbound surveillance opt-in",
    clinicalAuthorizedLabel: "Clinical patient-care use authorized",
    yesValue: "Yes",
    noValue: "No",
    outcomes: OUTCOMES,
    reasons: REASONS,
    funnelLabels: EN_FUNNEL,
    certaintyLevels: CERTAINTY_LEVELS,
  },
  ar: {
    skipToMain: "\u0627\u0644\u0627\u0646\u062A\u0642\u0627\u0644 \u0625\u0644\u0649 \u0627\u0644\u0645\u062D\u062A\u0648\u0649 \u0627\u0644\u0631\u0626\u064A\u0633\u064A",
    askHeading: "SafeEvidence \u2014 \u0627\u0644\u0627\u0633\u062A\u0639\u0644\u0627\u0645",
    workstationHeading: "SafeEvidence \u2014 \u0645\u062D\u0637\u0629 \u0627\u0644\u0623\u062F\u0644\u0629",
    sectionsNavLabel: "\u0623\u0642\u0633\u0627\u0645 \u0645\u062D\u0637\u0629 \u0627\u0644\u0639\u0645\u0644",
    switchLocaleButton: "English (LTR)",
    fixtureNotice: "\u0628\u064A\u0627\u0646\u0627\u062A \u0627\u062E\u062A\u0628\u0627\u0631 \u0647\u0646\u062F\u0633\u064A\u0629 \u0645\u062E\u062A\u0644\u0642\u0629. \u0644\u064A\u0633\u062A \u0645\u0639\u0644\u0648\u0645\u0627\u062A \u0637\u0628\u064A\u0629.",
    tabs: {
      ask: "\u0627\u0644\u0627\u0633\u062A\u0639\u0644\u0627\u0645",
      evidence: "\u0627\u0644\u0623\u062F\u0644\u0629 \u0648\u0627\u0644\u0645\u0635\u0627\u062F\u0631",
      review: "\u0627\u0644\u0645\u0631\u0627\u062C\u0639\u0629 \u0627\u0644\u0645\u0639\u0645\u0642\u0629",
      packs: "\u0627\u0644\u062D\u0632\u0645 \u0648\u0627\u0644\u0635\u0644\u0627\u062D\u064A\u0629",
      privacy: "\u0627\u0644\u062E\u0635\u0648\u0635\u064A\u0629 \u0648\u0627\u0644\u062A\u0634\u062E\u064A\u0635",
    },
    questionLabel: "\u0627\u0644\u0633\u0624\u0627\u0644",
    checkingButton: "\u062C\u0627\u0631\u064D \u0627\u0644\u062A\u062D\u0642\u0642",
    askButton: "\u0627\u0633\u0623\u0644",
    failurePrefix: "\u0644\u0645 \u064A\u062A\u0645 \u0639\u0631\u0636 \u0625\u062C\u0627\u0628\u0629: ",
    askedLabel: "\u0627\u0644\u0633\u0624\u0627\u0644 \u0627\u0644\u0645\u0637\u0631\u0648\u062D: ",
    alreadyCommitted: "\u0645\u062B\u0628\u062A \u0645\u0633\u0628\u0642\u0627\u064B \u0643\u0625\u062B\u0628\u0627\u062A",
    justCommitted: "\u062A\u0645 \u062A\u062B\u0628\u064A\u062A\u0647 \u0627\u0644\u0622\u0646 \u0643\u0625\u062B\u0628\u0627\u062A",
    citationsHeading: "\u0627\u0644\u0627\u0633\u062A\u0634\u0647\u0627\u062F\u0627\u062A",
    showCitedSpanPrefix: "\u0625\u0638\u0647\u0627\u0631 \u0627\u0644\u0645\u0642\u0637\u0639 \u0627\u0644\u0645\u0642\u062A\u0628\u0633 \u0641\u064A ",
    sourceHeadingPrefix: "\u0627\u0644\u0645\u0635\u062F\u0631 ",
    versionPrefix: "\u060C \u0627\u0644\u0625\u0635\u062F\u0627\u0631 ",
    traceHeading: "\u0645\u0627 \u062A\u0645 \u0641\u062D\u0635\u0647",
    excludedHeading: "\u0627\u0644\u0645\u0633\u062A\u0628\u0639\u062F\u0627\u062A",
    loadingOverview: "\u062C\u0627\u0631\u064D \u062A\u062D\u0645\u064A\u0644 \u062D\u0627\u0644\u0629 \u0645\u062D\u0637\u0629 \u0627\u0644\u0639\u0645\u0644 \u0627\u0644\u0645\u0648\u062B\u0642\u0629...",
    evidenceHeading: "\u0633\u062C\u0644 \u0627\u0644\u0623\u062F\u0644\u0629 \u0648\u0627\u0644\u062F\u0631\u0627\u0633\u0627\u062A \u0627\u0644\u0645\u0639\u062A\u0645\u062F",
    totalDocsLabel: "\u0625\u062C\u0645\u0627\u0644\u064A \u0627\u0644\u062A\u0642\u0627\u0631\u064A\u0631",
    independentStudiesLabel: "\u0627\u0644\u062F\u0631\u0627\u0633\u0627\u062A \u0627\u0644\u0623\u0648\u0644\u064A\u0629 \u0627\u0644\u0645\u0633\u062A\u0642\u0644\u0629 \u0627\u0644\u0646\u0634\u0637\u0629",
    colDocId: "\u0645\u0639\u0631\u0641 \u0627\u0644\u062A\u0642\u0631\u064A\u0631",
    colStudyId: "\u0645\u0639\u0631\u0641 \u0627\u0644\u062F\u0631\u0627\u0633\u0629",
    colPopulation: "\u0627\u0644\u0641\u0626\u0629",
    colStanding: "\u062D\u0627\u0644\u0629 \u0627\u0644\u0646\u0634\u0631",
    colRights: "\u0627\u0644\u062D\u0642\u0648\u0642",
    colDigest: "\u0628\u0635\u0645\u0629 SHA-256",
    reviewHeading: "\u0628\u0631\u0648\u062A\u0648\u0643\u0648\u0644 \u0627\u0644\u0645\u0631\u0627\u062C\u0639\u0629 \u0648\u0627\u0644\u0627\u0633\u062A\u062E\u0644\u0627\u0635 \u0648\u062A\u0642\u064A\u064A\u0645 GRADE",
    protocolHeading: "\u0628\u0631\u0648\u062A\u0648\u0643\u0648\u0644 \u0627\u0644\u0645\u0631\u0627\u062C\u0639\u0629 \u0627\u0644\u0645\u0642\u0641\u0644",
    protocolVersionLabel: "\u0625\u0635\u062F\u0627\u0631 \u0627\u0644\u0628\u0631\u0648\u062A\u0648\u0643\u0648\u0644",
    auditEventsLabel: "\u0623\u062D\u062F\u0627\u062B \u0627\u0644\u062A\u062F\u0642\u064A\u0642 \u0627\u0644\u0645\u062A\u0633\u0644\u0633\u0644\u0629",
    spanAuditLabel: "\u062A\u062F\u0642\u064A\u0642 \u062A\u062F\u0627\u062E\u0644 \u0627\u0644\u0646\u0637\u0627\u0642\u0627\u062A \u0627\u0644\u0645\u0639\u062A\u0645",
    offsetProjectionLabel: "\u0635\u064A\u063A \u0645\u062D\u0648\u0644\u0627\u062A \u0627\u0644\u0625\u0632\u0627\u062D\u0629 \u0627\u0644\u0645\u062A\u062D\u0642\u0642 \u0645\u0646\u0647\u0627",
    extractionsHeading: "\u0627\u0644\u0627\u0633\u062A\u062E\u0644\u0627\u0635\u0627\u062A \u0627\u0644\u0645\u0631\u062A\u0628\u0637\u0629 \u0628\u0627\u0642\u062A\u0628\u0627\u0633 \u062D\u0631\u0641\u064A",
    colOutcome: "\u0627\u0644\u0646\u062A\u064A\u062C\u0629",
    colEstimate: "\u0627\u0644\u062A\u0642\u062F\u064A\u0631 \u0627\u0644\u0645\u0648\u062B\u0642",
    colSpan: "\u0627\u0644\u0646\u0637\u0627\u0642 \u0627\u0644\u062D\u0631\u0641\u064A",
    colState: "\u062D\u0627\u0644\u0629 \u0627\u0644\u0627\u0639\u062A\u0645\u0627\u062F",
    colQuote: "\u0627\u0644\u0627\u0642\u062A\u0628\u0627\u0633 \u0627\u0644\u062D\u0631\u0641\u064A",
    appraisalHeading: "\u0645\u0644\u062E\u0635 \u0627\u0644\u0646\u062A\u0627\u0626\u062C \u0648\u064A\u0642\u064A\u0646 GRADE",
    certaintyLabel: "\u0645\u0633\u062A\u0648\u0649 \u064A\u0642\u064A\u0646 GRADE",
    packsHeading: "\u062D\u0632\u0645 \u0627\u0644\u0623\u062F\u0644\u0629 \u0627\u0644\u0645\u062D\u0644\u064A\u0629 \u0648\u062D\u0642\u0628\u0629 \u0627\u0644\u0635\u0644\u0627\u062D\u064A\u0629",
    validityEpochLabel: "\u062D\u0642\u0628\u0629 \u0627\u0644\u0635\u0644\u0627\u062D\u064A\u0629 \u0627\u0644\u0646\u0634\u0637\u0629",
    rightsGrantLabel: "\u0625\u0635\u062F\u0627\u0631 \u062A\u0635\u0631\u064A\u062D \u0627\u0644\u062D\u0642\u0648\u0642",
    packIdLabel: "\u0628\u064A\u0627\u0646 \u0627\u0644\u062D\u0632\u0645\u0629 \u0627\u0644\u0645\u0642\u0628\u0648\u0644\u0629",
    admissibleDocsHeading: "\u0627\u0644\u062A\u0642\u0627\u0631\u064A\u0631 \u0627\u0644\u0645\u0642\u0628\u0648\u0644\u0629 \u0641\u064A \u0627\u0644\u062D\u0632\u0645\u0629",
    excludedPackHeading: "\u0627\u0644\u0645\u0633\u062A\u0628\u0639\u062F \u0645\u0646 \u0628\u0646\u0627\u0621 \u0627\u0644\u062D\u0632\u0645\u0629",
    privacyHeading: "\u0627\u0644\u062E\u0635\u0648\u0635\u064A\u0629 \u0627\u0644\u0645\u062D\u0644\u064A\u0629 \u0648\u062D\u062F\u0648\u062F \u0627\u0644\u062B\u0642\u0629",
    networkPostureLabel: "\u0648\u0636\u0639 \u0627\u0644\u0634\u0628\u0643\u0629 \u0623\u062B\u0646\u0627\u0621 \u0627\u0644\u062A\u0634\u063A\u064A\u0644",
    httpClientsLabel: "\u0648\u062C\u0648\u062F \u0639\u0645\u0644\u0627\u0621 HTTP \u0641\u064A \u0627\u0644\u0646\u0648\u0627\u0629",
    vaultDomainLabel: "\u0646\u0637\u0627\u0642 \u062A\u0634\u0641\u064A\u0631 \u0627\u0644\u062E\u0632\u0646\u0629",
    schemaDigestLabel: "\u0628\u0635\u0645\u0629 \u0645\u062E\u0637\u0637 \u0645\u062E\u0632\u0646 \u0627\u0644\u0625\u062B\u0628\u0627\u062A",
    storeEstablishedLabel: "\u062A\u0623\u0633\u064A\u0633 \u0627\u0644\u062E\u0632\u0646\u0629 \u0627\u0644\u0645\u062D\u0644\u064A\u0629 \u0627\u0644\u0645\u0634\u0641\u0631\u0629",
    recordDoctorLabel: "\u0627\u062C\u062A\u064A\u0627\u0632 \u0641\u062D\u0635 \u0633\u0644\u0627\u0645\u0629 \u0627\u0644\u0633\u062C\u0644\u0627\u062A \u063A\u064A\u0631 \u0627\u0644\u0642\u0627\u0628\u0644\u0629 \u0644\u0644\u062A\u0639\u062F\u064A\u0644",
    mimeQuarantineLabel: "\u062A\u0641\u0639\u064A\u0644 \u0639\u0632\u0644 \u0627\u0644\u0645\u0644\u0641\u0627\u062A \u0627\u0644\u062E\u0628\u064A\u062B\u0629",
    recoveryEnvelopeLabel: "\u062A\u0633\u062C\u064A\u0644 \u0645\u0638\u0631\u0648\u0641 \u0627\u0644\u0627\u0633\u062A\u0631\u062F\u0627\u062F Argon2id",
    privateDataReadyLabel: "\u062C\u0627\u0647\u0632\u064A\u0629 \u0627\u0644\u0628\u064A\u0627\u0646\u0627\u062A \u0627\u0644\u062E\u0627\u0635\u0629 \u0645\u0639\u062A\u0645\u062F\u0629",
    residualRiskHeading: "\u0641\u0626\u0627\u062A \u0627\u0644\u0645\u062E\u0627\u0637\u0631 \u0627\u0644\u0645\u062A\u0628\u0642\u064A\u0629 \u0639\u0644\u0649 \u0645\u0633\u062A\u0648\u0649 \u0627\u0644\u0646\u0638\u0627\u0645",
    incognitoDefaultLabel: "\u0627\u0644\u0648\u0636\u0639 \u0627\u0644\u0645\u0624\u0642\u062A \u0644\u0639\u0627\u0631\u0636 \u0627\u0644\u0648\u064A\u0628",
    outboundOptInLabel: "\u0627\u0644\u0645\u0648\u0627\u0641\u0642\u0629 \u0627\u0644\u0627\u0641\u062A\u0631\u0627\u0636\u064A\u0629 \u0644\u0644\u0645\u062A\u0627\u0628\u0639\u0629 \u0627\u0644\u062E\u0627\u0631\u062C\u064A\u0629",
    clinicalAuthorizedLabel: "\u0627\u0644\u062A\u0635\u0631\u064A\u062D \u0628\u0627\u0644\u0627\u0633\u062A\u062E\u062F\u0627\u0645 \u0627\u0644\u0633\u0631\u064A\u0631\u064A",
    yesValue: "\u0646\u0639\u0645",
    noValue: "\u0644\u0627",
    outcomes: {
      ANSWER: "\u0625\u062C\u0627\u0628\u0629",
      ANSWER_WITH_CAUTION: "\u0625\u062C\u0627\u0628\u0629 \u0645\u0639 \u062A\u0646\u0628\u064A\u0647",
      ASK_MORE: "\u064A\u0644\u0632\u0645 \u0645\u0632\u064A\u062F \u0645\u0646 \u0627\u0644\u0645\u0639\u0644\u0648\u0645\u0627\u062A",
      CONFLICT: "\u062A\u0639\u0627\u0631\u0636 \u0641\u064A \u0627\u0644\u0623\u062F\u0644\u0629",
      ABSTAIN: "\u0644\u0645 \u062A\u064F\u0642\u062F\u0651\u064E\u0645 \u0625\u062C\u0627\u0628\u0629",
      ESCALATE: "\u064A\u062A\u0637\u0644\u0628 \u0645\u0631\u0627\u062C\u0639\u0629 \u0627\u0644\u0637\u0628\u064A\u0628",
      BLOCKED: "\u0645\u062D\u062C\u0648\u0628",
    },
    reasons: {
      SECURITY_DENIED: "\u0631\u0641\u0636\u062A \u0633\u064A\u0627\u0633\u0629 \u0627\u0644\u0623\u0645\u0627\u0646 \u0647\u0630\u0627 \u0627\u0644\u0637\u0644\u0628.",
      RIGHTS_UNRESOLVED: "\u062D\u0642\u0648\u0642 \u0627\u0633\u062A\u062E\u062F\u0627\u0645 \u0627\u0644\u0645\u0635\u062F\u0631 \u063A\u064A\u0631 \u0645\u062B\u0628\u062A\u0629.",
      SOURCE_UNAVAILABLE: "\u0623\u062D\u062F \u0627\u0644\u0645\u0635\u0627\u062F\u0631 \u0627\u0644\u0645\u0637\u0644\u0648\u0628\u0629 \u063A\u064A\u0631 \u0645\u062A\u0627\u062D.",
      SOURCE_INVALID_OR_RETRACTED: "\u0623\u062D\u062F \u0627\u0644\u0645\u0635\u0627\u062F\u0631 \u0627\u0644\u0645\u0637\u0644\u0648\u0628\u0629 \u063A\u064A\u0631 \u0635\u0627\u0644\u062D \u0623\u0648 \u0645\u0633\u062D\u0648\u0628.",
      EVIDENCE_INSUFFICIENT: "\u062A\u0639\u0630\u0631\u062A \u0627\u0644\u0625\u062C\u0627\u0628\u0629 \u0645\u0646 \u0627\u0644\u0623\u062F\u0644\u0629 \u0627\u0644\u0645\u062A\u0627\u062D\u0629.",
      MISSING_CRITICAL_CONTEXT: "\u064A\u0646\u0642\u0635 \u0627\u0644\u0633\u0624\u0627\u0644 \u0633\u064A\u0627\u0642 \u062C\u0648\u0647\u0631\u064A \u0645\u062B\u0644 \u0627\u0644\u0641\u0626\u0629 \u0627\u0644\u0633\u0643\u0627\u0646\u064A\u0629.",
      APPLICABILITY_UNRESOLVED: "\u0642\u062F \u0644\u0627 \u062A\u0646\u0637\u0628\u0642 \u0627\u0644\u0623\u062F\u0644\u0629 \u0639\u0644\u0649 \u0647\u0630\u0647 \u0627\u0644\u0641\u0626\u0629.",
      MATERIAL_CONTRADICTION: "\u062A\u062A\u0639\u0627\u0631\u0636 \u0627\u0644\u0645\u0635\u0627\u062F\u0631 \u0641\u064A \u0646\u0642\u0637\u0629 \u062C\u0648\u0647\u0631\u064A\u0629.",
      TOOL_FAILURE: "\u062A\u0639\u0630\u0631 \u0625\u062A\u0645\u0627\u0645 \u062E\u0637\u0648\u0629 \u0645\u0637\u0644\u0648\u0628\u0629 \u0644\u0630\u0644\u0643 \u0644\u0645 \u062A\u064F\u0639\u0631\u0636 \u0625\u062C\u0627\u0628\u0629.",
      TIME_BUDGET_EXHAUSTED: "\u0627\u0646\u062A\u0647\u062A \u0627\u0644\u0645\u0647\u0644\u0629 \u0627\u0644\u0632\u0645\u0646\u064A\u0629 \u0627\u0644\u0645\u062D\u062F\u062F\u0629.",
      CLINICIAN_AUTHORITY_REQUIRED: "\u064A\u062A\u0637\u0644\u0628 \u0647\u0630\u0627 \u0642\u0631\u0627\u0631 \u0637\u0628\u064A\u0628 \u0645\u062E\u062A\u0635.",
      POST_VERIFICATION_FAILED: "\u0641\u0634\u0644 \u0627\u0644\u062A\u062D\u0642\u0642 \u0645\u0646 \u0627\u0644\u0625\u062C\u0627\u0628\u0629 \u0644\u0630\u0644\u0643 \u0644\u0645 \u062A\u064F\u0639\u0631\u0636.",
      PROOF_RACE_INVALIDATED: "\u062A\u063A\u064A\u0631\u062A \u0627\u0644\u0635\u0644\u0627\u062D\u064A\u0629 \u0623\u062B\u0646\u0627\u0621 \u0627\u0644\u062A\u062D\u0642\u0642 \u0644\u0630\u0644\u0643 \u062D\u064F\u062C\u0628\u062A \u0627\u0644\u0625\u062C\u0627\u0628\u0629.",
      CURRENTNESS_UNKNOWN: "\u062D\u062F\u0627\u062B\u0629 \u0647\u0630\u0647 \u0627\u0644\u0625\u062C\u0627\u0628\u0629 \u063A\u064A\u0631 \u0645\u0639\u0631\u0648\u0641\u0629.",
      UNSUPPORTED_LANGUAGE: "\u0647\u0630\u0647 \u0627\u0644\u0644\u063A\u0629 \u063A\u064A\u0631 \u0645\u0641\u0639\u0644\u0629 \u0641\u064A \u0645\u0633\u0627\u0631 \u0627\u0644\u0627\u0633\u062A\u0639\u0644\u0627\u0645 \u0628\u0639\u062F.",
      NONE: "",
    },
    funnelLabels: {
      indexed: "\u0645\u0641\u0647\u0631\u0633",
      retrieved: "\u0645\u0633\u062A\u0631\u062C\u0639",
      citable: "\u0642\u0627\u0628\u0644 \u0644\u0644\u0627\u0633\u062A\u0634\u0647\u0627\u062F",
      rightsAdmissible: "\u0645\u0642\u0628\u0648\u0644 \u0627\u0644\u062D\u0642\u0648\u0642",
      applicable: "\u0645\u0646\u0637\u0628\u0642",
      independentStudies: "\u062F\u0631\u0627\u0633\u0627\u062A \u0645\u0633\u062A\u0642\u0644\u0629",
      verifiedClaims: "\u0627\u062F\u0639\u0627\u0621\u0627\u062A \u0645\u062A\u062D\u0642\u0642 \u0645\u0646\u0647\u0627",
    },
    certaintyLevels: {
      VERY_LOW: "\u0645\u0646\u062E\u0641\u0636 \u062C\u062F\u0627\u064B",
      LOW: "\u0645\u0646\u062E\u0641\u0636",
      MODERATE: "\u0645\u062A\u0648\u0633\u0637",
      HIGH: "\u0645\u0631\u062A\u0641\u0639",
    },
  },
};
