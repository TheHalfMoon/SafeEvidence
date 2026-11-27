// Trusted-backend projections for the Evidence, Deep Review, Packs, and Privacy panes.
// Rejects any mismatched or incomplete payload fail-closed.

import { REASONS, type ExcludedItem, type Reason } from "./ask-view.ts";

export const CERTAINTY_LEVELS = {
  VERY_LOW: "Very low",
  LOW: "Low",
  MODERATE: "Moderate",
  HIGH: "High",
} as const;
export type CertaintyKey = keyof typeof CERTAINTY_LEVELS;

export type SourceRecord = {
  docId: string;
  studyId: string;
  title: string;
  population: string;
  condition: string;
  intervention: string;
  publicationState: string;
  rights: string;
  citable: boolean;
  rightsAdmissible: boolean;
  scalarCount: number;
  sourceDigestPrefix: string;
};

export type EvidencePane = {
  corpusDescription: string;
  totalDocuments: number;
  activeIndependentStudies: number;
  sources: SourceRecord[];
};

export type ExtractionRow = {
  extractionId: string;
  studyId: string;
  sourceId: string;
  outcomeLabel: string;
  measureKind: string;
  pointEstimateText: string;
  timepoint: string;
  quoteText: string;
  startScalar: number;
  endScalar: number;
  workflowState: "PROPOSED" | "CONFIRMED" | "REJECTED";
  actorLabel: string;
};

export type DeepReviewPane = {
  protocolId: string;
  protocolTitle: string;
  protocolVersion: number;
  protocolDigestPrefix: string;
  auditEventCount: number;
  auditBundleDigestPrefix: string;
  spanAuditSpanCount: number;
  spanAuditOverlapCount: number;
  spanAuditFingerprintPrefix: string;
  offsetProjectionFormatsVerified: number;
  extractions: ExtractionRow[];
  certaintyOutcome: string;
  certaintyLevel: CertaintyKey;
  certaintyStatus: "PROPOSED" | "CONFIRMED";
  certaintyReasons: string[];
  externalWorkerGate: string;
};

export type PacksValidityPane = {
  validityEpoch: number;
  rightsGrantVersion: string;
  packId: string;
  packDigestPrefix: string;
  admissiblePackDocIds: string[];
  excludedFromPack: ExcludedItem[];
  signedPackGate: string;
};

export type PrivacyDiagnosticsPane = {
  networkPosture: "NETWORK_LOCKED";
  coreHttpClientsPresent: false;
  vaultDomainVersion: string;
  schemaDigestPrefix: string;
  storeEstablished: boolean;
  recordSemanticsDoctorPassed: boolean;
  hostileMimeQuarantineActive: boolean;
  recoveryEnvelopeEnrolled: boolean;
  privateDataReady: false;
  openResidualRiskClasses: string[];
  webviewIncognitoDefault: boolean;
  outboundSurveillanceDefaultOptIn: false;
  clinicalUseAuthorized: false;
};

export type WorkstationOverview = {
  schemaVersion: 1;
  fixtureOnly: true;
  evidence: EvidencePane;
  deepReview: DeepReviewPane;
  packsAndValidity: PacksValidityPane;
  privacyAndDiagnostics: PrivacyDiagnosticsPane;
};

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);
const isCount = (value: unknown): value is number =>
  Number.isSafeInteger(value) && (value as number) >= 0;
const isNonEmptyString = (value: unknown): value is string =>
  typeof value === "string" && value.trim().length > 0;

function parseExcluded(value: unknown): ExcludedItem {
  if (
    !isRecord(value) ||
    !isNonEmptyString(value.docId) ||
    typeof value.reasonCode !== "string" ||
    !Object.hasOwn(REASONS, value.reasonCode) ||
    value.reasonCode === "NONE" ||
    !isNonEmptyString(value.reason)
  ) {
    throw new Error("Invalid pack exclusion");
  }
  return {
    docId: value.docId,
    reasonCode: value.reasonCode as Exclude<Reason, "NONE">,
    reason: value.reason,
  };
}

function parseSourceRecord(value: unknown): SourceRecord {
  if (!isRecord(value)) throw new Error("Invalid source record");
  const {
    docId,
    studyId,
    title,
    population,
    condition,
    intervention,
    publicationState,
    rights,
    citable,
    rightsAdmissible,
    scalarCount,
    sourceDigestPrefix,
  } = value;
  if (
    !isNonEmptyString(docId) ||
    !isNonEmptyString(studyId) ||
    !isNonEmptyString(title) ||
    !isNonEmptyString(population) ||
    !isNonEmptyString(condition) ||
    !isNonEmptyString(intervention) ||
    !isNonEmptyString(publicationState) ||
    !isNonEmptyString(rights) ||
    typeof citable !== "boolean" ||
    typeof rightsAdmissible !== "boolean" ||
    !isCount(scalarCount) ||
    scalarCount === 0 ||
    !isNonEmptyString(sourceDigestPrefix)
  ) {
    throw new Error("Invalid source record");
  }
  return {
    docId,
    studyId,
    title,
    population,
    condition,
    intervention,
    publicationState,
    rights,
    citable,
    rightsAdmissible,
    scalarCount,
    sourceDigestPrefix,
  };
}

function parseExtractionRow(value: unknown): ExtractionRow {
  if (!isRecord(value)) throw new Error("Invalid extraction row");
  const {
    extractionId,
    studyId,
    sourceId,
    outcomeLabel,
    measureKind,
    pointEstimateText,
    timepoint,
    quoteText,
    startScalar,
    endScalar,
    workflowState,
    actorLabel,
  } = value;
  if (
    !isNonEmptyString(extractionId) ||
    !isNonEmptyString(studyId) ||
    !isNonEmptyString(sourceId) ||
    !isNonEmptyString(outcomeLabel) ||
    !isNonEmptyString(measureKind) ||
    !isNonEmptyString(pointEstimateText) ||
    !isNonEmptyString(timepoint) ||
    !isNonEmptyString(quoteText) ||
    !isCount(startScalar) ||
    !isCount(endScalar) ||
    startScalar >= endScalar ||
    (workflowState !== "PROPOSED" && workflowState !== "CONFIRMED" && workflowState !== "REJECTED") ||
    !isNonEmptyString(actorLabel)
  ) {
    throw new Error("Invalid extraction row");
  }
  return {
    extractionId,
    studyId,
    sourceId,
    outcomeLabel,
    measureKind,
    pointEstimateText,
    timepoint,
    quoteText,
    startScalar,
    endScalar,
    workflowState,
    actorLabel,
  };
}

export function parseWorkstationOverview(value: unknown): WorkstationOverview {
  if (!isRecord(value) || value.schemaVersion !== 1 || value.fixtureOnly !== true) {
    throw new Error("Unsupported workstation overview");
  }
  const { evidence, deepReview, packsAndValidity, privacyAndDiagnostics } = value;
  if (
    !isRecord(evidence) ||
    !isRecord(deepReview) ||
    !isRecord(packsAndValidity) ||
    !isRecord(privacyAndDiagnostics)
  ) {
    throw new Error("Malformed workstation overview sections");
  }

  if (
    !isNonEmptyString(evidence.corpusDescription) ||
    !isCount(evidence.totalDocuments) ||
    !isCount(evidence.activeIndependentStudies) ||
    !Array.isArray(evidence.sources) ||
    evidence.sources.length !== evidence.totalDocuments
  ) {
    throw new Error("Invalid evidence pane");
  }

  if (
    !isNonEmptyString(deepReview.protocolId) ||
    !isNonEmptyString(deepReview.protocolTitle) ||
    !isCount(deepReview.protocolVersion) ||
    deepReview.protocolVersion === 0 ||
    !isNonEmptyString(deepReview.protocolDigestPrefix) ||
    !isCount(deepReview.auditEventCount) ||
    !isNonEmptyString(deepReview.auditBundleDigestPrefix) ||
    !isCount(deepReview.spanAuditSpanCount) ||
    deepReview.spanAuditSpanCount === 0 ||
    !isCount(deepReview.spanAuditOverlapCount) ||
    !isNonEmptyString(deepReview.spanAuditFingerprintPrefix) ||
    !isCount(deepReview.offsetProjectionFormatsVerified) ||
    deepReview.offsetProjectionFormatsVerified === 0 ||
    !Array.isArray(deepReview.extractions) ||
    !isNonEmptyString(deepReview.certaintyOutcome) ||
    typeof deepReview.certaintyLevel !== "string" ||
    !Object.hasOwn(CERTAINTY_LEVELS, deepReview.certaintyLevel) ||
    (deepReview.certaintyStatus !== "PROPOSED" && deepReview.certaintyStatus !== "CONFIRMED") ||
    !Array.isArray(deepReview.certaintyReasons) ||
    deepReview.certaintyReasons.length !== 8 ||
    !deepReview.certaintyReasons.every(isNonEmptyString) ||
    !isNonEmptyString(deepReview.externalWorkerGate)
  ) {
    throw new Error("Invalid deep review pane");
  }

  if (
    !isCount(packsAndValidity.validityEpoch) ||
    packsAndValidity.validityEpoch === 0 ||
    !isNonEmptyString(packsAndValidity.rightsGrantVersion) ||
    !isNonEmptyString(packsAndValidity.packId) ||
    !isNonEmptyString(packsAndValidity.packDigestPrefix) ||
    !Array.isArray(packsAndValidity.admissiblePackDocIds) ||
    !packsAndValidity.admissiblePackDocIds.every(isNonEmptyString) ||
    !Array.isArray(packsAndValidity.excludedFromPack) ||
    !isNonEmptyString(packsAndValidity.signedPackGate)
  ) {
    throw new Error("Invalid packs pane");
  }

  if (
    privacyAndDiagnostics.networkPosture !== "NETWORK_LOCKED" ||
    privacyAndDiagnostics.coreHttpClientsPresent !== false ||
    !isNonEmptyString(privacyAndDiagnostics.vaultDomainVersion) ||
    !isNonEmptyString(privacyAndDiagnostics.schemaDigestPrefix) ||
    typeof privacyAndDiagnostics.storeEstablished !== "boolean" ||
    typeof privacyAndDiagnostics.recordSemanticsDoctorPassed !== "boolean" ||
    typeof privacyAndDiagnostics.hostileMimeQuarantineActive !== "boolean" ||
    typeof privacyAndDiagnostics.recoveryEnvelopeEnrolled !== "boolean" ||
    privacyAndDiagnostics.privateDataReady !== false ||
    !Array.isArray(privacyAndDiagnostics.openResidualRiskClasses) ||
    privacyAndDiagnostics.openResidualRiskClasses.length === 0 ||
    !privacyAndDiagnostics.openResidualRiskClasses.every(isNonEmptyString) ||
    typeof privacyAndDiagnostics.webviewIncognitoDefault !== "boolean" ||
    privacyAndDiagnostics.outboundSurveillanceDefaultOptIn !== false ||
    privacyAndDiagnostics.clinicalUseAuthorized !== false
  ) {
    throw new Error("Invalid privacy pane");
  }

  return {
    schemaVersion: 1,
    fixtureOnly: true,
    evidence: {
      corpusDescription: evidence.corpusDescription,
      totalDocuments: evidence.totalDocuments,
      activeIndependentStudies: evidence.activeIndependentStudies,
      sources: evidence.sources.map(parseSourceRecord),
    },
    deepReview: {
      protocolId: deepReview.protocolId,
      protocolTitle: deepReview.protocolTitle,
      protocolVersion: deepReview.protocolVersion,
      protocolDigestPrefix: deepReview.protocolDigestPrefix,
      auditEventCount: deepReview.auditEventCount,
      auditBundleDigestPrefix: deepReview.auditBundleDigestPrefix,
      spanAuditSpanCount: deepReview.spanAuditSpanCount,
      spanAuditOverlapCount: deepReview.spanAuditOverlapCount,
      spanAuditFingerprintPrefix: deepReview.spanAuditFingerprintPrefix,
      offsetProjectionFormatsVerified: deepReview.offsetProjectionFormatsVerified,
      extractions: deepReview.extractions.map(parseExtractionRow),
      certaintyOutcome: deepReview.certaintyOutcome,
      certaintyLevel: deepReview.certaintyLevel as CertaintyKey,
      certaintyStatus: deepReview.certaintyStatus,
      certaintyReasons: deepReview.certaintyReasons,
      externalWorkerGate: deepReview.externalWorkerGate,
    },
    packsAndValidity: {
      validityEpoch: packsAndValidity.validityEpoch,
      rightsGrantVersion: packsAndValidity.rightsGrantVersion,
      packId: packsAndValidity.packId,
      packDigestPrefix: packsAndValidity.packDigestPrefix,
      admissiblePackDocIds: packsAndValidity.admissiblePackDocIds,
      excludedFromPack: packsAndValidity.excludedFromPack.map(parseExcluded),
      signedPackGate: packsAndValidity.signedPackGate,
    },
    privacyAndDiagnostics: {
      networkPosture: "NETWORK_LOCKED",
      coreHttpClientsPresent: false,
      vaultDomainVersion: privacyAndDiagnostics.vaultDomainVersion,
      schemaDigestPrefix: privacyAndDiagnostics.schemaDigestPrefix,
      storeEstablished: privacyAndDiagnostics.storeEstablished,
      recordSemanticsDoctorPassed: privacyAndDiagnostics.recordSemanticsDoctorPassed,
      hostileMimeQuarantineActive: privacyAndDiagnostics.hostileMimeQuarantineActive,
      recoveryEnvelopeEnrolled: privacyAndDiagnostics.recoveryEnvelopeEnrolled,
      privateDataReady: false,
      openResidualRiskClasses: privacyAndDiagnostics.openResidualRiskClasses,
      webviewIncognitoDefault: privacyAndDiagnostics.webviewIncognitoDefault,
      outboundSurveillanceDefaultOptIn: false,
      clinicalUseAuthorized: false,
    },
  };
}
