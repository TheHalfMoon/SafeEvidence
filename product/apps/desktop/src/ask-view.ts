// The native response and how it reads. Rejects a mismatched protocol instead of rendering an
// assumed safe state. Nothing here computes or shows a confidence percentage.

export const OUTCOMES = {
  ANSWER: "Answer",
  ANSWER_WITH_CAUTION: "Answer, with caution",
  ASK_MORE: "More information needed",
  CONFLICT: "The evidence conflicts",
  ABSTAIN: "No answer given",
  ESCALATE: "Needs clinician review",
  BLOCKED: "Blocked",
} as const;
export type Outcome = keyof typeof OUTCOMES;

export const REASONS = {
  SECURITY_DENIED: "Security policy denied this request.",
  RIGHTS_UNRESOLVED: "The rights to use a source are not established.",
  SOURCE_UNAVAILABLE: "A required source is unavailable.",
  SOURCE_INVALID_OR_RETRACTED: "A required source is invalid or retracted.",
  EVIDENCE_INSUFFICIENT: "The evidence is not sufficient to answer.",
  MISSING_CRITICAL_CONTEXT: "The question is missing critical context, such as the population.",
  APPLICABILITY_UNRESOLVED: "The evidence may not apply to this population.",
  MATERIAL_CONTRADICTION: "Sources disagree on a material point.",
  TOOL_FAILURE: "A required step failed, so no answer is shown.",
  TIME_BUDGET_EXHAUSTED: "The time budget ran out.",
  CLINICIAN_AUTHORITY_REQUIRED: "This needs a clinician's decision.",
  POST_VERIFICATION_FAILED: "The answer failed verification, so it is not shown.",
  PROOF_RACE_INVALIDATED: "Validity changed during verification, so the answer is not shown.",
  CURRENTNESS_UNKNOWN: "This answer's currentness is unknown.",
  UNSUPPORTED_LANGUAGE: "This language is not supported yet.",
  NONE: "",
} as const;
export type Reason = keyof typeof REASONS;

export type Funnel = {
  indexed: number;
  retrieved: number;
  citable: number;
  rightsAdmissible: number;
  applicable: number;
  independentStudies: number;
  verifiedClaims: number;
};

export const FUNNEL_STAGES: ReadonlyArray<[keyof Funnel, string]> = [
  ["indexed", "Indexed"],
  ["retrieved", "Retrieved"],
  ["citable", "Citable"],
  ["rightsAdmissible", "Rights admissible"],
  ["applicable", "Applicable"],
  ["independentStudies", "Independent studies"],
  ["verifiedClaims", "Verified claims"],
];

export type Citation = {
  claimId: string;
  sourceId: string;
  sourceVersion: string;
  startScalar: number;
  endScalar: number;
  sourceText: string;
};

export type AskView = {
  schemaVersion: 1;
  fixtureOnly: true;
  outcome: Outcome;
  reason: Reason;
  funnel: Funnel;
  excluded: Array<{ docId: string; reason: string }>;
  brief: string | null;
  proofId: string | null;
  citations: Citation[];
};

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);
const isCount = (value: unknown): value is number => Number.isSafeInteger(value) && (value as number) >= 0;

function parseCitation(value: unknown): Citation {
  if (!isRecord(value)) throw new Error("Invalid citation");
  const { claimId, sourceId, sourceVersion, startScalar, endScalar, sourceText } = value;
  if (typeof claimId !== "string" || typeof sourceId !== "string" || typeof sourceVersion !== "string" ||
      typeof sourceText !== "string" || !isCount(startScalar) || !isCount(endScalar) ||
      startScalar >= endScalar || endScalar > Array.from(sourceText).length) {
    throw new Error("Invalid citation");
  }
  return { claimId, sourceId, sourceVersion, startScalar, endScalar, sourceText };
}

export function parseAskView(value: unknown): AskView {
  if (!isRecord(value) || value.schemaVersion !== 1 || value.fixtureOnly !== true) {
    throw new Error("Unsupported ask response");
  }
  const { outcome, reason, funnel, excluded, brief, proofId, citations } = value;
  if (typeof outcome !== "string" || !Object.hasOwn(OUTCOMES, outcome) ||
      typeof reason !== "string" || !Object.hasOwn(REASONS, reason) || !isRecord(funnel) ||
      !Array.isArray(excluded) || !Array.isArray(citations)) {
    throw new Error("Unsupported ask response");
  }
  if (!FUNNEL_STAGES.every(([stage]) => isCount(funnel[stage]))) throw new Error("Invalid funnel");
  const answered = outcome === "ANSWER" || outcome === "ANSWER_WITH_CAUTION";
  // A brief appears only with its committed proof, and only for an answering outcome.
  if (answered ? typeof brief !== "string" || brief.length === 0 || typeof proofId !== "string" || proofId.length === 0
               : brief !== null || proofId !== null || citations.length !== 0) {
    throw new Error("Answer and proof do not agree");
  }
  return {
    schemaVersion: 1,
    fixtureOnly: true,
    outcome: outcome as Outcome,
    reason: reason as Reason,
    funnel: funnel as unknown as Funnel,
    excluded: excluded.map((item) => {
      if (!isRecord(item) || typeof item.docId !== "string" || typeof item.reason !== "string") {
        throw new Error("Invalid exclusion");
      }
      return { docId: item.docId, reason: item.reason };
    }),
    brief: brief as string | null,
    proofId: proofId as string | null,
    citations: citations.map(parseCitation),
  };
}

/** Splits text around a span given in Unicode scalar values, as the proof manifest records it. */
export function spanSegments(text: string, start: number, end: number): [string, string, string] {
  const scalars = Array.from(text);
  return [scalars.slice(0, start).join(""), scalars.slice(start, end).join(""), scalars.slice(end).join("")];
}
