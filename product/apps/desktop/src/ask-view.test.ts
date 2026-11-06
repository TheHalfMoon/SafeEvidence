import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { FUNNEL_STAGES, OUTCOMES, REASONS, parseAskView, spanSegments } from "./ask-view.ts";

const funnel = { indexed: 4, retrieved: 3, citable: 3, rightsAdmissible: 3, applicable: 2, independentStudies: 2, verifiedClaims: 2 };
const citation = { claimId: "c", sourceId: "s", sourceVersion: "1", startScalar: 0, endScalar: 3, sourceText: "abcd" };
const answer = {
  schemaVersion: 1, fixtureOnly: true, outcome: "ANSWER_WITH_CAUTION", reason: "NONE", funnel, excluded: [],
  brief: "Synthetic brief", proofId: "vs1a-x", citations: [citation],
};
const refusal = { ...answer, outcome: "ABSTAIN", reason: "EVIDENCE_INSUFFICIENT", brief: null, proofId: null, citations: [] };

test("answers and refusals both parse with their trace", () => {
  assert.deepEqual(parseAskView(answer), answer);
  assert.deepEqual(parseAskView(refusal), refusal);
  assert.equal(parseAskView(refusal).funnel.indexed, 4);
});

test("mismatched or malformed responses are rejected, never assumed", () => {
  for (const invalid of [
    null, [], "ready", {},
    { ...answer, schemaVersion: 2 },
    { ...answer, fixtureOnly: false },
    { ...answer, outcome: "MAYBE" },
    { ...answer, outcome: "toString" },
    { ...answer, reason: "UNKNOWN" },
    { ...answer, funnel: { ...funnel, indexed: -1 } },
    { ...answer, funnel: { ...funnel, verifiedClaims: "2" } },
    { ...answer, citations: [{ ...citation, endScalar: 5 }] },
    { ...answer, citations: [{ ...citation, startScalar: 3 }] },
  ]) {
    assert.throws(() => parseAskView(invalid));
  }
});

test("a brief never appears without its proof or on a refusal", () => {
  for (const invalid of [
    { ...answer, proofId: null },
    { ...answer, proofId: "" },
    { ...answer, brief: null },
    { ...answer, brief: "" },
    { ...answer, citations: [] },
    { ...refusal, brief: "text" },
    { ...refusal, proofId: "vs1a-x" },
    { ...refusal, citations: [citation] },
  ]) {
    assert.throws(() => parseAskView(invalid));
  }
});

test("the disabled emergency outcome cannot be rendered", () => {
  assert.equal(Object.hasOwn(OUTCOMES, "EMERGENCY_NOTICE"), false);
  assert.throws(() => parseAskView({ ...refusal, outcome: "EMERGENCY_NOTICE" }));
});

test("spans use Unicode scalar values, as the manifest does", () => {
  assert.deepEqual(spanSegments("a\u{1F9EA}bcd", 1, 3), ["a", "\u{1F9EA}b", "cd"]);
  assert.deepEqual(spanSegments("\u0645\u0631\u062D\u0628\u0627", 1, 3), ["\u0645", "\u0631\u062D", "\u0628\u0627"]);
});

test("every outcome and funnel stage has text, and no text shows a percentage", () => {
  const app = readFileSync(new URL("./App.tsx", import.meta.url), "utf8");
  const shown = [...Object.values(OUTCOMES), ...Object.values(REASONS), ...FUNNEL_STAGES.map(([, label]) => label), app];
  for (const text of shown) {
    assert.doesNotMatch(text, /\d\s*%|percent|confidence/i);
  }
  assert.equal(FUNNEL_STAGES.length, Object.keys(funnel).length);
});
