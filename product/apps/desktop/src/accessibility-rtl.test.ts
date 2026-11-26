// Accessibility (WCAG 2.1 AA contrast & WAI-ARIA tab keyboarding), RTL/LTR parity, and workstation parser tests (WP-18, WP-19, TA-22).

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { UI_TEXT, WORKSTATION_TABS, directionForLocale, nextTabForKey } from "./i18n.ts";
import { parseWorkstationOverview } from "./workstation-types.ts";

function srgbChannelToLinear(channel8: number): number {
  const c = channel8 / 255;
  return c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
}

function relativeLuminance(hex: string): number {
  const clean = hex.replace(/^#/, "");
  assert.equal(clean.length, 6, `expected 6-digit hex color: ${hex}`);
  const r = srgbChannelToLinear(Number.parseInt(clean.slice(0, 2), 16));
  const g = srgbChannelToLinear(Number.parseInt(clean.slice(2, 4), 16));
  const b = srgbChannelToLinear(Number.parseInt(clean.slice(4, 6), 16));
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

function contrastRatio(fgHex: string, bgHex: string): number {
  const l1 = relativeLuminance(fgHex);
  const l2 = relativeLuminance(bgHex);
  const lighter = Math.max(l1, l2);
  const darker = Math.min(l1, l2);
  return (lighter + 0.05) / (darker + 0.05);
}

test("styles.css light and dark palette tokens satisfy WCAG 2.1 AA (>= 4.5:1) contrast", () => {
  const css = readFileSync(new URL("./styles.css", import.meta.url), "utf8");
  const tokens = new Map<string, [string, string]>();
  for (const match of css.matchAll(/--([a-z-]+):\s*light-dark\((#[0-9a-fA-F]{6}),\s*(#[0-9a-fA-F]{6})\)/g)) {
    tokens.set(match[1]!, [match[2]!, match[3]!]);
  }
  for (const required of ["ink", "muted", "surface", "panel", "accent", "mark", "caution"]) {
    assert.ok(tokens.has(required), `missing CSS token --${required}`);
  }

  const pairs: ReadonlyArray<[string, string]> = [
    ["ink", "surface"],
    ["ink", "panel"],
    ["muted", "surface"],
    ["muted", "panel"],
    ["accent", "surface"],
    ["accent", "panel"],
    ["caution", "surface"],
    ["caution", "panel"],
    ["ink", "mark"],
  ];

  for (const [fgName, bgName] of pairs) {
    const [fgLight, fgDark] = tokens.get(fgName)!;
    const [bgLight, bgDark] = tokens.get(bgName)!;
    const lightRatio = contrastRatio(fgLight, bgLight);
    const darkRatio = contrastRatio(fgDark, bgDark);
    assert.ok(lightRatio >= 4.5, `light contrast --${fgName} on --${bgName} is ${lightRatio.toFixed(2)} (< 4.5)`);
    assert.ok(darkRatio >= 4.5, `dark contrast --${fgName} on --${bgName} is ${darkRatio.toFixed(2)} (< 4.5)`);
  }
});

test("English and Arabic catalogues have complete parity and zero percentages", () => {
  assert.equal(directionForLocale("en"), "ltr");
  assert.equal(directionForLocale("ar"), "rtl");
  assert.deepEqual(Object.keys(UI_TEXT.en).sort(), Object.keys(UI_TEXT.ar).sort());
  assert.deepEqual(Object.keys(UI_TEXT.en.tabs), [...WORKSTATION_TABS]);
  assert.deepEqual(Object.keys(UI_TEXT.ar.tabs), [...WORKSTATION_TABS]);

  for (const locale of ["en", "ar"] as const) {
    const serialized = JSON.stringify(UI_TEXT[locale]);
    assert.doesNotMatch(serialized, /\d\s*%|percent|confidence/i);
  }
});

test("WAI-ARIA tablist keyboard roving reverses ArrowLeft and ArrowRight in RTL", () => {
  // LTR: ArrowRight moves forward, ArrowLeft wraps backward
  assert.equal(nextTabForKey("ask", "ArrowRight", "ltr"), "evidence");
  assert.equal(nextTabForKey("ask", "ArrowLeft", "ltr"), "privacy");
  // RTL: ArrowLeft moves forward, ArrowRight wraps backward
  assert.equal(nextTabForKey("ask", "ArrowLeft", "rtl"), "evidence");
  assert.equal(nextTabForKey("ask", "ArrowRight", "rtl"), "privacy");
  // Home and End are direction-independent
  assert.equal(nextTabForKey("packs", "Home", "rtl"), "ask");
  assert.equal(nextTabForKey("packs", "End", "ltr"), "privacy");
  assert.equal(nextTabForKey("ask", "Enter", "ltr"), null);
});

const validOverview = {
  schemaVersion: 1,
  fixtureOnly: true,
  evidence: {
    corpusDescription: "Invented fixture",
    totalDocuments: 1,
    activeIndependentStudies: 1,
    sources: [
      {
        docId: "doc-1",
        studyId: "study-1",
        title: "Synthetic trial",
        population: "adults",
        condition: "glimmer syndrome",
        intervention: "veltrixamine",
        publicationState: "CURRENT",
        rights: "synthetic_owned",
        citable: true,
        rightsAdmissible: true,
        scalarCount: 80,
        sourceDigestPrefix: "0123456789abcdef",
      },
    ],
  },
  deepReview: {
    protocolId: "proto-1",
    protocolTitle: "Synthetic review",
    protocolVersion: 1,
    protocolDigestPrefix: "abcdef0123456789",
    auditEventCount: 3,
    auditBundleDigestPrefix: "fedcba9876543210",
    extractions: [
      {
        extractionId: "ext-1",
        studyId: "study-1",
        sourceId: "doc-1",
        outcomeLabel: "glimmer syndrome",
        measureKind: "mean_difference",
        pointEstimateText: "8 points",
        timepoint: "8 weeks",
        quoteText: "Improved by 8 points.",
        startScalar: 10,
        endScalar: 31,
        workflowState: "PROPOSED",
        actorLabel: "rule-extractor-v1",
      },
    ],
    certaintyOutcome: "Glimmer score",
    certaintyLevel: "MODERATE",
    certaintyStatus: "PROPOSED",
    certaintyReasons: ["r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8"],
    externalWorkerGate: "EXT-01 gated",
  },
  packsAndValidity: {
    validityEpoch: 3,
    rightsGrantVersion: "synthetic-owned-1",
    packId: "pack-vs1a",
    packDigestPrefix: "1122334455667788",
    admissiblePackDocIds: ["doc-1"],
    excludedFromPack: [
      {
        docId: "doc-2",
        reasonCode: "RIGHTS_UNRESOLVED",
        reason: "rights not established",
      },
    ],
    signedPackGate: "EXT-05 gated",
  },
  privacyAndDiagnostics: {
    networkPosture: "NETWORK_LOCKED",
    coreHttpClientsPresent: false,
    vaultDomainVersion: "SAFEVD-v1",
    schemaDigestPrefix: "9988776655443322",
    storeEstablished: true,
    webviewIncognitoDefault: true,
    outboundSurveillanceDefaultOptIn: false,
    clinicalUseAuthorized: false,
  },
};

test("parseWorkstationOverview validates strict backend contracts and rejects tampering", () => {
  assert.deepEqual(parseWorkstationOverview(validOverview), validOverview);
  for (const invalid of [
    null,
    {},
    { ...validOverview, schemaVersion: 2 },
    { ...validOverview, fixtureOnly: false },
    { ...validOverview, privacyAndDiagnostics: { ...validOverview.privacyAndDiagnostics, clinicalUseAuthorized: true } },
    { ...validOverview, privacyAndDiagnostics: { ...validOverview.privacyAndDiagnostics, networkPosture: "OPEN" } },
    { ...validOverview, deepReview: { ...validOverview.deepReview, certaintyReasons: ["only-one"] } },
    { ...validOverview, deepReview: { ...validOverview.deepReview, certaintyLevel: "UNKNOWN" } },
    { ...validOverview, evidence: { ...validOverview.evidence, totalDocuments: 2 } },
  ]) {
    assert.throws(() => parseWorkstationOverview(invalid));
  }
});
