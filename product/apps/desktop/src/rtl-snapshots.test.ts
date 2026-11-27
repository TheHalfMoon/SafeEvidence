// Deterministic LTR (en) and RTL (ar) HTML structural snapshots and WCAG 2.1 AA / WAI-ARIA semantic audits
// across all five SafeEvidence Workstation views (TA-20, TA-22).

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { createServer } from "vite";
import type { AskView, Citation } from "./ask-view.ts";
import { type Locale, type WorkstationTab, UI_TEXT, WORKSTATION_TABS } from "./i18n.ts";
import type { WorkstationOverview } from "./workstation-types.ts";

const desktopRoot = fileURLToPath(new URL("../", import.meta.url));

const sampleCitation: Citation = {
  claimId: "claim-1",
  sourceId: "doc-veltrix-a",
  sourceVersion: "1",
  startScalar: 9,
  endScalar: 57,
  sourceText: "Trial A: Veltrixamine improved glimmer scores by 6 points at 12 weeks.",
};

const arabicSampleText = "تجربة أ: حَسَّنَ فـلـتـريـكـسـامـيـن درجات الوميض بمقدار 6 نقاط عند الأسبوع 12.";
const arabicMarkPhrase = "حَسَّنَ فـلـتـريـكـسـامـيـن درجات الوميض بمقدار 6 نقاط";
const arabicScalars = Array.from(arabicSampleText);
const arabicStartScalar = Array.from("تجربة أ: ").length;
const arabicEndScalar = arabicStartScalar + Array.from(arabicMarkPhrase).length;
assert.equal(arabicScalars.slice(arabicStartScalar, arabicEndScalar).join(""), arabicMarkPhrase);

const arabicCitation: Citation = {
  claimId: "claim-ar-1",
  sourceId: "doc-veltrix-ar",
  sourceVersion: "1",
  startScalar: arabicStartScalar,
  endScalar: arabicEndScalar,
  sourceText: arabicSampleText,
};

const answeredAskView: AskView = {
  schemaVersion: 1,
  fixtureOnly: true,
  outcome: "ANSWER_WITH_CAUTION",
  reason: "APPLICABILITY_UNRESOLVED",
  funnel: {
    indexed: 7,
    retrieved: 2,
    citable: 2,
    rightsAdmissible: 2,
    applicable: 1,
    independentStudies: 1,
    verifiedClaims: 1,
  },
  excluded: [
    {
      docId: "doc-veltrix-peds",
      reasonCode: "APPLICABILITY_UNRESOLVED",
      reason: "population children does not match adults",
    },
  ],
  brief: "Veltrixamine improved glimmer scores by 6 points at 12 weeks [doc-veltrix-a].",
  proofId: "vs1a-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  alreadyCommitted: false,
  citations: [sampleCitation],
};

const conflictAskView: AskView = {
  schemaVersion: 1,
  fixtureOnly: true,
  outcome: "CONFLICT",
  reason: "MATERIAL_CONTRADICTION",
  funnel: {
    indexed: 7,
    retrieved: 2,
    citable: 2,
    rightsAdmissible: 2,
    applicable: 2,
    independentStudies: 2,
    verifiedClaims: 0,
  },
  excluded: [],
  brief: null,
  proofId: null,
  alreadyCommitted: false,
  citations: [],
};

const sampleOverview: WorkstationOverview = {
  schemaVersion: 1,
  fixtureOnly: true,
  evidence: {
    corpusDescription: "Invented engineering fixture",
    totalDocuments: 2,
    activeIndependentStudies: 1,
    sources: [
      {
        docId: "doc-veltrix-a",
        studyId: "study-veltrix-a",
        title: "Synthetic adult trial",
        population: "adults",
        condition: "glimmer syndrome",
        intervention: "veltrixamine",
        publicationState: "CURRENT",
        rights: "synthetic_owned",
        citable: true,
        rightsAdmissible: true,
        scalarCount: 120,
        sourceDigestPrefix: "0123456789abcdef",
      },
      {
        docId: "doc-quenzil-retracted",
        studyId: "study-quenzil",
        title: "Retracted synthetic trial",
        population: "adults",
        condition: "hollow cough",
        intervention: "quenzil",
        publicationState: "RETRACTED",
        rights: "synthetic_owned",
        citable: false,
        rightsAdmissible: true,
        scalarCount: 95,
        sourceDigestPrefix: "fedcba9876543210",
      },
    ],
  },
  deepReview: {
    protocolId: "proto-synthetic-01",
    protocolTitle: "Synthetic review protocol for glimmer syndrome",
    protocolVersion: 1,
    protocolDigestPrefix: "abcdef0123456789",
    auditEventCount: 3,
    auditBundleDigestPrefix: "1122334455667788",
    spanAuditSpanCount: 3,
    spanAuditOverlapCount: 1,
    spanAuditFingerprintPrefix: "8877665544332211",
    offsetProjectionFormatsVerified: 5,
    extractions: [
      {
        extractionId: "ext-orbalin-a",
        studyId: "study-orbalin-a",
        sourceId: "doc-orbalin-a",
        outcomeLabel: "ember fatigue",
        measureKind: "mean_difference",
        pointEstimateText: "8 points",
        timepoint: "8 weeks",
        quoteText: "Orbalin improved ember fatigue by 8 points.",
        startScalar: 12,
        endScalar: 55,
        workflowState: "PROPOSED",
        actorLabel: "rule-extractor-v1",
      },
      {
        extractionId: "ext-veltrix-peds",
        studyId: "study-veltrix-peds",
        sourceId: "doc-veltrix-peds",
        outcomeLabel: "glimmer syndrome",
        measureKind: "mean_difference",
        pointEstimateText: "did not improve",
        timepoint: "12 weeks",
        quoteText: "Veltrixamine did not improve glimmer scores in children.",
        startScalar: 0,
        endScalar: 56,
        workflowState: "CONFIRMED",
        actorLabel: "reviewer-synthetic-lead",
      },
    ],
    certaintyOutcome: "Glimmer syndrome composite score (adults)",
    certaintyLevel: "MODERATE",
    certaintyStatus: "PROPOSED",
    certaintyReasons: ["r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8"],
    externalWorkerGate: "EXT-01: External workers remain gated on Issue #5.",
  },
  packsAndValidity: {
    validityEpoch: 1,
    rightsGrantVersion: "urn:safeevidence:rights:synthetic-owned-1",
    packId: "pack-vs1a-synthetic",
    packDigestPrefix: "99aa88bb77cc66dd",
    admissiblePackDocIds: ["doc-veltrix-a", "doc-orbalin-a"],
    excludedFromPack: [
      {
        docId: "doc-tessarine-unknown-rights",
        reasonCode: "RIGHTS_UNRESOLVED",
        reason: "rights not established for pack inclusion",
      },
    ],
    signedPackGate: "EXT-01 / EXT-05: TUF-signed pack import remains gated.",
  },
  privacyAndDiagnostics: {
    networkPosture: "NETWORK_LOCKED",
    coreHttpClientsPresent: false,
    vaultDomainVersion: "SAFEVD-v1",
    schemaDigestPrefix: "c278d741a7736b1c",
    storeEstablished: true,
    recordSemanticsDoctorPassed: true,
    hostileMimeQuarantineActive: true,
    recoveryEnvelopeEnrolled: false,
    privateDataReady: false,
    openResidualRiskClasses: ["swap", "hibernate", "snapshot", "pagefile", "core_dump"],
    webviewIncognitoDefault: true,
    outboundSurveillanceDefaultOptIn: false,
    clinicalUseAuthorized: false,
  },
};

function auditHtmlSemanticsAndBidi(html: string, locale: Locale, activeTab: WorkstationTab) {
  const expectedDir = locale === "ar" ? "rtl" : "ltr";

  // 1. Root container carries exact lang and dir attributes:
  assert.match(
    html,
    new RegExp(`^<div class="workstation-shell" lang="${locale}" dir="${expectedDir}">`),
    `root lang/dir mismatch for ${locale}/${activeTab}`,
  );

  // 2. Skip-to-main link targets #main-content, and <main id="main-content"> exists:
  assert.match(html, /<a class="skip-link" href="#main-content">/);
  assert.match(html, /<main id="main-content">/);

  // 3. Zero duplicate element IDs anywhere in the rendered HTML:
  const ids = [...html.matchAll(/\bid="([^"]+)"/g)].map((m) => m[1]!);
  assert.equal(new Set(ids).size, ids.length, `duplicate DOM IDs in ${locale}/${activeTab}: ${ids.join(",")}`);

  // 4. Every form control (<textarea>, <input>, <select>) has a matching <label for="...">:
  const labels = new Set([...html.matchAll(/<label\b[^>]*\bfor="([^"]+)"/g)].map((m) => m[1]!));
  for (const ctrl of html.matchAll(/<(textarea|input|select)\b([^>]*)>/g)) {
    const idMatch = ctrl[2]!.match(/\bid="([^"]+)"/);
    assert.ok(idMatch, `unlabeled <${ctrl[1]}> without id in ${locale}/${activeTab}`);
    assert.ok(labels.has(idMatch[1]!), `missing <label for="${idMatch[1]}"> in ${locale}/${activeTab}`);
  }

  // 5. WAI-ARIA tablist / tab / tabpanel invariants and roving tabindex:
  assert.match(html, /role="tablist"/);
  const tabs = [...html.matchAll(/<button\b([^>]*\brole="tab"[^>]*)>/g)].map((m) => m[1]!);
  assert.equal(tabs.length, WORKSTATION_TABS.length);
  let selectedCount = 0;
  for (const attrs of tabs) {
    const id = attrs.match(/\bid="tab-([a-z]+)"/)?.[1];
    assert.ok(id, `tab missing id in ${attrs}`);
    assert.match(attrs, new RegExp(`aria-controls="panel-${id}"`));
    if (id === activeTab) {
      selectedCount += 1;
      assert.match(attrs, /aria-selected="true"/);
      assert.match(attrs, /tabindex="0"/);
    } else {
      assert.match(attrs, /aria-selected="false"/);
      assert.match(attrs, /tabindex="-1"/);
    }
  }
  assert.equal(selectedCount, 1);
  assert.match(
    html,
    new RegExp(`<div id="panel-${activeTab}" role="tabpanel" aria-labelledby="tab-${activeTab}">`),
  );

  // 6. Every <th> in data tables carries explicit scope="col":
  for (const th of html.matchAll(/<th\b([^>]*)>/g)) {
    assert.match(th[1]!, /\bscope="col"/, `<th> missing scope="col" in ${locale}/${activeTab}`);
  }

  // 7. Every <code> element carries dir="ltr" so technical IDs/digests/ranges never flip in RTL:
  for (const code of html.matchAll(/<code\b([^>]*)>/g)) {
    assert.match(code[1]!, /\bdir="ltr"/, `<code> missing dir="ltr" in ${locale}/${activeTab}`);
  }

  // 8. Zero inline style attributes (CSP), zero percentages/confidence, and mandatory fixture notice:
  assert.doesNotMatch(html, /\bstyle=/i);
  assert.doesNotMatch(html, /%|\u066A|percent|confidence/i);
  assert.ok(
    html.includes(UI_TEXT[locale].fixtureNotice),
    `missing localized fixture notice in ${locale}/${activeTab}`,
  );
}

function structuralTagSkeleton(html: string): string {
  // Strip text nodes while keeping tag names and structural/ARIA/BiDi attributes so LTR and RTL
  // trees can be verified structurally isomorphic apart from root dir="ltr" vs dir="rtl" and lang.
  return html
    .replace(/>[^<]*</g, "><")
    .replace(/\blang="(en|ar)"/g, 'lang="*"')
    .replace(/\bdir="(ltr|rtl)"/, 'dir="*"')
    .replace(/\baria-label="[^"]*"/g, 'aria-label="*"');
}

test("WorkstationShell renders deterministic WCAG/WAI-ARIA-compliant LTR and RTL HTML across all 5 views", async () => {
  const vite = await createServer({
    root: desktopRoot,
    server: { middlewareMode: true },
    appType: "custom",
    logLevel: "silent",
  });

  try {
    const mod = await vite.ssrLoadModule("/src/App.tsx");
    const WorkstationShell = mod.WorkstationShell as (props: Record<string, unknown>) => ReturnType<typeof createElement>;
    assert.equal(typeof WorkstationShell, "function");

    const scenarios: ReadonlyArray<{
      name: string;
      tab: WorkstationTab;
      view: AskView | null;
      selected: Citation | null;
      asked: string;
    }> = [
      { name: "ask-idle", tab: "ask", view: null, selected: null, asked: "" },
      {
        name: "ask-answered-with-span",
        tab: "ask",
        view: answeredAskView,
        selected: sampleCitation,
        asked: "Does veltrixamine help adults with glimmer syndrome?",
      },
      {
        name: "ask-answered-arabic-vocalized-span",
        tab: "ask",
        view: { ...answeredAskView, citations: [arabicCitation] },
        selected: arabicCitation,
        asked: "هل يساعد فلتريكسامين البالغين المصابين بمتلازمة الوميض؟",
      },
      {
        name: "ask-conflict",
        tab: "ask",
        view: conflictAskView,
        selected: null,
        asked: "Does orbalin help adults with ember fatigue?",
      },
      { name: "evidence", tab: "evidence", view: null, selected: null, asked: "" },
      { name: "review", tab: "review", view: null, selected: null, asked: "" },
      { name: "packs", tab: "packs", view: null, selected: null, asked: "" },
      { name: "privacy", tab: "privacy", view: null, selected: null, asked: "" },
    ];

    for (const scenario of scenarios) {
      const renderFor = (locale: Locale) =>
        renderToStaticMarkup(
          createElement(WorkstationShell, {
            locale,
            activeTab: scenario.tab,
            question: "Does veltrixamine help adults with glimmer syndrome?",
            view: scenario.view,
            selected: scenario.selected,
            failure: null,
            busy: false,
            asked: scenario.asked,
            overview: scenario.tab === "ask" ? null : sampleOverview,
            overviewError: null,
          }),
        );

      const enHtmlA = renderFor("en");
      const enHtmlB = renderFor("en");
      const arHtmlA = renderFor("ar");
      const arHtmlB = renderFor("ar");

      // Byte-for-byte determinism across repeated renders:
      assert.equal(enHtmlA, enHtmlB);
      assert.equal(arHtmlA, arHtmlB);
      assert.notEqual(enHtmlA, arHtmlB);

      const enSha = createHash("sha256").update(enHtmlA).digest("hex");
      const arSha = createHash("sha256").update(arHtmlA).digest("hex");
      assert.equal(enSha.length, 64);
      assert.equal(arSha.length, 64);

      auditHtmlSemanticsAndBidi(enHtmlA, "en", scenario.tab);
      auditHtmlSemanticsAndBidi(arHtmlA, "ar", scenario.tab);

      // Structural DOM isomorphism between English LTR and Arabic RTL:
      assert.equal(
        structuralTagSkeleton(enHtmlA),
        structuralTagSkeleton(arHtmlA),
        `LTR/RTL DOM skeleton diverged on scenario ${scenario.name}`,
      );

      if (scenario.name === "ask-answered-with-span") {
        assert.match(enHtmlA, /<mark tabindex="-1">Veltrixamine improved glimmer scores by 6 points<\/mark>/);
        assert.match(arHtmlA, /<mark tabindex="-1">Veltrixamine improved glimmer scores by 6 points<\/mark>/);
      }
      if (scenario.name === "ask-answered-arabic-vocalized-span") {
        assert.ok(enHtmlA.includes(`<mark tabindex="-1">${arabicMarkPhrase}</mark>`));
        assert.ok(arHtmlA.includes(`<mark tabindex="-1">${arabicMarkPhrase}</mark>`));
      }
      if (scenario.name === "review") {
        assert.match(enHtmlA, /Opaque span-overlap audit/);
        assert.match(arHtmlA, new RegExp(UI_TEXT.ar.spanAuditLabel));
      }
      if (scenario.name === "privacy") {
        assert.match(enHtmlA, /Append-only record-semantics doctor verified/);
        assert.match(arHtmlA, new RegExp(UI_TEXT.ar.recordDoctorLabel));
        assert.match(arHtmlA, /<code dir="ltr">core_dump<\/code>/);
      }
    }
  } finally {
    await vite.close();
  }
});
