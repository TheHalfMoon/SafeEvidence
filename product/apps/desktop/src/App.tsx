import { invoke } from "@tauri-apps/api/core";
import { type FormEvent, type KeyboardEvent, useEffect, useRef, useState } from "react";
import { type AskView, type Citation, FUNNEL_STAGES, parseAskView, spanSegments } from "./ask-view";
import {
  type Locale,
  type UiCatalogue,
  type WorkstationTab,
  UI_TEXT,
  WORKSTATION_TABS,
  directionForLocale,
  nextTabForKey,
} from "./i18n";
import { type WorkstationOverview, parseWorkstationOverview } from "./workstation-types";

const EXAMPLE = "Does veltrixamine help adults with glimmer syndrome?";
const FIXTURE_NOTICE = "Invented engineering fixture. Not medical information.";

function FunnelTrace({ view, text }: { view: AskView; text: UiCatalogue }) {
  return (
    <section aria-labelledby="trace-heading">
      <h2 id="trace-heading">{text.traceHeading}</h2>
      <ol className="funnel">
        {FUNNEL_STAGES.map(([stage]) => (
          <li key={stage}>
            <span className="count">{view.funnel[stage]}</span> {text.funnelLabels[stage]}
          </li>
        ))}
      </ol>
      {view.excluded.length > 0 && (
        <>
          <h3>{text.excludedHeading}</h3>
          <ul>
            {view.excluded.map((item) => (
              <li key={item.docId}>
                <code dir="ltr">{item.docId}</code> (<code dir="ltr">{item.reasonCode}</code>): {item.reason}
              </li>
            ))}
          </ul>
        </>
      )}
    </section>
  );
}

function SourcePanel({ citation, text }: { citation: Citation; text: UiCatalogue }) {
  const mark = useRef<HTMLElement>(null);
  useEffect(() => {
    mark.current?.focus();
    mark.current?.scrollIntoView({ block: "center" });
  }, [citation]);
  const [before, span, after] = spanSegments(citation.sourceText, citation.startScalar, citation.endScalar);
  return (
    <section aria-labelledby="source-heading">
      <h2 id="source-heading">
        {text.sourceHeadingPrefix}
        <code dir="ltr">{citation.sourceId}</code>
        {text.versionPrefix}
        <code dir="ltr">{citation.sourceVersion}</code>
      </h2>
      <p dir="auto" className="source">
        {before}
        <mark ref={mark} tabIndex={-1}>{span}</mark>
        {after}
      </p>
    </section>
  );
}

function EvidenceSection({ overview, text }: { overview: WorkstationOverview; text: UiCatalogue }) {
  const { evidence } = overview;
  return (
    <section aria-labelledby="evidence-heading">
      <h2 id="evidence-heading">{text.evidenceHeading}</h2>
      <dl className="kv-grid">
        <div>
          <dt>{text.totalDocsLabel}</dt>
          <dd className="count">{evidence.totalDocuments}</dd>
        </div>
        <div>
          <dt>{text.independentStudiesLabel}</dt>
          <dd className="count">{evidence.activeIndependentStudies}</dd>
        </div>
      </dl>
      <div className="table-wrap">
        <table className="data-table">
          <thead>
            <tr>
              <th scope="col">{text.colDocId}</th>
              <th scope="col">{text.colStudyId}</th>
              <th scope="col">{text.colPopulation}</th>
              <th scope="col">{text.colStanding}</th>
              <th scope="col">{text.colRights}</th>
              <th scope="col">{text.colDigest}</th>
            </tr>
          </thead>
          <tbody>
            {evidence.sources.map((src) => (
              <tr key={src.docId}>
                <td><code dir="ltr">{src.docId}</code></td>
                <td><code dir="ltr">{src.studyId}</code></td>
                <td>{src.population}</td>
                <td>
                  <code dir="ltr" className={src.citable ? "tag-ok" : "tag-warn"}>
                    {src.publicationState}
                  </code>
                </td>
                <td>
                  <code dir="ltr" className={src.rightsAdmissible ? "tag-ok" : "tag-warn"}>
                    {src.rights}
                  </code>
                </td>
                <td><code dir="ltr">{src.sourceDigestPrefix}</code></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function DeepReviewSection({ overview, text }: { overview: WorkstationOverview; text: UiCatalogue }) {
  const { deepReview } = overview;
  return (
    <section aria-labelledby="review-heading">
      <h2 id="review-heading">{text.reviewHeading}</h2>
      <h3>{text.protocolHeading}</h3>
      <p>{deepReview.protocolTitle}</p>
      <dl className="kv-grid">
        <div>
          <dt>{text.protocolVersionLabel}</dt>
          <dd>
            <code dir="ltr">{deepReview.protocolId}</code> v{deepReview.protocolVersion} (
            <code dir="ltr">{deepReview.protocolDigestPrefix}</code>)
          </dd>
        </div>
        <div>
          <dt>{text.auditEventsLabel}</dt>
          <dd>
            <span className="count">{deepReview.auditEventCount}</span> (
            <code dir="ltr">{deepReview.auditBundleDigestPrefix}</code>)
          </dd>
        </div>
        <div>
          <dt>{text.spanAuditLabel}</dt>
          <dd>
            <span className="count">{deepReview.spanAuditSpanCount}</span> /{" "}
            <span className="count">{deepReview.spanAuditOverlapCount}</span> (
            <code dir="ltr">{deepReview.spanAuditFingerprintPrefix}</code>)
          </dd>
        </div>
        <div>
          <dt>{text.offsetProjectionLabel}</dt>
          <dd className="count">{deepReview.offsetProjectionFormatsVerified}</dd>
        </div>
      </dl>

      <h3>{text.extractionsHeading}</h3>
      <div className="table-wrap">
        <table className="data-table">
          <thead>
            <tr>
              <th scope="col">{text.colDocId}</th>
              <th scope="col">{text.colOutcome}</th>
              <th scope="col">{text.colEstimate}</th>
              <th scope="col">{text.colSpan}</th>
              <th scope="col">{text.colState}</th>
              <th scope="col">{text.colQuote}</th>
            </tr>
          </thead>
          <tbody>
            {deepReview.extractions.map((row) => (
              <tr key={row.extractionId}>
                <td><code dir="ltr">{row.sourceId}</code></td>
                <td>{row.outcomeLabel}</td>
                <td>{row.pointEstimateText} ({row.timepoint})</td>
                <td><code dir="ltr">{row.startScalar}..{row.endScalar}</code></td>
                <td>
                  <code dir="ltr" className={row.workflowState === "CONFIRMED" ? "tag-ok" : "tag-warn"}>
                    {row.workflowState}
                  </code>{" "}
                  (<code dir="ltr">{row.actorLabel}</code>)
                </td>
                <td dir="auto">{row.quoteText}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <h3>{text.appraisalHeading}</h3>
      <p>
        <strong>{deepReview.certaintyOutcome}</strong> &mdash; {text.certaintyLabel}:{" "}
        <strong>{text.certaintyLevels[deepReview.certaintyLevel]}</strong> (
        <code dir="ltr">{deepReview.certaintyStatus}</code>)
      </p>
      <ul>
        {deepReview.certaintyReasons.map((reason) => (
          <li key={reason}>{reason}</li>
        ))}
      </ul>
      <p className="gate-note" role="note">{deepReview.externalWorkerGate}</p>
    </section>
  );
}

function PacksSection({ overview, text }: { overview: WorkstationOverview; text: UiCatalogue }) {
  const { packsAndValidity } = overview;
  return (
    <section aria-labelledby="packs-heading">
      <h2 id="packs-heading">{text.packsHeading}</h2>
      <dl className="kv-grid">
        <div>
          <dt>{text.validityEpochLabel}</dt>
          <dd className="count">{packsAndValidity.validityEpoch}</dd>
        </div>
        <div>
          <dt>{text.rightsGrantLabel}</dt>
          <dd><code dir="ltr">{packsAndValidity.rightsGrantVersion}</code></dd>
        </div>
        <div>
          <dt>{text.packIdLabel}</dt>
          <dd>
            <code dir="ltr">{packsAndValidity.packId}</code> (
            <code dir="ltr">{packsAndValidity.packDigestPrefix}</code>)
          </dd>
        </div>
      </dl>

      <h3>{text.admissibleDocsHeading}</h3>
      <ul>
        {packsAndValidity.admissiblePackDocIds.map((docId) => (
          <li key={docId}><code dir="ltr">{docId}</code></li>
        ))}
      </ul>

      <h3>{text.excludedPackHeading}</h3>
      <ul>
        {packsAndValidity.excludedFromPack.map((item) => (
          <li key={item.docId}>
            <code dir="ltr">{item.docId}</code> (<code dir="ltr">{item.reasonCode}</code>): {item.reason}
          </li>
        ))}
      </ul>
      <p className="gate-note" role="note">{packsAndValidity.signedPackGate}</p>
    </section>
  );
}

function PrivacySection({ overview, text }: { overview: WorkstationOverview; text: UiCatalogue }) {
  const { privacyAndDiagnostics: p } = overview;
  const yn = (flag: boolean) => (flag ? text.yesValue : text.noValue);
  return (
    <section aria-labelledby="privacy-heading">
      <h2 id="privacy-heading">{text.privacyHeading}</h2>
      <dl className="kv-grid">
        <div>
          <dt>{text.networkPostureLabel}</dt>
          <dd><code dir="ltr">{p.networkPosture}</code></dd>
        </div>
        <div>
          <dt>{text.httpClientsLabel}</dt>
          <dd>{yn(p.coreHttpClientsPresent)}</dd>
        </div>
        <div>
          <dt>{text.vaultDomainLabel}</dt>
          <dd><code dir="ltr">{p.vaultDomainVersion}</code></dd>
        </div>
        <div>
          <dt>{text.schemaDigestLabel}</dt>
          <dd><code dir="ltr">{p.schemaDigestPrefix}</code></dd>
        </div>
        <div>
          <dt>{text.storeEstablishedLabel}</dt>
          <dd>{yn(p.storeEstablished)}</dd>
        </div>
        <div>
          <dt>{text.recordDoctorLabel}</dt>
          <dd>{yn(p.recordSemanticsDoctorPassed)}</dd>
        </div>
        <div>
          <dt>{text.mimeQuarantineLabel}</dt>
          <dd>{yn(p.hostileMimeQuarantineActive)}</dd>
        </div>
        <div>
          <dt>{text.recoveryEnvelopeLabel}</dt>
          <dd>{yn(p.recoveryEnvelopeEnrolled)}</dd>
        </div>
        <div>
          <dt>{text.privateDataReadyLabel}</dt>
          <dd>{yn(p.privateDataReady)}</dd>
        </div>
        <div>
          <dt>{text.incognitoDefaultLabel}</dt>
          <dd>{yn(p.webviewIncognitoDefault)}</dd>
        </div>
        <div>
          <dt>{text.outboundOptInLabel}</dt>
          <dd>{yn(p.outboundSurveillanceDefaultOptIn)}</dd>
        </div>
        <div>
          <dt>{text.clinicalAuthorizedLabel}</dt>
          <dd>{yn(p.clinicalUseAuthorized)}</dd>
        </div>
      </dl>
      <h3>{text.residualRiskHeading}</h3>
      <ul>
        {p.openResidualRiskClasses.map((riskClass) => (
          <li key={riskClass}><code dir="ltr">{riskClass}</code></li>
        ))}
      </ul>
    </section>
  );
}

export function App() {
  const [locale, setLocale] = useState<Locale>("en");
  const [activeTab, setActiveTab] = useState<WorkstationTab>("ask");
  const [question, setQuestion] = useState(EXAMPLE);
  const [view, setView] = useState<AskView | null>(null);
  const [selected, setSelected] = useState<Citation | null>(null);
  const [failure, setFailure] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [asked, setAsked] = useState("");
  const [overview, setOverview] = useState<WorkstationOverview | null>(null);
  const [overviewError, setOverviewError] = useState<string | null>(null);
  // Only the newest request may fill the view, so a late reply cannot overwrite it.
  const latest = useRef(0);
  const tabRefs = useRef<Record<WorkstationTab, HTMLButtonElement | null>>({
    ask: null,
    evidence: null,
    review: null,
    packs: null,
    privacy: null,
  });

  const dir = directionForLocale(locale);
  const text = UI_TEXT[locale];

  useEffect(() => {
    document.documentElement.lang = locale;
    document.documentElement.dir = dir;
  }, [locale, dir]);

  useEffect(() => {
    if (activeTab === "ask") return;
    let cancelled = false;
    setOverviewError(null);
    invoke("workstation_overview")
      .then((raw) => {
        if (!cancelled) setOverview(parseWorkstationOverview(raw));
      })
      .catch((error) => {
        if (!cancelled) {
          setOverview(null);
          setOverviewError(String(error));
        }
      });
    return () => {
      cancelled = true;
    };
  }, [activeTab]);

  async function submit(event: FormEvent) {
    event.preventDefault();
    const request = ++latest.current;
    setBusy(true);
    setAsked(question);
    setView(null);
    setSelected(null);
    setFailure(null);
    try {
      const response = parseAskView(await invoke("ask_question", { question }));
      if (request === latest.current) setView(response);
    } catch (error) {
      if (request === latest.current) setFailure(String(error));
    } finally {
      if (request === latest.current) setBusy(false);
    }
  }

  function onTabKeyDown(event: KeyboardEvent<HTMLButtonElement>, current: WorkstationTab) {
    const next = nextTabForKey(current, event.key, dir);
    if (!next) return;
    event.preventDefault();
    setActiveTab(next);
    tabRefs.current[next]?.focus();
  }

  return (
    <div className="workstation-shell" lang={locale} dir={dir}>
      <a className="skip-link" href="#main-content">{text.skipToMain}</a>
      <header className="topbar">
        <div className="topbar-row">
          <h1>{activeTab === "ask" ? text.askHeading : text.workstationHeading}</h1>
          <button
            id="locale-toggle"
            type="button"
            className="locale-button"
            onClick={() => setLocale((prev) => (prev === "en" ? "ar" : "en"))}
          >
            {text.switchLocaleButton}
          </button>
        </div>
        <nav aria-label={text.sectionsNavLabel}>
          <div role="tablist" aria-label={text.sectionsNavLabel} className="tablist">
            {WORKSTATION_TABS.map((tab) => (
              <button
                key={tab}
                ref={(el) => {
                  tabRefs.current[tab] = el;
                }}
                id={`tab-${tab}`}
                role="tab"
                type="button"
                className="tab-button"
                aria-selected={activeTab === tab}
                aria-controls={`panel-${tab}`}
                tabIndex={activeTab === tab ? 0 : -1}
                onClick={() => setActiveTab(tab)}
                onKeyDown={(event) => onTabKeyDown(event, tab)}
              >
                {text.tabs[tab]}
              </button>
            ))}
          </div>
        </nav>
      </header>

      <main id="main-content">
        <p className="notice" role="note">{locale === "en" ? FIXTURE_NOTICE : text.fixtureNotice}</p>

        <div id={`panel-${activeTab}`} role="tabpanel" aria-labelledby={`tab-${activeTab}`}>
          {activeTab === "ask" && (
            <>
              <form onSubmit={submit}>
                <label htmlFor="question">{text.questionLabel}</label>
                <textarea
                  id="question"
                  dir="auto"
                  rows={2}
                  maxLength={1024}
                  value={question}
                  readOnly={busy}
                  onChange={(event) => setQuestion(event.target.value)}
                />
                <button type="submit" disabled={busy}>{busy ? text.checkingButton : text.askButton}</button>
              </form>

              <div aria-live="polite">
                {failure && <p className="failure" role="alert">{text.failurePrefix}{failure}</p>}
                {view && (
                  <section aria-labelledby="outcome-heading">
                    <p className="asked">{text.askedLabel}<span dir="auto">{asked}</span></p>
                    <h2 id="outcome-heading" className={`outcome ${view.brief ? "answered" : "refused"}`}>
                      {text.outcomes[view.outcome]}
                    </h2>
                    {text.reasons[view.reason] && <p>{text.reasons[view.reason]}</p>}
                    {view.brief && <p dir="auto" className="brief">{view.brief}</p>}
                    {view.proofId && (
                      <p className="proof">
                        {view.alreadyCommitted ? text.alreadyCommitted : text.justCommitted}{" "}
                        <code dir="ltr">{view.proofId}</code>
                      </p>
                    )}
                  </section>
                )}
              </div>

              {view && view.citations.length > 0 && (
                <section aria-labelledby="citations-heading">
                  <h2 id="citations-heading">{text.citationsHeading}</h2>
                  <ul className="citations">
                    {view.citations.map((citation) => (
                      <li key={`${citation.claimId}-${citation.startScalar}`}>
                        <button type="button" onClick={() => setSelected(citation)}>
                          {text.showCitedSpanPrefix}<span dir="ltr">{citation.sourceId}</span>
                        </button>
                      </li>
                    ))}
                  </ul>
                </section>
              )}
              {selected && <SourcePanel citation={selected} text={text} />}
              {view && <FunnelTrace view={view} text={text} />}
            </>
          )}

          {activeTab !== "ask" && overviewError && (
            <p className="failure" role="alert">{text.failurePrefix}{overviewError}</p>
          )}
          {activeTab !== "ask" && !overview && !overviewError && (
            <p className="notice">{text.loadingOverview}</p>
          )}
          {activeTab === "evidence" && overview && <EvidenceSection overview={overview} text={text} />}
          {activeTab === "review" && overview && <DeepReviewSection overview={overview} text={text} />}
          {activeTab === "packs" && overview && <PacksSection overview={overview} text={text} />}
          {activeTab === "privacy" && overview && <PrivacySection overview={overview} text={text} />}
        </div>
      </main>
    </div>
  );
}
