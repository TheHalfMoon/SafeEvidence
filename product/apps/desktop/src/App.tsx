import { invoke } from "@tauri-apps/api/core";
import { type FormEvent, useEffect, useRef, useState } from "react";
import { type AskView, type Citation, FUNNEL_STAGES, OUTCOMES, REASONS, parseAskView, spanSegments } from "./ask-view";

const EXAMPLE = "Does veltrixamine help adults with glimmer syndrome?";

function FunnelTrace({ view }: { view: AskView }) {
  return (
    <section aria-labelledby="trace-heading">
      <h2 id="trace-heading">What was considered</h2>
      <ol className="funnel">
        {FUNNEL_STAGES.map(([stage, label]) => (
          <li key={stage}>
            <span className="count">{view.funnel[stage]}</span> {label}
          </li>
        ))}
      </ol>
      {view.excluded.length > 0 && (
        <>
          <h3>Excluded</h3>
          <ul>
            {view.excluded.map((item) => (
              <li key={item.docId}>
                <code dir="ltr">{item.docId}</code>: {item.reason}
              </li>
            ))}
          </ul>
        </>
      )}
    </section>
  );
}

function SourcePanel({ citation }: { citation: Citation }) {
  const mark = useRef<HTMLElement>(null);
  useEffect(() => {
    mark.current?.focus();
    mark.current?.scrollIntoView({ block: "center" });
  }, [citation]);
  const [before, span, after] = spanSegments(citation.sourceText, citation.startScalar, citation.endScalar);
  return (
    <section aria-labelledby="source-heading">
      <h2 id="source-heading">
        Source <code dir="ltr">{citation.sourceId}</code>, version <code dir="ltr">{citation.sourceVersion}</code>
      </h2>
      <p dir="auto" className="source">
        {before}
        <mark ref={mark} tabIndex={-1}>{span}</mark>
        {after}
      </p>
    </section>
  );
}

export function App() {
  const [question, setQuestion] = useState(EXAMPLE);
  const [view, setView] = useState<AskView | null>(null);
  const [selected, setSelected] = useState<Citation | null>(null);
  const [failure, setFailure] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setView(null);
    setSelected(null);
    setFailure(null);
    try {
      setView(parseAskView(await invoke("ask_question", { question })));
    } catch (error) {
      setFailure(String(error));
    } finally {
      setBusy(false);
    }
  }

  return (
    <main>
      <h1>SafeEvidence Ask</h1>
      <p className="notice" role="note">Invented engineering fixture. Not medical information.</p>
      <form onSubmit={submit}>
        <label htmlFor="question">Question</label>
        <textarea id="question" dir="auto" rows={2} maxLength={1024} value={question}
          onChange={(event) => setQuestion(event.target.value)} />
        <button type="submit" disabled={busy}>{busy ? "Checking" : "Ask"}</button>
      </form>

      <div aria-live="polite">
        {failure && <p className="failure" role="alert">No answer is shown: {failure}</p>}
        {view && (
          <section aria-labelledby="outcome-heading">
            <h2 id="outcome-heading" className={`outcome ${view.brief ? "answered" : "refused"}`}>{OUTCOMES[view.outcome]}</h2>
            {REASONS[view.reason] && <p>{REASONS[view.reason]}</p>}
            {view.brief && <p dir="auto" className="brief">{view.brief}</p>}
            {view.proofId && <p className="proof">Committed proof <code dir="ltr">{view.proofId}</code></p>}
          </section>
        )}
      </div>

      {view && view.citations.length > 0 && (
        <section aria-labelledby="citations-heading">
          <h2 id="citations-heading">Citations</h2>
          <ul className="citations">
            {view.citations.map((citation) => (
              <li key={`${citation.claimId}-${citation.startScalar}`}>
                <button type="button" onClick={() => setSelected(citation)}>
                  Show the cited span in <span dir="ltr">{citation.sourceId}</span>
                </button>
              </li>
            ))}
          </ul>
        </section>
      )}
      {selected && <SourcePanel citation={selected} />}
      {view && <FunnelTrace view={view} />}
    </main>
  );
}
