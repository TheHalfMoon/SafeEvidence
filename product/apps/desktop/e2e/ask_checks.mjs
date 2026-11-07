// The Ask flow's end-to-end checks, shared by the Windows and Linux drivers. It uses no packages.
//
// It checks what a person would see, on the real native command and the real OS protector. It is the Ask subset
// of TA-20. It says nothing about Deep Review, pack import or TA-21: where a driver has a network log, the log
// covers the page only, not the process. Mutants should be able to fail each check, so a probe that would pass
// with the protection removed does not belong here.
//
// A driver has:
// - `launch(dataDir)`, which starts the app and returns a page with `eval(expression)` and `close()`.
//   A page may have `requests` and `isAppRequest(url)`, if the driver can see the page's network.
// - `stop()`, which kills the app and waits until it has gone.
// - `diagnose()`, which reports what it can after a failure.
// - `keyStore`, which names the OS protector and checks the store's files for it.

import assert from "node:assert/strict";
import { mkdtempSync, readdirSync, rmSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";

const ANSWERED = "Does veltrixamine help adults with glimmer syndrome?";
const ASK_MORE = "Does veltrixamine help with glimmer syndrome?";
const OUTSIDE_GRAMMAR = "What should I take?";

export async function waitFor(check, what, timeoutMs = 60_000) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    try {
      const value = await check();
      if (value) return value;
    } catch {
      // Not ready yet.
    }
    assert.ok(Date.now() < deadline, `timed out waiting for ${what}`);
    await sleep(100);
  }
}

// As React sees a person typing: its value tracker needs the native setter and a real input event.
async function ask(page, question) {
  await page.eval(`(() => {
    const box = document.querySelector("#question");
    Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value").set.call(box, ${JSON.stringify(question)});
    box.dispatchEvent(new Event("input", { bubbles: true }));
    document.querySelector('button[type="submit"]').click();
  })()`);
  await waitFor(
    () => page.eval(`document.querySelector(".asked span")?.textContent === ${JSON.stringify(question)} && !document.querySelector('button[type="submit"]').disabled`),
    `the reply to "${question}"`,
  );
}

function readView(page) {
  return page.eval(`({
    outcome: document.querySelector("#outcome-heading")?.textContent ?? null,
    brief: document.querySelector(".brief")?.textContent ?? null,
    proof: document.querySelector(".proof code")?.textContent ?? null,
    proofLine: document.querySelector(".proof")?.textContent ?? null,
    citations: document.querySelectorAll(".citations button").length,
    funnel: document.querySelectorAll(".funnel li").length,
    failure: document.querySelector('[role="alert"]')?.textContent ?? null,
    body: document.body.innerText,
  })`);
}

export async function runAskChecks(driver) {
  const checks = [];
  const passed = (name) => {
    checks.push(name);
    console.log(`ok - ${name}`);
  };
  const dataDir = mkdtempSync(join(tmpdir(), "se-e2e-"));
  let failed = true;
  try {
    let page = await driver.launch(dataDir);
    await waitFor(() => page.eval(`!!document.querySelector("#question")`), "the view");

    let view = await readView(page);
    assert.match(view.body, /Invented engineering fixture\. Not medical information\./);
    passed("the view says its data is invented");

    await ask(page, ANSWERED);
    view = await readView(page);
    assert.equal(view.failure, null);
    assert.equal(view.outcome, "Answer, with caution");
    assert.ok(view.brief?.length > 0);
    assert.match(view.proof, /^vs1a-[0-9a-f]{64}$/);
    assert.match(view.proofLine, /^Just committed as proof /);
    assert.ok(view.citations > 0);
    assert.equal(view.funnel, 7);
    assert.doesNotMatch(view.body, /\d\s*%|confidence/i);
    passed("an answer shows its outcome, committed proof, citations and funnel, with no percentage");
    const answered = view;

    const stores = readdirSync(dataDir).filter((name) => name.startsWith("synthetic-ask-store-"));
    assert.equal(stores.length, 1);
    const stored = readdirSync(join(dataDir, stores[0]));
    assert.ok(stored.includes("vault.db") && stored.includes("store-established"), stored.join());
    driver.keyStore.check(stored);
    passed(`the store is in the test's own directory, with its key under ${driver.keyStore.name}`);

    await ask(page, OUTSIDE_GRAMMAR);
    await ask(page, ANSWERED);
    view = await readView(page);
    assert.equal(view.proof, answered.proof);
    assert.match(view.proofLine, /^Already committed as proof /);
    passed("asking again finds the proof in the store, so the first request really committed it");

    await page.eval(`document.querySelector(".citations button").click()`);
    const span = await waitFor(
      () => page.eval(`document.activeElement?.tagName === "MARK" ? document.activeElement.textContent : ""`),
      "focus on the cited span",
    );
    assert.ok(span.length > 0);
    assert.ok(answered.brief.includes(span), "the cited span appears in the brief");
    passed("span jump moves focus to the cited text, and that text is in the brief");

    await ask(page, OUTSIDE_GRAMMAR);
    view = await readView(page);
    assert.equal(view.outcome, "No answer given");
    assert.equal(view.brief, null);
    assert.equal(view.proof, null);
    assert.equal(view.citations, 0);
    assert.equal(view.funnel, 7);
    assert.equal(await page.eval(`document.querySelector("mark")`), null);
    passed("an abstention shows its outcome and funnel, and clears the earlier answer and its span");

    await ask(page, ASK_MORE);
    view = await readView(page);
    assert.equal(view.outcome, "More information needed");
    assert.equal(view.brief, null);
    passed("a question missing its population asks for more");

    // A local listener, so a blocked fetch is told from one that simply could not resolve a name.
    let probeHits = 0;
    const probe = createServer((_request, response) => {
      probeHits += 1;
      response.end("reached");
    });
    await new Promise((resolve) => probe.listen(0, "127.0.0.1", resolve));
    const probeUrl = `http://127.0.0.1:${probe.address().port}/`;
    const csp = await page.eval(`(async () => {
      const violated = [];
      document.addEventListener("securitypolicyviolation", (event) => violated.push(event.effectiveDirective));
      const style = document.createElement("style");
      style.textContent = "#question { order: 77; }";
      document.head.append(style);
      const inlineStyle = getComputedStyle(document.querySelector("#question")).order === "77";
      let remoteFetch = true;
      try { await fetch(${JSON.stringify(probeUrl)}, { mode: "no-cors" }); } catch { remoteFetch = false; }
      let inlineEval = true;
      try { new Function("return 1")(); } catch { inlineEval = false; }
      await new Promise((resolve) => setTimeout(resolve, 200));
      return { inlineStyle, remoteFetch, inlineEval, blockedFetch: violated.includes("connect-src") };
    })()`);
    await new Promise((resolve) => probe.close(resolve));
    // The event shows it was the CSP that stopped the fetch, not some other rule about loopback.
    assert.deepEqual(csp, { inlineStyle: false, remoteFetch: false, inlineEval: false, blockedFetch: true });
    assert.equal(probeHits, 0, "the fetch never reached the listener");
    passed("the running page's CSP blocks inline style, an off-app fetch and eval");

    if (page.requests) {
      const remote = page.requests.filter((url) => !page.isAppRequest(url) && url !== probeUrl);
      assert.deepEqual(remote, []);
      passed("once loaded, this page requested nothing outside the app, apart from the CSP probe");
    }

    // A core command that exists but is not granted, so a refusal can only come from the capability.
    const refusal = await page.eval(`window.__TAURI_INTERNALS__.invoke("plugin:app|version").then(() => "allowed", (error) => String(error))`);
    // Exact, because Tauri's "not found" errors for a renamed command also say "not allowed".
    assert.match(refusal, /^app\.version not allowed\. Permissions associated with this command/, refusal);
    passed("the capability refuses a real core command the page was not granted");

    page.close();
    await driver.stop();
    page = await driver.launch(dataDir);
    await waitFor(() => page.eval(`!!document.querySelector("#question")`), "the view after restart");
    await ask(page, ANSWERED);
    view = await readView(page);
    assert.equal(view.outcome, answered.outcome);
    assert.equal(view.proof, answered.proof);
    assert.equal(view.brief, answered.brief);
    assert.match(view.proofLine, /^Already committed as proof /);
    passed("after a kill and restart, the proof is still in the store");
    page.close();
    failed = false;
  } catch (error) {
    await driver.diagnose();
    // The web view is still running, so a directory can vanish during the walk. That must not hide the real failure.
    try {
      console.log("--- data directory\n" + readdirSync(dataDir, { recursive: true }).slice(0, 40).join("\n"));
    } catch (walkError) {
      console.log(`--- data directory unreadable: ${walkError.message}`);
    }
    throw error;
  } finally {
    await driver.stop().catch(() => {});
    console.log(`${checks.length} checks passed${failed ? ", then one failed" : ""}`);
    // A web view can hold its files for a while after the process exits. A leftover directory holds invented
    // data only, and must not hide the test's real result.
    await sleep(1000);
    try {
      rmSync(dataDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 500 });
    } catch (error) {
      console.log(`note: could not remove ${dataDir}: ${error.code}`);
    }
  }
}
