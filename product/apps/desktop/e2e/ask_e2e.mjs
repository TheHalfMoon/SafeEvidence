// End-to-end Ask flow against the real app in a real WebView2 window, driven over its debugging protocol.
// Windows only: WebView2 is what exposes this protocol. It uses no packages.
//
// Usage: node e2e/ask_e2e.mjs <path to an app built with --features custom-protocol,e2e>
//
// It checks what a person would see, on the real native command and the real OS protector. It is the Ask
// subset of TA-20 on Windows. It says nothing about Ubuntu, Deep Review, pack import or TA-21: the network log
// here covers this page only, not the process. Mutants should be able to fail each check, so a probe that would
// pass with the protection removed does not belong here.

import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createServer } from "node:http";
import { mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";

const ANSWERED = "Does veltrixamine help adults with glimmer syndrome?";
const ASK_MORE = "Does veltrixamine help with glimmer syndrome?";
const OUTSIDE_GRAMMAR = "What should I take?";
const PORT = 9333;
const APP_ORIGIN = "http://tauri.localhost";
const executable = process.argv[2];
assert.ok(executable, "pass the app's path");

async function waitFor(check, what, timeoutMs = 60_000) {
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

class Page {
  #socket;
  #next = 1;
  #pending = new Map();
  requests = [];

  static async open() {
    const target = await waitFor(async () => {
      const targets = await (await fetch(`http://127.0.0.1:${PORT}/json`)).json();
      return targets.find((item) => item.type === "page" && item.url.startsWith(APP_ORIGIN));
      // A cold hosted runner can take far longer than a developer machine to start WebView2.
    }, "the app's page", 180_000);
    const page = new Page();
    page.#socket = new WebSocket(target.webSocketDebuggerUrl);
    await new Promise((resolve, reject) => {
      page.#socket.onopen = resolve;
      page.#socket.onerror = reject;
    });
    page.#socket.onmessage = (event) => page.#receive(JSON.parse(event.data));
    // A crash must fail the test now, not leave a call waiting forever.
    page.#socket.onclose = () => {
      for (const pending of page.#pending.values()) pending.reject(new Error("the page's connection closed"));
      page.#pending.clear();
    };
    await page.#send("Network.enable");
    await page.#send("Runtime.enable");
    return page;
  }

  #receive(message) {
    if (message.method === "Network.requestWillBeSent") this.requests.push(message.params.request.url);
    const pending = this.#pending.get(message.id);
    if (!pending) return;
    this.#pending.delete(message.id);
    if (message.error) pending.reject(new Error(message.error.message));
    else pending.resolve(message.result);
  }

  #send(method, params = {}) {
    const id = this.#next++;
    return new Promise((resolve, reject) => {
      // Sending on a closed socket is silently dropped, and the call would never settle.
      if (this.#socket.readyState !== WebSocket.OPEN) {
        reject(new Error("the page's connection is closed"));
        return;
      }
      this.#pending.set(id, { resolve, reject });
      this.#socket.send(JSON.stringify({ id, method, params }));
    });
  }

  async eval(expression) {
    const { result, exceptionDetails } = await this.#send("Runtime.evaluate", {
      expression,
      awaitPromise: true,
      returnByValue: true,
      // This defaults to true, which would let the CSP check below pass or fail for the wrong reason.
      allowUnsafeEvalBlockedByCSP: false,
    });
    if (exceptionDetails) throw new Error(exceptionDetails.exception?.description ?? exceptionDetails.text);
    return result.value;
  }

  close() {
    this.#socket.close();
  }

  // As React sees a person typing: its value tracker needs the native setter and a real input event.
  async ask(question) {
    await this.eval(`(() => {
      const box = document.querySelector("#question");
      Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value").set.call(box, ${JSON.stringify(question)});
      box.dispatchEvent(new Event("input", { bubbles: true }));
      document.querySelector('button[type="submit"]').click();
    })()`);
    await waitFor(
      () => this.eval(`document.querySelector(".asked span")?.textContent === ${JSON.stringify(question)} && !document.querySelector('button[type="submit"]').disabled`),
      `the reply to "${question}"`,
    );
  }

  view() {
    return this.eval(`({
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
}

const appOutput = [];

function launch(dataDir) {
  const app = spawn(executable, [], {
    stdio: ["ignore", "pipe", "pipe"],
    env: {
      ...process.env,
      SAFEEVIDENCE_E2E_DATA_DIR: dataDir,
      WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS: `--remote-debugging-port=${PORT}`,
    },
  });
  for (const stream of [app.stdout, app.stderr]) {
    stream.on("data", (chunk) => appOutput.push(String(chunk)));
  }
  app.once("exit", (code) => appOutput.push(`[app exited with ${code}]\n`));
  return app;
}

async function stop(app) {
  if (app.exitCode === null && app.signalCode === null) {
    const exited = new Promise((resolve) => app.once("exit", resolve));
    app.kill();
    await exited;
  }
  await waitFor(async () => {
    try {
      await fetch(`http://127.0.0.1:${PORT}/json`);
      return false;
    } catch {
      return true;
    }
  }, "the debugging port to close", 30_000);
}

const HOST_REPORT = `
  Get-CimInstance Win32_Process |
    Where-Object Name -Match 'msedgewebview2|safeevidence' |
    ForEach-Object { "$($_.ProcessId) $($_.Name) $($_.CommandLine)" }
  Get-ItemProperty 'HKLM:/SOFTWARE/WOW6432Node/Microsoft/EdgeUpdate/Clients/{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}' -ErrorAction SilentlyContinue |
    ForEach-Object { "WebView2 Runtime $($_.pv)" }
`;

async function diagnose() {
  console.log("--- app output\n" + (appOutput.join("") || "(none)"));
  const host = spawnSync("powershell", ["-NoProfile", "-Command", HOST_REPORT], { encoding: "utf8", timeout: 60_000 });
  console.log("--- host\n" + (host.stdout || "(none)") + (host.stderr ?? ""));
  console.log("--- data directory\n" + readdirSync(dataDir, { recursive: true }).slice(0, 40).join("\n"));
  try {
    console.log("--- debugging targets\n" + (await (await fetch(`http://127.0.0.1:${PORT}/json`)).text()));
  } catch (error) {
    console.log(`--- debugging port unreachable: ${error.message}`);
  }
}

const checks = [];
function passed(name) {
  checks.push(name);
  console.log(`ok - ${name}`);
}

const dataDir = mkdtempSync(join(tmpdir(), "se-e2e-"));
let child = launch(dataDir);
let failed = true;
try {
  let page = await Page.open();
  await waitFor(() => page.eval(`!!document.querySelector("#question")`), "the view");

  let view = await page.view();
  assert.match(view.body, /Invented engineering fixture\. Not medical information\./);
  passed("the view says its data is invented");

  await page.ask(ANSWERED);
  view = await page.view();
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
  assert.ok(stored.includes("vault.db") && stored.includes("store-established") && stored.includes("dpapi"), stored.join());
  passed("the store is in the test's own directory, with its key under real DPAPI");

  await page.ask(OUTSIDE_GRAMMAR);
  await page.ask(ANSWERED);
  view = await page.view();
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

  await page.ask(OUTSIDE_GRAMMAR);
  view = await page.view();
  assert.equal(view.outcome, "No answer given");
  assert.equal(view.brief, null);
  assert.equal(view.proof, null);
  assert.equal(view.citations, 0);
  assert.equal(view.funnel, 7);
  assert.equal(await page.eval(`document.querySelector("mark")`), null);
  passed("an abstention shows its outcome and funnel, and clears the earlier answer and its span");

  await page.ask(ASK_MORE);
  view = await page.view();
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

  const remote = page.requests.filter(
    (url) => !/^(http:\/\/(tauri|ipc)\.localhost(:\d+)?\/|data:|blob:)/.test(url) && url !== probeUrl,
  );
  assert.deepEqual(remote, []);
  passed("once loaded, this page requested nothing outside the app, apart from the CSP probe");

  // A core command that exists but is not granted, so a refusal can only come from the capability.
  const refusal = await page.eval(`window.__TAURI_INTERNALS__.invoke("plugin:app|version").then(() => "allowed", (error) => String(error))`);
  // Exact, because Tauri's "not found" errors for a renamed command also say "not allowed".
  assert.match(refusal, /^app\.version not allowed\. Permissions associated with this command/, refusal);
  passed("the capability refuses a real core command the page was not granted");

  page.close();
  await stop(child);
  child = launch(dataDir);
  page = await Page.open();
  await waitFor(() => page.eval(`!!document.querySelector("#question")`), "the view after restart");
  await page.ask(ANSWERED);
  view = await page.view();
  assert.equal(view.outcome, answered.outcome);
  assert.equal(view.proof, answered.proof);
  assert.equal(view.brief, answered.brief);
  assert.match(view.proofLine, /^Already committed as proof /);
  passed("after a kill and restart, the proof is still in the store");
  page.close();
  failed = false;
} catch (error) {
  await diagnose();
  throw error;
} finally {
  await stop(child).catch(() => {});
  console.log(`${checks.length} checks passed${failed ? ", then one failed" : ""}`);
  // WebView2 can hold its files for a while after the process exits. A leftover directory holds invented
  // data only, and must not hide the test's real result.
  await sleep(1000);
  try {
    rmSync(dataDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 500 });
  } catch (error) {
    console.log(`note: could not remove ${dataDir}: ${error.code}`);
  }
}
