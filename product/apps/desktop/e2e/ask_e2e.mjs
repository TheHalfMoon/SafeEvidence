// Drives the Ask checks in a real WebView2 window, over its debugging protocol. Windows only: WebView2 is what
// exposes this protocol. It uses no packages.
//
// Usage: node e2e/ask_e2e.mjs <path to an app built with --features custom-protocol,e2e>

import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";

import { runAskChecks, waitFor } from "./ask_checks.mjs";

// The port the app's `e2e` feature opens. See `main.rs`.
const PORT = 9333;
const APP_ORIGIN = "http://tauri.localhost";
const executable = process.argv[2];
assert.ok(executable, "pass the app's path");

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
      // This defaults to true, which would let the CSP check pass or fail for the wrong reason.
      allowUnsafeEvalBlockedByCSP: false,
    });
    if (exceptionDetails) throw new Error(exceptionDetails.exception?.description ?? exceptionDetails.text);
    return result.value;
  }

  isAppRequest(url) {
    return /^(http:\/\/(tauri|ipc)\.localhost(:\d+)?\/|data:|blob:)/.test(url);
  }

  close() {
    this.#socket.close();
  }
}

const HOST_REPORT = `
  Get-CimInstance Win32_Process |
    Where-Object Name -Match 'msedgewebview2|safeevidence' |
    ForEach-Object { "$($_.ProcessId) $($_.Name) $($_.CommandLine)" }
  Get-ItemProperty 'HKLM:/SOFTWARE/WOW6432Node/Microsoft/EdgeUpdate/Clients/{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}' -ErrorAction SilentlyContinue |
    ForEach-Object { "WebView2 Runtime $($_.pv)" }
`;

const appOutput = [];
let app = null;

await runAskChecks({
  expectedChecks: 11,
  keyStore: {
    name: "real DPAPI",
    check: (stored) => assert.ok(stored.includes("dpapi"), stored.join()),
  },

  async launch(dataDir) {
    app = spawn(executable, [], {
      stdio: ["ignore", "pipe", "pipe"],
      env: { ...process.env, SAFEEVIDENCE_E2E_DATA_DIR: dataDir },
    });
    for (const stream of [app.stdout, app.stderr]) {
      stream.on("data", (chunk) => appOutput.push(String(chunk)));
    }
    app.once("exit", (code) => appOutput.push(`[app exited with ${code}]\n`));
    return Page.open();
  },

  async stop() {
    if (app && app.exitCode === null && app.signalCode === null) {
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
  },

  async diagnose() {
    console.log("--- app output\n" + (appOutput.join("") || "(none)"));
    const host = spawnSync("powershell", ["-NoProfile", "-Command", HOST_REPORT], { encoding: "utf8", timeout: 60_000 });
    console.log("--- host\n" + (host.stdout || "(none)") + (host.stderr ?? ""));
    try {
      console.log("--- debugging targets\n" + (await (await fetch(`http://127.0.0.1:${PORT}/json`)).text()));
    } catch (error) {
      console.log(`--- debugging port unreachable: ${error.message}`);
    }
  },
});
