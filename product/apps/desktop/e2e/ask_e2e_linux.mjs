// Drives the Ask checks in a real WebKitGTK window, through WebKitWebDriver. Linux only. It uses no packages.
//
// Usage, inside a display and a session bus with an unlocked Secret Service:
//   node e2e/ask_e2e_linux.mjs <path to an app built with --features custom-protocol,e2e>
// The keyring helper must already be beside the app: nothing installs it there yet.

import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";

import { runAskChecks, waitFor } from "./ask_checks.mjs";

const PORT = 4444;
const ROOT = `http://127.0.0.1:${PORT}`;
const executable = process.argv[2];
assert.ok(executable, "pass the app's path");

async function request(method, path, body) {
  const response = await fetch(`${ROOT}${path}`, {
    method,
    headers: { "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const { value } = await response.json();
  if (!response.ok) throw new Error(`${value.error}: ${value.message}`);
  return value;
}

class Page {
  #session;

  constructor(session) {
    this.#session = session;
  }

  async eval(expression) {
    const outcome = await request("POST", `/session/${this.#session}/execute/async`, {
      script: `const done = arguments[arguments.length - 1];
        Promise.resolve().then(() => (${expression})).then((value) => done({ value }), (error) => done({ error: String(error) }));`,
      args: [],
    });
    if (outcome.error !== undefined) throw new Error(outcome.error);
    return outcome.value ?? null;
  }

  close() {}
}

const output = [];
let driver = null;

await runAskChecks({
  // On Linux the helper is the only way to the key, and a store dir that holds a wrapped key file would be wrong.
  keyStore: {
    name: "the real Secret Service",
    check: (stored) => assert.ok(!stored.includes("dpapi"), stored.join()),
  },

  async launch(dataDir) {
    driver = spawn("WebKitWebDriver", [`--port=${PORT}`], {
      stdio: ["ignore", "pipe", "pipe"],
      env: { ...process.env, SAFEEVIDENCE_E2E_DATA_DIR: dataDir, TAURI_WEBVIEW_AUTOMATION: "true" },
    });
    for (const stream of [driver.stdout, driver.stderr]) {
      stream.on("data", (chunk) => output.push(String(chunk)));
    }
    driver.once("exit", (code) => output.push(`[driver exited with ${code}]\n`));
    await waitFor(() => request("GET", "/status").then((status) => status.ready), "the driver", 30_000);
    const { sessionId } = await request("POST", "/session", {
      capabilities: {
        alwaysMatch: {
          browserName: "wry",
          "webkitgtk:browserOptions": { binary: executable, args: [] },
        },
      },
    });
    await request("POST", `/session/${sessionId}/timeouts`, { script: 60_000 });
    return new Page(sessionId);
  },

  // A real kill, so nothing gets a chance to close cleanly.
  async stop() {
    spawnSync("pkill", ["-KILL", "-f", executable]);
    if (driver && driver.exitCode === null && driver.signalCode === null) {
      const exited = new Promise((resolve) => driver.once("exit", resolve));
      driver.kill("SIGKILL");
      await exited;
    }
    await waitFor(() => spawnSync("pgrep", ["-f", executable]).status !== 0, "the app to exit", 30_000);
  },

  async diagnose() {
    console.log("--- driver and app output\n" + (output.join("") || "(none)"));
    const host = spawnSync("sh", ["-c", "ps -eo pid,args | grep -E 'safeevidence|WebKit|gnome-keyring' | grep -v grep"], { encoding: "utf8" });
    console.log("--- host\n" + (host.stdout || "(none)"));
  },
});
