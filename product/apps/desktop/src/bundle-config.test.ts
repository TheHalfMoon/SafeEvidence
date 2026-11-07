// The shell configuration stays inside its authorized scope.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";

const read = (path: string) => readFileSync(new URL(path, import.meta.url), "utf8");
const conf = JSON.parse(read("../src-tauri/tauri.conf.json"));
const capability = JSON.parse(read("../src-tauri/capabilities/default.json"));

test("this build packages nothing and adds no updater or plugin", () => {
  assert.equal(conf.bundle.active, false);
  assert.equal(conf.plugins, undefined);
  assert.equal(conf.bundle.createUpdaterArtifacts, undefined);
  assert.deepEqual(conf.app.security.capabilities, ["default"]);
});

test("the main window may call the named command and nothing else", () => {
  assert.deepEqual(capability.windows, ["main"]);
  assert.deepEqual(capability.permissions, ["allow-ask-question"]);
  assert.equal(capability.remote, undefined);
});

test("production CSP allows no remote origin and no inline style or script", () => {
  const csp: string = conf.app.security.csp;
  assert.doesNotMatch(csp, /https?:\/\/(?!ipc\.localhost)/);
  assert.doesNotMatch(csp, /unsafe-inline|unsafe-eval/);
  assert.match(csp, /default-src 'none';/);
  assert.match(csp, /style-src 'self';/);
  assert.match(csp, /script-src 'self';/);
  assert.match(csp, /connect-src ipc: http:\/\/ipc\.localhost;/);
  assert.match(csp, /frame-ancestors 'none'/);
});

test("the end-to-end data directory and debugging port exist only behind their own feature", () => {
  const manifest = read("../src-tauri/Cargo.toml");
  assert.doesNotMatch(manifest, /^default\s*=/m);
  assert.match(manifest, /^e2e = \[\]$/m, "the feature enables nothing else");
  assert.match(manifest, /^custom-protocol = \["tauri\/custom-protocol"\]$/m, "the shipped feature does not imply it");
  const main = read("../src-tauri/src/main.rs");
  const name = "SAFEEVIDENCE_E2E_DATA_DIR";
  assert.equal(main.split(name).length, 2, "read in exactly one place");
  const use = main.indexOf(name);
  assert.match(main.slice(Math.max(0, use - 100), use), /#\[cfg\(feature = "e2e"\)\]/);
  assert.match(main, /#\[cfg\(all\(feature = "e2e", not\(debug_assertions\)\)\)\]\ncompile_error!/, "a release build refuses it");
  const port = "--remote-debugging-port";
  assert.equal(main.split(port).length, 2, "opened in exactly one place");
  assert.match(main.slice(Math.max(0, main.indexOf(port) - 300), main.indexOf(port)), /#\[cfg\(all\(feature = "e2e", windows\)\)\]/);
  const conf = read("../src-tauri/tauri.conf.json");
  assert.doesNotMatch(conf, /remote-debugging|additionalBrowserArgs/, "the config reaches shipped builds");
  for (const file of readdirSync(new URL("../src-tauri/src/", import.meta.url))) {
    if (file !== "main.rs") assert.doesNotMatch(read(`../src-tauri/src/${file}`), /remote-debugging|additional_browser_args/, file);
  }
  const scripts = read("../package.json");
  assert.doesNotMatch(conf + scripts, /\be2e\b/);
});

test("the Rust manifest pins Tauri and enables no extra feature", () => {
  const manifest = read("../src-tauri/Cargo.toml");
  assert.match(manifest, /tauri = \{ version = "=2\.12\.0", default-features = false, features = \["wry", "common-controls-v6", "x11"\] \}/);
  assert.doesNotMatch(manifest, /tauri-plugin|reqwest|updater/);
});
