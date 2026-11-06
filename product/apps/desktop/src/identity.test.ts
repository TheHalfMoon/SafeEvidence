// Product-facing surfaces carry this product's identity, not the donor's.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join } from "node:path";

const app = fileURLToPath(new URL("../", import.meta.url));

function walk(dir: string): string[] {
  return readdirSync(join(app, dir)).flatMap((name) => {
    const rel = join(dir, name);
    return statSync(join(app, rel)).isDirectory() ? walk(rel) : [rel];
  });
}

test("no donor identity reaches a product surface", () => {
  const surfaces = [
    ...walk("src").filter((path) => /\.(tsx?|css)$/.test(path) && !path.endsWith(".test.ts")),
    "index.html",
    "package.json",
    join("src-tauri", "tauri.conf.json"),
    join("src-tauri", "Cargo.toml"),
    join("src-tauri", "src", "startup_failure.rs"),
  ];
  const hits = surfaces.filter((path) => /medscale|ottari|himsat/i.test(readFileSync(join(app, path), "utf8")));
  assert.deepEqual(hits, []);
});

test("product name and window title are SafeEvidence", () => {
  const conf = JSON.parse(readFileSync(join(app, "src-tauri", "tauri.conf.json"), "utf8"));
  assert.equal(conf.productName, "SafeEvidence");
  assert.ok(conf.app.windows.every((window: { title: string }) => window.title === "SafeEvidence"));
});

test("the view states it uses invented data and is not medical information", () => {
  const view = readFileSync(join(app, "src", "App.tsx"), "utf8");
  assert.match(view, /Invented engineering fixture\. Not medical information\./);
});
