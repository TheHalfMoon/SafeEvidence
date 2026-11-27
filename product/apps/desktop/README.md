# SafeEvidence desktop shell

Tauri 2 and React shell with one Ask view, `plan-v1.1` §C step 4. It answers over the invented fixture only.

```bash
npm ci
npm test
npx tauri dev
```

Native tests: `cargo test --locked --manifest-path src-tauri/Cargo.toml`.

Rust dependencies live in this crate's own workspace, so Tauri stays out of the core's `product/Cargo.lock`. Provenance and limits are in
`PROVENANCE.md`.
