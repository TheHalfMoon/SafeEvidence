# Provenance: product workspace root

`deny.toml`: admission `ADM-0002` (T11) in `docs/evidence/source_admissions.json`.

- Source: `AbdulazizShehri/MedScale` @ `5c33d77c0a82748c1fab85a9f2fd7b515145fea2`, `deny.toml`, Apache-2.0.
- Rights decision: https://github.com/TheHalfMoon/SafeEvidence/issues/5#issuecomment-6647500204
- Adapted: header comment renamed. The license allowlist is replaced by the master plan's
  §7 list, and all per-crate exceptions are removed.
- SafeEvidence addition: `[bans]` denies the HTTP clients named by TA-29.
- Not stricter in one respect: MPL-2.0 moves from five per-crate exceptions to the general
  allowlist, as the plan's allowlist specifies. No current dependency uses it.
- Scoped advisory exception: `RUSTSEC-2026-0459` (`CVE-2026-119375`, mismatched SQLite `-wal` page size on
  SQLite `< 3.54.0`), mitigated in `safeevidence-vault::vault_sqlcipher` by rejecting any non-empty `< 32`-byte
  or page-size `!= 4096` sibling `-wal` pre-open and pinning codec `cipher_page_size == 4096` (so `sqlite3Codec`
  HMAC-SHA512 zeroes unauthenticated 4096-byte page buffers even if a local process races the lazy `-wal` open;
  `safeevidence-ask` opens `:memory:` only). `libsqlite3-sys 0.39.x` switches `bundled-sqlcipher` to `sqlcipher-src`
  `419.0.6` (still bundling SQLite `3.53.4 < 3.54.0` under unadmitted `WTFPL`/`blessing` licenses).
