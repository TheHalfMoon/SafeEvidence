# Provenance: product workspace root

`deny.toml`: admission `ADM-0002` (T11) in `docs/evidence/source_admissions.json`.

- Source: `AbdulazizShehri/MedScale` @ `5c33d77c0a82748c1fab85a9f2fd7b515145fea2`, `deny.toml`, Apache-2.0.
- Rights decision: https://github.com/TheHalfMoon/SafeEvidence/issues/5#issuecomment-6647500204
- Adapted: header comment renamed. The license allowlist is replaced by the master plan's
  §7 list, and all per-crate exceptions are removed.
- SafeEvidence addition: `[bans]` denies the HTTP clients named by TA-29.
- Not stricter in one respect: MPL-2.0 moves from five per-crate exceptions to the general
  allowlist, as the plan's allowlist specifies. No current dependency uses it.
