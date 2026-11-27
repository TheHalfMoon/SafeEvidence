# `safeevidence-pack` Provenance

- **Admission:** `ADM-0016` (`T07`)
- **Upstream Donor:** `AbdulazizShehri/MedScale` @ `5c33d77c0a82748c1fab85a9f2fd7b515145fea2` (`Apache-2.0`)
- **Authorization Basis:** `PUBLIC_LICENSE` under `docs/adr/0004-public-license-source-admission-and-zero-cost-governance-simplification.md`
- **Adaptations:** `runtime.rs` intentionally excluded (`not_copied` per F8); implemented clean-room `#![forbid(unsafe_code)]` RFC 8032 Ed25519 signature verification (`src/trust.rs`) and monotonic epoch + SemVer + equivocation anti-rollback (`TA-06`, `TA-28`).
