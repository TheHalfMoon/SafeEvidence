# `safeevidence-network` Provenance

- **Admission:** `ADM-0015` (`T05`)
- **Upstream Donor:** `AbdulazizShehri/MedScale` @ `5c33d77c0a82748c1fab85a9f2fd7b515145fea2` (`Apache-2.0`)
- **Authorization Basis:** `PUBLIC_LICENSE` under `docs/adr/0004-public-license-source-admission-and-zero-cost-governance-simplification.md`
- **Adaptations:** Removed `ureq` to preserve `TA-29` HTTP-client exclusion; enforced `NetworkMode::NetworkLocked` default denial, SSRF IPv4/IPv6 filtering, and `TA-30` `OutboundQueryPreview` + `EgressApprovalReceipt` cryptographic digest verification.
