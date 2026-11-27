# `safeevidence-fhir` Provenance

- **Admission:** `ADM-0017` (`T09`)
- **Upstream Donor:** `AbdulazizShehri/MedScale` @ `5c33d77c0a82748c1fab85a9f2fd7b515145fea2` (`Apache-2.0`)
- **Authorization Basis:** `PUBLIC_LICENSE` under `docs/adr/0004-public-license-source-admission-and-zero-cost-governance-simplification.md`
- **Adaptations:** Enforces `FhirUsageScope::SyntheticResearchFixture` (`ADR-0003` non-clinical research scope, refusing live clinical patient context fail-closed) plus Unicode-escaped duplicate-key lexical rejection and pinned UCUM subset comparability.
