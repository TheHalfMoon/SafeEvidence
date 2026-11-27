# Provenance: bench/scifact

Admission `ADM-0030` (`T27`) in `docs/evidence/source_admissions.json`.

- Donor: `allenai/scifact` @ `68b98a56d93e0f9da0d2aab4e6c3294699a0f72e`, Apache-2.0 (`ADR-0004`).
- Verbatim (`modification: "none"`): `LICENSE.md` (`18a738e109d7e3b28935a75d2134c5ccd602f403`, 542 bytes).
- Adapted (`modification: "adapted"`):
  - `verisci/evaluate/lib/data.py` -> `scifact_data.py` (Python stdlib-only JSONL/dataclass port; explicit UTF-8 context managers).
  - `verisci/evaluate/lib/metrics.py` -> `scifact_metrics.py` (Python stdlib-only sentence/abstract precision/recall/F1 port replacing `pandas.DataFrame` with deterministic dictionaries).
- SafeEvidence-written: `test_scifact_eval.py` (synthetic benchmark evaluator unit tests).
- Scope restriction: Strictly confined to `bench/scifact/` for offline benchmark evaluation; never imported or bundled in shipped product binaries. Underlying external SciFact claims (`CC-BY-4.0`) and abstracts (`ODC-By-1.0`) are not copied in-tree.
