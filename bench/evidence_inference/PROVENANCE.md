# Provenance: bench/evidence_inference

Admission `ADM-0032` (`T28`) in `docs/evidence/source_admissions.json`.

- Donor: `jayded/evidence-inference` @ `a661e8c14f973398380c8865cf2f27a535aaaf6d`, MIT (`ADR-0004`).
- Verbatim (`modification: "none"`): `LICENSE` (`65dfccb60c9e43e2527d262db5e6a4a2fb1047b2`, 1116 bytes).
- Adapted (`modification: "adapted"`):
  - `evidence_inference/preprocess/preprocessor.py` -> `ei_schema.py` (Python stdlib-only PICO prompt, 3-class significance label `-1/0/+1`, and exact character-span validation).
  - `evidence_inference/models/pipeline.py` -> `ei_eval.py` (Python stdlib-only 3-class PICO macro-F1, accuracy, span IoU hit-rate, and joint grounded accuracy evaluator).
- SafeEvidence-written: `test_ei_eval.py` (synthetic RCT benchmark evaluator unit tests).
- Scope restriction: Strictly confined to `bench/evidence_inference/` for offline benchmark evaluation; never imported or bundled in shipped product binaries. External PMC Open Access articles are not copied in-tree.
