#!/usr/bin/env python3
"""Generate TA-13's fixture-subset vectors by running the donor's interaction scaffold.

Usage: generate_case_vectors.py <checkout of TheHalfMoon/commandMed at the pinned commit> <output directory>

Writes one `t13_cases_<fixture>.json` per donor fixture file.

Each case keeps the question text, the rules the donor's pipeline actually fired, and its final state.
The Rust port then resolves those same rules (`plan-v1.4`). The donor's code stays out of this
repository. Cases P00 excludes keep their reason and text, and their fired rules are dropped.
Reason codes are not kept. The caller must pass a checkout at the pinned commit; this does not verify it.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

PIN = "51f73ec05750137e5bd94ffa0765f6383f475fee"
FIXTURES = ["us1-tool-routing", "us2-context-safety", "us3-injection-spoof"]
LEXICAL_EMERGENCY = "lexical emergency trigger, which P00 disables in V1"
EXCLUDED = {
    "emergency-keyword-en": LEXICAL_EMERGENCY,
    "emergency-keyword-ar-msa": LEXICAL_EMERGENCY,
    "ambiguous-risk-fails-toward-escalation-not-answer": LEXICAL_EMERGENCY,
    "injection-suppressed-emergency-preserved": LEXICAL_EMERGENCY,
    "severe-pattern-escalates": "symptom-phrase trigger for ESCALATE, which P00 guard 2 forbids",
}
INTERACTION_ID = "22222222-3333-4444-8555-666666666666"


def main() -> int:
    checkout, output = Path(sys.argv[1]), Path(sys.argv[2])
    sys.path.insert(0, str(checkout))
    from src.commandmed.spec006 import policy, scaffold

    def bundle(name: str) -> dict:
        return json.loads((checkout / "data/spec006" / name).read_text(encoding="utf-8"))

    registry, safety, prerequisites = (
        bundle("tool_registry.json"),
        bundle("safety_policy.json"),
        bundle("evidence_prerequisites.json"),
    )
    captured: list[list[dict]] = []
    original = policy.evaluate_precedence

    def capture(fired_rules):
        captured.append(json.loads(json.dumps(fired_rules)))
        return original(fired_rules)

    policy.evaluate_precedence = capture

    total = 0
    for name in FIXTURES:
        cases = []
        path = checkout / "tests/spec006/fixtures" / f"{name}.json"
        for case in json.loads(path.read_text(encoding="utf-8"))["cases"]:
            captured.clear()
            decision = scaffold.evaluate_interaction(
                INTERACTION_ID, case["request"], case["context"], registry, safety, prerequisites
            )
            if decision["state_after"] != case["expected_state_after"]:
                raise SystemExit(f"{case['case_id']}: donor gave {decision['state_after']}")
            if len(captured) != 1:
                raise SystemExit(f"{case['case_id']}: precedence ran {len(captured)} times")
            reason = EXCLUDED.get(case["case_id"])
            fired = [
                [rule["rule_id"], rule["precedence"], rule["required_state"]]
                for rule in captured[0]
            ]
            cases.append(
                {
                    "case_id": case["case_id"],
                    "text": case["request"]["text"],
                    "excluded_reason": reason,
                    "fired": [] if reason else fired,
                    "donor_state": None if reason else decision["state_after"],
                }
            )
        document = {"donor": "TheHalfMoon/commandMed", "commit": PIN, "cases": cases}
        target = output / f"t13_cases_{name.replace('-', '_')}.json"
        target.write_bytes((json.dumps(document, indent=1, ensure_ascii=False) + "\n").encode("utf-8"))
        total += len(cases)
    print(f"{total} cases")
    return 0


if __name__ == "__main__":
    sys.exit(main())
