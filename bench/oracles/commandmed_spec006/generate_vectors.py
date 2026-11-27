#!/usr/bin/env python3
"""Generate T13 parity vectors by running the donor's `evaluate_precedence`.

Usage: generate_vectors.py <checkout of TheHalfMoon/commandMed at the pinned commit> <output.json>

The donor's code stays out of this repository; only its outputs on a synthetic rule grid are
kept. Every combination of up to three rules is run. EMERGENCY is left out because P00 disables
it in V1, and the Rust port fails closed on it instead of matching the donor.
"""
from __future__ import annotations

import itertools
import json
import sys
from pathlib import Path

PIN = "51f73ec05750137e5bd94ffa0765f6383f475fee"
STATES = ["ANSWER", "ASK_MORE", "ABSTAIN", "ESCALATE", "USE_TOOL", "RETRIEVE_EVIDENCE"]
PRECEDENCES = [1, 2, 3]


def main() -> int:
    checkout, output = Path(sys.argv[1]), Path(sys.argv[2])
    sys.path.insert(0, str(checkout))
    from src.commandmed.spec006.policy import BEHAVIORAL_STATES, evaluate_precedence

    missing = set(STATES) - set(BEHAVIORAL_STATES)
    if missing:
        raise SystemExit(f"donor vocabulary lacks {sorted(missing)}")
    options = [(state, precedence) for state in STATES for precedence in PRECEDENCES]
    vectors = []
    for size in (1, 2, 3):
        for combination in itertools.combinations_with_replacement(options, size):
            rules = [
                {"rule_id": f"SCAFFOLD::{index}", "precedence": precedence, "required_state": state}
                for index, (state, precedence) in enumerate(combination)
            ]
            result = evaluate_precedence(rules)
            vectors.append(
                {
                    "rules": [[state, precedence] for state, precedence in combination],
                    "state": result["state_after"],
                    "conflict": "CONFLICTING_SAFETY_OUTCOMES" in result["reason_codes"],
                    "winners": [int(r.split("::")[1]) for r in result["trigger_record_ids"]],
                }
            )
    document = {"donor": "TheHalfMoon/commandMed", "commit": PIN, "vectors": vectors}
    output.write_text(json.dumps(document, separators=(",", ":")) + "\n", encoding="utf-8")
    print(f"{len(vectors)} vectors")
    return 0


if __name__ == "__main__":
    sys.exit(main())
