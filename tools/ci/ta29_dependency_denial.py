#!/usr/bin/env python3
"""TA-29 HTTP-client clause: no shipped crate may depend on a denied HTTP client.

Checks every target's normal dependencies. `safeevidence-network`, the one crate allowed
an HTTP client by the architecture, does not exist yet, so nothing is exempt. Xberg and
docling.rs clauses bind WP-13 (plan-v1.1). This does not detect sockets opened directly.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

DENIED = {"reqwest", "ureq", "hyper", "hf-hub", "liter-llm"}
TREE = [
    "cargo", "tree", "--offline", "--locked", "--workspace", "-e", "normal",
    "--target", "all", "--prefix", "none", "--format", "{p}",
]


def package_names(tree_output: str) -> set[str]:
    names = set()
    for line in tree_output.splitlines():
        parts = line.split()
        if parts:
            names.add(parts[0])
    return names


def violations(names: set[str]) -> set[str]:
    return names & DENIED


def main() -> int:
    root = Path(__file__).resolve().parents[2] / "product"
    result = subprocess.run(TREE, cwd=root, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        print(f"TA-29 FAIL: cargo tree failed: {result.stderr.strip()}")
        return 1
    names = package_names(result.stdout)
    if "safeevidence-contracts" not in names or "rusqlite" not in names:
        print("TA-29 FAIL: dependency tree looks incomplete")
        return 1
    found = violations(names)
    if found:
        print(f"TA-29 FAIL: denied crates present: {sorted(found)}")
        return 1
    print(f"TA-29 HTTP-client clause: PASS across {len(names)} packages")
    return 0


if __name__ == "__main__":
    sys.exit(main())
