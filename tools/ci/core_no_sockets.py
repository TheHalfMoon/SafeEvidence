#!/usr/bin/env python3
"""Architecture section 2: the core process opens no sockets, so its tree holds no socket crates.

Checks the core crates' normal dependencies on each desktop target. The Linux keyring helper is left out on
purpose: it is a separate process, and holding `zbus` is its job. This reads the dependency tree, so it does not
detect a socket opened through `std::net`, and the list names known crates only. `ta29_desktop_denial.py` holds
the desktop shell to the crates that give it sockets.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from ta29_dependency_denial import package_names

CORE = (
    "safeevidence-contracts",
    "safeevidence-assurance",
    "safeevidence-ask",
    "safeevidence-keyring-wire",
    "safeevidence-vault",
    "safeevidence-proofstore",
)
SOCKET_CRATES = {
    "async-io", "async-net", "async-std", "curl", "h2", "hyper", "mio", "polling", "quinn", "reqwest",
    "smol", "socket2", "tokio", "tungstenite", "ureq", "zbus",
}
TARGETS = ("x86_64-pc-windows-msvc", "x86_64-unknown-linux-gnu", "aarch64-apple-darwin")


def tree(target: str) -> list[str]:
    packages = [argument for package in CORE for argument in ("-p", package)]
    return [
        "cargo", "tree", "--offline", "--locked", *packages, "-e", "normal",
        "--target", target, "--prefix", "none", "--format", "{p}",
    ]


def violations(names: set[str]) -> set[str]:
    return names & SOCKET_CRATES


def main() -> int:
    root = Path(__file__).resolve().parents[2] / "product"
    for target in TARGETS:
        result = subprocess.run(tree(target), cwd=root, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            print(f"Core socket check FAIL: cargo tree failed for {target}: {result.stderr.strip()}")
            return 1
        names = package_names(result.stdout)
        if not set(CORE) <= names:
            print(f"Core socket check FAIL: tree for {target} looks incomplete")
            return 1
        found = violations(names)
        if found:
            print(f"Core socket check FAIL: socket crates for {target}: {sorted(found)}")
            return 1
        print(f"Core socket check on {target}: PASS across {len(names)} packages")
    return 0


if __name__ == "__main__":
    sys.exit(main())
