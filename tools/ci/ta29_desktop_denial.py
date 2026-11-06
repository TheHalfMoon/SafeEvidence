#!/usr/bin/env python3
"""TA-29 HTTP-client clause for the desktop binary, on each desktop target it ships for.

The app has its own Cargo workspace, so `ta29_dependency_denial.py` does not see it. Tauri lists
`reqwest` for mobile targets only, so this checks named targets rather than `--target all`. Mobile
is not built yet and must pass before M5. It also refuses a list of known socket crates, because this process hosts
the core. `tokio` stays allowed: Tauri needs it, and without its `net` feature, which is what pulls in `mio`, it has
no socket driver. The list is partial, and `gio` and `webkit2gtk` are in the Linux tree. This does not detect sockets
opened directly.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from ta29_dependency_denial import package_names, violations

TARGETS = ("x86_64-pc-windows-msvc", "x86_64-unknown-linux-gnu", "aarch64-apple-darwin")
EXPECTED = {"safeevidence-desktop", "safeevidence-proofstore", "tauri"}
SOCKET_CRATES = {
    "async-io", "async-net", "async-std", "curl", "h2", "mio", "polling", "quinn", "smol", "socket2",
    "tungstenite", "zbus",
}


def tree(target: str) -> list[str]:
    return [
        "cargo", "tree", "--locked", "-e", "normal", "--target", target,
        "--prefix", "none", "--format", "{p}",
    ]


def main() -> int:
    root = Path(__file__).resolve().parents[2] / "product" / "apps" / "desktop" / "src-tauri"
    for target in TARGETS:
        result = subprocess.run(tree(target), cwd=root, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            print(f"TA-29 FAIL: cargo tree failed for {target}: {result.stderr.strip()}")
            return 1
        names = package_names(result.stdout)
        if not EXPECTED <= names:
            print(f"TA-29 FAIL: dependency tree for {target} looks incomplete")
            return 1
        found = violations(names) | (names & SOCKET_CRATES)
        if found:
            print(f"TA-29 FAIL: denied crates for {target}: {sorted(found)}")
            return 1
        print(f"TA-29 HTTP-client clause, desktop on {target}: PASS across {len(names)} packages")
    return 0


if __name__ == "__main__":
    sys.exit(main())
