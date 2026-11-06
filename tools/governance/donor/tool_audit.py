#!/usr/bin/env python3
"""Audits this repository's governance and CI Python for a named set of network modules, dynamic
execution calls, and `subprocess` outside named tools.

Adapted from T30 (`ADM-0008`). It reads source only and runs nothing. It finds direct imports and
calls by name, so `e = eval`, `importlib`, `os.system` and any module not listed, such as `requests`
or `smtplib`, pass. Tests under `tools/governance/tests` are not audited. This guards against
mistakes in trusted tools. It is not a sandbox.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

BANNED_IMPORT_ROOTS = {"ftplib", "http", "socket", "ssl", "urllib"}
BANNED_CALLS = {"__import__", "compile", "eval", "exec"}
# Each of these must run a named tool, so it may import `subprocess`. Any other tool may not.
SUBPROCESS_ALLOWED = {
    "tools/ci/ta29_dependency_denial.py",
    "tools/ci/ta29_desktop_denial.py",
    "tools/governance/p01_preentry_check.py",
}
AUDITED_DIRECTORIES = ("tools/ci", "tools/governance")
EXCLUDED_DIRECTORY = "tools/governance/tests"


def audit_source(source: str, *, may_spawn: bool = False) -> list[str]:
    """Returns one problem per forbidden import or call. Fails on source that does not parse."""
    problems = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            roots = {alias.name.split(".", 1)[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom):
            # A relative import stays inside this repository.
            roots = {node.module.split(".", 1)[0]} if node.module and not node.level else set()
        else:
            roots = set()
        for root in sorted(roots):
            if root in BANNED_IMPORT_ROOTS:
                problems.append(f"forbidden network import {root}")
            if root == "subprocess" and not may_spawn:
                problems.append("subprocess import outside the allowed tools")
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in BANNED_CALLS:
            problems.append(f"forbidden dynamic execution call {node.func.id}")
    return problems


def audited_paths(root: Path) -> list[Path]:
    excluded = root / EXCLUDED_DIRECTORY
    return sorted(
        path
        for directory in AUDITED_DIRECTORIES
        for path in (root / directory).rglob("*.py")
        if excluded not in path.parents and "__pycache__" not in path.parts
    )


def audit_repository(root: Path) -> list[str]:
    problems = []
    for path in audited_paths(root):
        relative = path.relative_to(root).as_posix()
        source = path.read_text(encoding="utf-8")
        problems += [f"{relative}: {problem}" for problem in audit_source(source, may_spawn=relative in SUBPROCESS_ALLOWED)]
    return problems


def main() -> int:
    root = Path(__file__).resolve().parents[3]
    problems = audit_repository(root)
    for problem in problems:
        print(f"Tool audit FAIL: {problem}")
    if problems:
        return 1
    print(f"Tool audit: PASS across {len(audited_paths(root))} files")
    return 0


if __name__ == "__main__":
    sys.exit(main())
