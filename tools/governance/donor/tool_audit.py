#!/usr/bin/env python3
"""Audits this repository's governance and CI Python for forbidden network modules, dynamic
execution primitives, OS command-spawning shortcuts, and `subprocess` outside named tools.

Adapted from T30 (`ADM-0008`). It reads source only and runs nothing. It flags direct/from imports
across standard-library and common third-party network/FFI/import-loader packages, bare references
to dynamic execution builtins (`eval`, `exec`, `compile`, `__import__`), `os.system`/`popen`/`spawn*`
/`exec*` helpers, and `subprocess` imports outside the explicit allowlist. Tests under
`tools/governance/tests` are not audited. This guards against mistakes in trusted tools; it is not
an OS sandbox.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

BANNED_IMPORT_ROOTS = {
    "_ctypes",
    "_socket",
    "aiohttp",
    "builtins",
    "ctypes",
    "ftplib",
    "http",
    "httpx",
    "imaplib",
    "importlib",
    "poplib",
    "pty",
    "requests",
    "runpy",
    "smtplib",
    "socket",
    "socketserver",
    "ssl",
    "telnetlib",
    "urllib",
    "urllib3",
    "websocket",
    "websockets",
    "xmlrpc",
}
BANNED_DYNAMIC_NAMES = {"__builtins__", "__import__", "compile", "eval", "exec"}
BANNED_OS_SPAWN_ATTRS = {
    "execl",
    "execle",
    "execlp",
    "execlpe",
    "execv",
    "execve",
    "execvp",
    "execvpe",
    "fork",
    "forkpty",
    "popen",
    "posix_spawn",
    "posix_spawnp",
    "spawnl",
    "spawnle",
    "spawnlp",
    "spawnlpe",
    "spawnv",
    "spawnve",
    "spawnvp",
    "spawnvpe",
    "startfile",
    "system",
}
# Each of these must run a named tool, so it may import `subprocess`. Any other tool may not.
SUBPROCESS_ALLOWED = {
    "tools/ci/core_no_sockets.py",
    "tools/ci/ta29_dependency_denial.py",
    "tools/ci/ta29_desktop_denial.py",
    "tools/governance/p01_preentry_check.py",
}
AUDITED_DIRECTORIES = ("tools/ci", "tools/governance")
EXCLUDED_DIRECTORY = "tools/governance/tests"


def audit_source(source: str, *, may_spawn: bool = False) -> list[str]:
    """Returns one problem per forbidden import, reference, or spawn helper."""
    problems = []
    os_aliases: set[str] = set()
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".", 1)[0]
                if root == "os":
                    os_aliases.add(alias.asname or "os")
                if root in BANNED_IMPORT_ROOTS:
                    problems.append(f"forbidden import {root}")
                if root == "subprocess" and not may_spawn:
                    problems.append("subprocess import outside the allowed tools")
        elif isinstance(node, ast.ImportFrom):
            # A relative import stays inside this repository.
            if node.module and not node.level:
                root = node.module.split(".", 1)[0]
                if root in BANNED_IMPORT_ROOTS:
                    problems.append(f"forbidden import {root}")
                if root == "subprocess" and not may_spawn:
                    problems.append("subprocess import outside the allowed tools")
                if root == "os":
                    for alias in node.names:
                        if alias.name in BANNED_OS_SPAWN_ATTRS or alias.name == "*":
                            problems.append(f"forbidden os spawn import {alias.name}")
        elif isinstance(node, ast.Name) and node.id in BANNED_DYNAMIC_NAMES:
            problems.append(f"forbidden dynamic execution symbol {node.id}")

    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id in os_aliases
            and node.attr in BANNED_OS_SPAWN_ATTRS
        ):
            problems.append(f"forbidden os spawn helper {node.value.id}.{node.attr}")
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
        problems += [
            f"{relative}: {problem}"
            for problem in audit_source(
                source, may_spawn=relative in SUBPROCESS_ALLOWED
            )
        ]
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
