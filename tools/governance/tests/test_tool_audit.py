"""The tool audit must flag what it names, and this repository's tools must pass it."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "donor"))
import tool_audit as check  # noqa: E402

ROOT = Path(__file__).resolve().parents[3]


class ToolAuditTests(unittest.TestCase):
    def test_this_repository_passes(self):
        self.assertEqual(check.audit_repository(ROOT), [])

    def test_the_audit_covers_the_gate_scripts(self):
        names = {path.name for path in check.audited_paths(ROOT)}
        for name in ("source_admission_check.py", "ta29_dependency_denial.py", "ta29_desktop_denial.py", "tool_audit.py"):
            self.assertIn(name, names)

    def test_every_allowed_tool_exists(self):
        for relative in check.SUBPROCESS_ALLOWED:
            self.assertTrue((ROOT / relative).is_file(), relative)

    def test_network_imports_are_flagged_in_each_form(self):
        for source in ("import socket", "import urllib.request", "from http import client", "import os, ssl", "from ftplib import FTP"):
            with self.subTest(source=source):
                self.assertTrue(check.audit_source(source, may_spawn=True))

    def test_dynamic_execution_is_flagged(self):
        for source in ("eval('1')", "exec('1')", "compile('1', 'x', 'exec')", "__import__('socket')"):
            with self.subTest(source=source):
                self.assertTrue(check.audit_source(source))

    def test_subprocess_needs_the_allowance(self):
        self.assertTrue(check.audit_source("import subprocess"))
        self.assertTrue(check.audit_source("from subprocess import run"))
        self.assertEqual(check.audit_source("import subprocess", may_spawn=True), [])

    def test_plain_tools_and_lookalikes_pass(self):
        source = "import json\nfrom pathlib import Path\nimport socketserverish\nre_compile = 1\nx.eval('1')\n"
        self.assertEqual(check.audit_source(source), [])

    def test_relative_imports_are_not_mistaken_for_the_standard_library(self):
        self.assertEqual(check.audit_source("from .http import helper"), [])

    def test_unparsable_source_fails_instead_of_passing(self):
        with self.assertRaises(SyntaxError):
            check.audit_source("def (")


if __name__ == "__main__":
    unittest.main()
