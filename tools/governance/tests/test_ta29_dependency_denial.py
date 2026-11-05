"""The TA-29 checker must catch a denied crate wherever it appears in the tree."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "ci"))
import ta29_dependency_denial as check  # noqa: E402


class DenialTests(unittest.TestCase):
    def test_every_denied_crate_is_caught(self):
        for name in sorted(check.DENIED):
            with self.subTest(name=name):
                tree = f"safeevidence-vault v0.0.0\n{name} v1.2.3\nserde v1.0.0 (*)\n"
                self.assertEqual(check.violations(check.package_names(tree)), {name})

    def test_clean_tree_and_lookalike_names_pass(self):
        tree = "hyperlocal-not v1.0.0\nmy-reqwest v0.1.0\nserde v1.0.0\n\n"
        self.assertEqual(check.violations(check.package_names(tree)), set())

    def test_workspace_paths_keep_the_package_name_only(self):
        names = check.package_names("safeevidence-vault v0.0.0 (C:\\repo\\product)\n")
        self.assertEqual(names, {"safeevidence-vault"})


if __name__ == "__main__":
    unittest.main()
