"""The desktop TA-29 check must name the shipped desktop targets and reuse the same denial list."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "ci"))
import ta29_desktop_denial as check  # noqa: E402


class DesktopDenialTests(unittest.TestCase):
    def test_every_desktop_platform_is_checked(self):
        self.assertEqual(
            {target.split("-", 2)[-1].split("-")[0] for target in check.TARGETS},
            {"windows", "linux", "darwin"},
        )

    def test_the_check_is_per_target_not_all_targets(self):
        for target in check.TARGETS:
            command = check.tree(target)
            self.assertEqual(command[command.index("--target") + 1], target)
            self.assertIn("--locked", command)
            self.assertEqual(command[command.index("-e") + 1], "normal")

    def test_a_denied_crate_is_caught(self):
        names = check.package_names("tauri v2.12.0\nreqwest v0.13.5\n")
        self.assertEqual(check.violations(names), {"reqwest"})


if __name__ == "__main__":
    unittest.main()
