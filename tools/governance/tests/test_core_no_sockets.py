"""The core's socket check must name the crates it guards, and leave out only the helper."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "ci"))
import core_no_sockets as check  # noqa: E402


class CoreNoSocketsTests(unittest.TestCase):
    def test_the_helper_is_outside_the_core_and_the_vault_is_inside(self):
        self.assertNotIn("safeevidence-linux-keyring-helper", check.CORE)
        for package in ("safeevidence-vault", "safeevidence-proofstore", "safeevidence-ask"):
            self.assertIn(package, check.CORE)

    def test_socket_crates_are_caught_and_lookalikes_are_not(self):
        for name in ("mio", "socket2", "tokio", "zbus"):
            self.assertEqual(check.violations({"serde", name}), {name})
        self.assertEqual(check.violations({"serde", "tokio-util-not", "miopia"}), set())

    def test_each_target_and_core_package_reaches_the_command(self):
        for target in check.TARGETS:
            command = check.tree(target)
            self.assertEqual(command[command.index("--target") + 1], target)
            for package in check.CORE:
                self.assertIn(package, command)
            self.assertEqual(command[command.index("-e") + 1], "normal")


if __name__ == "__main__":
    unittest.main()
