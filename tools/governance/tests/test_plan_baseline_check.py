"""Positive and negative tests for the V1 planning baseline check; no network."""
from __future__ import annotations

import json
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from plan_baseline_check import ARTIFACTS, FREEZE, PINS, normalized_digest, validate

REPO = Path(__file__).resolve().parents[3]


class PlanBaselineCheckTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for name in (*ARTIFACTS, FREEZE):
            dest = self.root / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(REPO / name, dest)

    def errors(self):
        return validate(self.root)["errors"]

    def edit(self, relative, old, new, count=1):
        path = self.root / relative
        text = path.read_text(encoding="utf-8")
        self.assertIn(old, text)
        path.write_text(text.replace(old, new, count), encoding="utf-8")

    def refreeze(self, relative):
        """Re-record a digest after an intentional edit so only the targeted rule fires."""
        digest = normalized_digest((self.root / relative).read_bytes())
        freeze = self.root / FREEZE
        text = freeze.read_text(encoding="utf-8")
        text = re.sub(
            rf"(\| `{re.escape(relative)}` \| `)[0-9a-f]{{64}}(`)",
            lambda m: m.group(1) + digest + m.group(2),
            text,
        )
        freeze.write_text(text, encoding="utf-8")

    def test_repository_baseline_passes(self):
        report = validate(REPO)
        self.assertEqual(report["errors"], [])
        self.assertEqual(report["structure"], "PASS")
        self.assertFalse(report["source_imports_authorized"])

    def test_digest_drift_fails(self):
        self.edit(ARTIFACTS[0], "Copy-First", "Copy-Later")
        self.assertTrue(any("Digest drift" in e for e in self.errors()))

    def test_crlf_checkout_does_not_drift(self):
        path = self.root / ARTIFACTS[1]
        # Normalize first: a Windows CI checkout may already be CRLF.
        lf = path.read_bytes().replace(b"\r\n", b"\n")
        path.write_bytes(lf.replace(b"\n", b"\r\n"))
        self.assertEqual(self.errors(), [])

    def test_admission_flip_fails(self):
        pins = self.root / PINS
        data = json.loads(pins.read_text(encoding="utf-8"))
        data["copy_authorized"] = True
        pins.write_text(json.dumps(data, indent=1) + "\n", encoding="utf-8")
        self.refreeze(PINS)
        self.assertTrue(any("copy_authorized" in e for e in self.errors()))

    def test_redaction_only_for_private_and_well_formed(self):
        pins = self.root / PINS
        data = json.loads(pins.read_text(encoding="utf-8"))
        data["packets"]["T01"]["redacted_file_manifest"] = {"file_count": 0, "commitment_sha256": "x"}
        pins.write_text(json.dumps(data, indent=1) + "\n", encoding="utf-8")
        self.refreeze(PINS)
        errors = self.errors()
        self.assertTrue(any("T01: malformed redacted_file_manifest" in e for e in errors))
        self.assertTrue(any("T01: only private repositories may be redacted" in e for e in errors))
        self.assertTrue(any("T01: redacted packet must not also list files" in e for e in errors))

    def test_duplicate_json_key_fails(self):
        pins = self.root / PINS
        text = pins.read_text(encoding="utf-8")
        pins.write_text(text.replace('"schema_version": 1,', '"schema_version": 1,\n "schema_version": 2,', 1), encoding="utf-8")
        self.refreeze(PINS)
        self.assertTrue(any("strict JSON" in e for e in self.errors()))

    def test_unknown_test_reference_fails(self):
        relative = "docs/plan/FEATURE_COVERAGE_MATRIX_V1.md"
        self.edit(relative, "| TA-13, TA-14, TA-20 |", "| TA-13, TA-99, TA-20 |")
        self.refreeze(relative)
        self.assertTrue(any("unknown test TA-99" in e for e in self.errors()))

    def test_scheduled_feature_without_packet_fails(self):
        relative = "docs/plan/FEATURE_COVERAGE_MATRIX_V1.md"
        self.edit(relative, "| SQLite FTS5, MedScale retriever (oracle) | D/O | WP-07 |",
                  "| SQLite FTS5, MedScale retriever (oracle) | D/O | none |")
        self.refreeze(relative)
        self.assertTrue(any("F03: scheduled feature without a work packet" in e for e in self.errors()))

    def test_work_packet_dependency_cycle_fails(self):
        relative = "docs/plan/IMPLEMENTATION_WORK_PACKETS_V1.md"
        self.edit(relative, "| WP-02 | Canonical contracts (P02) | C: T01;", "| WP-02 | Canonical contracts (P02) | C: T01;")
        path = self.root / relative
        text = path.read_text(encoding="utf-8")
        row_start = text.index("| WP-02 |")
        row_end = text.index("\n", row_start)
        cells = text[row_start:row_end].split("|")
        cells[4] = " WP-01, WP-03 "  # WP-03 already depends on WP-02
        path.write_text(text[:row_start] + "|".join(cells) + text[row_end:], encoding="utf-8")
        self.refreeze(relative)
        self.assertTrue(any("dependency cycle" in e for e in self.errors()))

    def test_matrix_commit_must_match_pins(self):
        relative = "docs/plan/SOURCE_TRANSPLANT_MATRIX_V1.md"
        self.edit(relative, "commandMed @ `51f73ec05750137e5bd94ffa0765f6383f475fee`",
                  "commandMed @ `0000000000000000000000000000000000000000`")
        self.refreeze(relative)
        self.assertTrue(any("T13: matrix commit" in e for e in self.errors()))

    def test_frozen_state_requires_tag_and_commit(self):
        # The canonical baseline is frozen; break both mandatory metadata fields.
        self.edit(FREEZE, "Freeze tag: `plan-v1.0.0`", "Freeze tag: `invalid`")
        path = self.root / FREEZE
        data = path.read_text(encoding="utf-8")
        data, count = re.subn(r"Freeze commit: `[0-9a-f]{40}`", "Freeze commit: `invalid`", data)
        self.assertEqual(count, 1)
        path.write_text(data, encoding="utf-8")
        errors = self.errors()
        self.assertTrue(any("Freeze tag" in e for e in errors))
        self.assertTrue(any("Freeze commit" in e for e in errors))

    def test_hidden_freeze_state_is_not_authority(self):
        self.edit(FREEZE, "Freeze state: `FROZEN`", "<!-- Freeze state: `FROZEN` -->")
        self.assertTrue(any("exactly one 'Freeze state:'" in e for e in self.errors()))


if __name__ == "__main__":
    unittest.main()
