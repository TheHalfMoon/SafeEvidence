"""Positive and negative cases for the TA-01 source admission validator."""
from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import source_admission_check as check  # noqa: E402

BYTES = b"synthetic donor bytes\n"


def good_row() -> dict:
    return {
        "admission_id": "ADM-0001",
        "packet": "T00",
        "repo": "example/donor",
        "source_commit": "a" * 40,
        "state": "VERIFIED_ALLOWED",
        "copy_authorized": True,
        "basis": "FOUNDER_OWNED",
        "license_spdx": "Apache-2.0",
        "decision_ref": check.DECISION_PREFIX + "5#issuecomment-1",
        "notices": "THIRD_PARTY_NOTICES.md",
        "transitive": "none",
        "assets": "none",
        "security_test_owner": "founder",
        "files": [
            {
                "source_path": "src/a.rs",
                "git_blob_oid": check.git_blob_oid(BYTES),
                "bytes": len(BYTES),
                "dest_path": "crates/x/a.rs",
                "modification": "none",
            }
        ],
    }


class AdmissionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "docs/evidence").mkdir(parents=True)
        (self.root / "crates/x").mkdir(parents=True)
        (self.root / "crates/x/a.rs").write_bytes(BYTES)

    def errors(self, *rows) -> list[str]:
        text = json.dumps({"schema_version": 1, "admissions": list(rows)})
        (self.root / check.MANIFEST).write_text(text, encoding="utf-8")
        return check.validate(self.root)

    def mutated(self, **fields) -> dict:
        row = copy.deepcopy(good_row())
        row.update(fields)
        return row

    def test_repository_manifest_passes(self):
        self.assertEqual(check.validate(Path(__file__).resolve().parents[3]), [])

    def test_reviewed_fixture_and_empty_ledger_pass(self):
        self.assertEqual(self.errors(good_row()), [])
        self.assertEqual(self.errors(), [])

    def test_missing_manifest_denies(self):
        self.assertTrue(check.validate(self.root))

    def test_missing_or_short_commit_denies(self):
        self.assertTrue(self.errors(self.mutated(source_commit="")))
        self.assertTrue(self.errors(self.mutated(source_commit="a" * 39)))
        row = good_row()
        del row["source_commit"]
        self.assertTrue(self.errors(row))

    def test_blob_and_byte_mismatch_denies(self):
        (self.root / "crates/x/a.rs").write_bytes(BYTES + b"tampered")
        self.assertTrue(self.errors(good_row()))

    def test_same_size_different_bytes_denies(self):
        (self.root / "crates/x/a.rs").write_bytes(BYTES.replace(b"s", b"z", 1))
        self.assertTrue(self.errors(good_row()))

    def test_duplicate_json_keys_deny(self):
        (self.root / check.MANIFEST).write_text(
            '{"schema_version":1,"schema_version":1,"admissions":[]}', encoding="utf-8"
        )
        self.assertTrue(check.validate(self.root))

    def test_duplicate_admission_id_denies(self):
        self.assertTrue(self.errors(good_row(), good_row()))

    def test_copy_authorized_requires_verified_allowed(self):
        for state in sorted(check.STATES - {"VERIFIED_ALLOWED"}):
            with self.subTest(state=state):
                self.assertTrue(self.errors(self.mutated(state=state)))

    def test_verified_allowed_requires_copy_authorized_true(self):
        self.assertTrue(self.errors(self.mutated(copy_authorized=False)))

    def test_admission_requires_decision_and_notices(self):
        self.assertTrue(self.errors(self.mutated(decision_ref="founder said so")))
        self.assertTrue(self.errors(self.mutated(notices=" ")))

    def test_asserted_basis_cannot_admit(self):
        self.assertTrue(self.errors(self.mutated(basis="SEPARATE_PERMISSION_ASSERTED")))

    def test_unadmitted_row_cannot_place_bytes(self):
        row = self.mutated(state="CANDIDATE", copy_authorized=False)
        self.assertTrue(self.errors(row))
        row["files"][0].update(modification="not_copied", dest_path=None)
        self.assertEqual(self.errors(row), [])

    def test_unsafe_paths_deny(self):
        for field, value in (("dest_path", "../x"), ("dest_path", "/x"), ("source_path", "a\\b")):
            with self.subTest(field=field, value=value):
                row = good_row()
                row["files"][0][field] = value
                self.assertTrue(self.errors(row))

    def test_unknown_keys_deny(self):
        self.assertTrue(self.errors(self.mutated(extra="x")))


if __name__ == "__main__":
    unittest.main()
