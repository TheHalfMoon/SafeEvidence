"""Fail-closed P01 pre-entry register regression fixtures; all synthetic."""
from __future__ import annotations

import hashlib
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import p01_preentry_check as check


class GateFixtures(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for path in [*check.ORIGINAL_PATHS.values(), check.TRACKER,
                     check.ENTRY, check.CHARTER, check.RIGHTS]:
            (self.root / path).parent.mkdir(parents=True, exist_ok=True)
        for reviewer, path in check.ORIGINAL_PATHS.items():
            content = "".join(
                f"| {ident} | Phase-{ident} | Reviewer-{reviewer} | Required decision | Evidence-{ident} |\n"
                for ident in sorted(check.EXPECTED[reviewer])
            )
            content = "| Finding | Binding phase/entry gate | Responsible owner role | Required decision BEFORE affected work | Acceptance evidence |\n|---|---|---|---|---|\n" + content
            self.write(path, content)
        all_ids = sorted(set().union(*check.EXPECTED.values()))
        content = "Status: OPEN_OWNER_ASSIGNMENT; unassigned\n" + "".join(
            f"| {ident} | Phase-{ident} | Reviewer-{ident.split('-')[0]} | "
            f"[#3](https://github.com/TheHalfMoon/SafeEvidence/issues/3) | "
            f"OPEN — owner unassigned | Evidence-{ident} |\n"
            for ident in all_ids
        )
        content = content.replace(
            "Status: OPEN_OWNER_ASSIGNMENT; unassigned\n",
            "Status: OPEN_OWNER_ASSIGNMENT; unassigned\n\n"
            "| ID | Original phase entry | Unappointed owner role | Tracking issue | State | Required objective evidence |\n"
            "|---|---|---|---|---|---|\n",
            1,
        )
        self.write(check.TRACKER, content)
        self.write(check.ENTRY, "P01_PRE_ENTRY_GATES_PENDING; PREPARED_NOT_ACTIVATED; UNAPPROVED; BLOCKED")
        self.write(check.CHARTER, "DRAFT_UNAPPROVED; NOT_SIGNED; NOT_IDENTIFIED")
        self.write(check.RIGHTS, "NO_ADMISSIONS, VERIFIED_ALLOWED (deny by default)")
        # Synthetic fixtures have different source text; pin their original snapshot
        # before mutation, just like production pins its accepted P00 review packet.
        self.source_pins = {
            reviewer: hashlib.sha256(
                (self.root / path).read_text(encoding="utf-8").encode("utf-8")
            ).hexdigest()
            for reviewer, path in check.ORIGINAL_PATHS.items()
        }

    def validate_fixture(self) -> dict[str, object]:
        return check.validate(self.root, expected_register_hashes=self.source_pins)

    def write(self, path: str, text: str) -> None:
        (self.root / path).write_text(text, encoding="utf-8")

    def edit(self, path: str, old: str, new: str) -> None:
        p = self.root / path
        t = p.read_text(encoding="utf-8")
        self.assertIn(old, t)
        self.write(path, t.replace(old, new, 1))

    def assert_deny(self, explanation: str) -> None:
        out = self.validate_fixture()
        self.assertEqual(out["structure"], "FAIL")
        self.assertEqual(out["p01_g01_activation"], "BLOCKED")
        self.assertTrue(any(explanation in e for e in out["errors"]), out["errors"])

    def test_identical_out_of_checkout_governance_files_denied(self):
        trusted = [
            *check.ORIGINAL_PATHS.values(), check.TRACKER,
            check.ENTRY, check.CHARTER, check.RIGHTS,
        ]
        for relative in trusted:
            with self.subTest(file=relative), tempfile.TemporaryDirectory() as external:
                file = self.root / relative
                original = file.read_bytes()
                outside = Path(external) / "matching-evidence"
                outside.write_bytes(original)
                file.unlink()
                try:
                    file.symlink_to(outside)
                except OSError as exc:
                    file.write_bytes(original)
                    self.skipTest(f"Host cannot create symbolic links: {exc}")
                try:
                    report = self.validate_fixture()
                    self.assertEqual("FAIL", report["structure"], report)
                    self.assertTrue(any("Symbolic link" in e for e in report["errors"]))
                    self.assertEqual("BLOCKED", report["p01_g01_activation"])
                    self.assertFalse(report["source_imports_authorized"])
                finally:
                    file.unlink()
                    file.write_bytes(original)

    def test_linked_parent_governance_directory_denied(self):
        with tempfile.TemporaryDirectory() as external:
            folder = self.root / "docs"
            outside = Path(external) / "matching-docs"
            shutil.copytree(folder, outside)
            shutil.rmtree(folder)
            try:
                folder.symlink_to(outside, target_is_directory=True)
            except OSError as exc:
                shutil.copytree(outside, folder)
                self.skipTest(f"Host cannot create directory links: {exc}")
            try:
                report = self.validate_fixture()
                self.assertEqual("FAIL", report["structure"], report)
                self.assertTrue(any("Symbolic link" in e for e in report["errors"]))
                self.assertEqual("BLOCKED", report["p01_g01_activation"])
            finally:
                folder.unlink()
                shutil.copytree(outside, folder)

    def test_valid_register_is_still_not_authorized(self):
        out = self.validate_fixture()
        self.assertEqual(out["structure"], "PASS", out["errors"])
        self.assertEqual(out["original_codex_p1"], 24)
        self.assertEqual(out["original_opus_p1"], 17)
        self.assertEqual(out["p01_g01_activation"], "BLOCKED")
        self.assertFalse(out["clinical_evaluation_verified"])

    def test_fenced_tracker_table_cannot_supply_all_41_rows(self):
        path = self.root / check.TRACKER
        original = path.read_text(encoding="utf-8")
        marker = "| ID | Original phase entry"
        self.assertIn(marker, original)
        for opener, closer in ((chr(96) * 3 + "markdown", chr(96) * 3),
                               ("~~~~markdown", "~~~~")):
            with self.subTest(opener=opener):
                pos = original.index(marker)
                self.write(check.TRACKER, original[:pos] + opener + "\n"
                           + original[pos:] + "\n" + closer + "\n")
                self.assert_deny("P01 tracker missing IDs")

    def test_commented_tracker_table_cannot_supply_41_rows(self):
        path = self.root / check.TRACKER
        original = path.read_text(encoding="utf-8")
        marker = "| ID | Original phase entry"
        pos = original.index(marker)
        self.write(check.TRACKER, original[:pos] + "<!--\n"
                   + original[pos:] + "\n-->\n")
        self.assert_deny("P01 tracker missing IDs")

    def test_fenced_original_table_cannot_supply_review_findings(self):
        path = check.ORIGINAL_PATHS["CODEX"]
        original = (self.root / path).read_text(encoding="utf-8")
        marker = "| Finding | Binding phase/entry gate"
        pos = original.index(marker)
        self.write(path, original[:pos] + chr(96) * 3 + "md\n"
                   + original[pos:] + "\n" + chr(96) * 3 + "\n")
        self.assert_deny("CODEX source IDs missing")

    def test_hidden_examples_do_not_create_phantom_duplicate_tables(self):
        path = check.TRACKER
        original = (self.root / path).read_text(encoding="utf-8")
        header = next(line for line in original.splitlines() if line.startswith("| ID |"))
        fake = header + "\n|---|---|---|---|---|---|\n"
        examples = (chr(96) * 3 + "markdown\n" + fake + chr(96) * 3 + "\n"
                    + "<!--\n" + fake + "-->\n")
        self.write(path, examples + original)
        self.assertEqual(self.validate_fixture()["structure"], "PASS")

    def test_coordinated_source_and_tracker_rewrite_denied(self):
        key = "CODEX-P00-07"
        for path in (check.ORIGINAL_PATHS["CODEX"], check.TRACKER):
            self.edit(path, "Evidence-" + key, "FABRICATED-EVIDENCE-" + key)
        self.assert_deny("original P00 register changed from reviewed baseline")

    def test_extra_source_prose_is_immutable(self):
        p = self.root / check.ORIGINAL_PATHS["OPUS"]
        p.write_text(p.read_text(encoding="utf-8") + "\nUnchecked claim.\n",
                     encoding="utf-8")
        self.assert_deny("original P00 register changed from reviewed baseline")

    def test_crlf_checkout_preserves_pinned_original_content(self):
        path = self.root / check.ORIGINAL_PATHS["CODEX"]
        # Write exactly one CRLF per logical line even when running on Windows,
        # where write_text() may already have produced CRLF in the fixture.
        normalized = path.read_text(encoding="utf-8")
        path.write_bytes(normalized.replace("\n", "\r\n").encode("utf-8"))
        self.assertEqual(self.validate_fixture()["structure"], "PASS")

    def test_canonical_repository_registers_match_accepted_hashes(self):
        for reviewer, path in check.ORIGINAL_PATHS.items():
            digest = hashlib.sha256(
                (Path(__file__).resolve().parents[3] / path)
                .read_text(encoding="utf-8").encode("utf-8")
            ).hexdigest()
            self.assertEqual(digest, check.PINNED_ORIGINAL_SHA256[reviewer])

    def test_unbound_tracker_row_cannot_replace_canonical_row(self):
        p = self.root / check.TRACKER
        original = p.read_text(encoding="utf-8")
        target = next(line for line in original.splitlines()
                      if line.startswith("| CODEX-P00-07 |"))
        changed = original.replace(target + "\n", "", 1)
        p.write_text(changed + "\nDetached example:\n\n" + target + "\n",
                     encoding="utf-8")
        self.assert_deny("P01 tracker missing IDs")

    def test_unbound_original_row_cannot_replace_finding(self):
        p = self.root / check.ORIGINAL_PATHS["CODEX"]
        original = p.read_text(encoding="utf-8")
        target = next(line for line in original.splitlines()
                      if line.startswith("| CODEX-P00-07 |"))
        changed = original.replace(target + "\n", "", 1)
        p.write_text(changed + "\nDetached note:\n" + target + "\n",
                     encoding="utf-8")
        self.assert_deny("CODEX source IDs missing")

    def test_missing_tracker_table_header_is_rejected(self):
        self.edit(check.TRACKER, "| ID |", "| Not-an-ID-header |")
        self.assert_deny("Missing or duplicated P1 table")

    def test_duplicate_table_header_is_rejected(self):
        p = self.root / check.TRACKER
        original = p.read_text(encoding="utf-8")
        header = "| ID | Original phase entry | Unappointed owner role | Tracking issue | State | Required objective evidence |"
        p.write_text(original + "\n" + header + "\n", encoding="utf-8")
        self.assert_deny("Duplicate P1 table header")

    def test_missing_tracker_id_rejected(self):
        self.edit(check.TRACKER, "| CODEX-P00-07 |", "| LOST-P00-07 |")
        self.assert_deny("P01 tracker missing IDs")

    def test_duplicate_id_rejected(self):
        p = self.root / check.TRACKER
        text = p.read_text(encoding="utf-8")
        row = next(line for line in text.splitlines()
                   if line.startswith("| CODEX-P00-07 |"))
        p.write_text(text.replace(row, row + "\n" + row, 1),
                     encoding="utf-8")
        self.assert_deny("Duplicate P1 ID")

    def test_evidence_drift_rejected(self):
        self.edit(check.TRACKER, "Evidence-CODEX-P00-07", "UNQUALIFIED")
        self.assert_deny("drift in acceptance evidence")

    def test_role_drift_rejected(self):
        self.edit(check.TRACKER, "Reviewer-CODEX", "Invented-Signer")
        self.assert_deny("drift in owner role")

    def test_phase_gate_drift_rejected(self):
        self.edit(check.TRACKER, "Phase-OPUS-P00-003", "Later-Phase")
        self.assert_deny("drift in phase entry")

    def test_fabricated_approval_rejected(self):
        self.edit(check.TRACKER, "OPEN — owner unassigned", "APPROVED")
        self.assert_deny("unexpected status")

    def test_issue_bound_owner_assignment_passes_without_activating_p01(self):
        self.edit(
            check.TRACKER,
            "OPEN — owner unassigned",
            "ASSIGNED — @TheHalfMoon (https://github.com/TheHalfMoon/SafeEvidence/issues/3#issuecomment-100)",
        )
        out = self.validate_fixture()
        self.assertEqual(out["structure"], "PASS", out["errors"])
        self.assertEqual(out["assigned_owners_recorded"], 1)
        self.assertEqual(out["named_human_approvals_verified"], 0)
        self.assertEqual(out["p01_g01_activation"], "BLOCKED")
        self.assertFalse(out["clinical_evaluation_verified"])

    def test_owner_assignment_without_matching_issue_comment_rejected(self):
        for bad_state in (
            "ASSIGNED — @TheHalfMoon",
            "ASSIGNED — @TheHalfMoon (https://github.com/TheHalfMoon/SafeEvidence/issues/5#issuecomment-100)",
            "ASSIGNED — unauthenticated (https://github.com/TheHalfMoon/SafeEvidence/issues/3#issuecomment-100)",
        ):
            with self.subTest(bad_state=bad_state):
                self.setUp()
                self.edit(check.TRACKER, "OPEN — owner unassigned", bad_state)
                self.assert_deny("unexpected status")

    def test_all_41_assigned_requires_pending_marker_and_remains_blocked(self):
        tracker_path = self.root / check.TRACKER
        text = tracker_path.read_text(encoding="utf-8").replace(
            "OPEN — owner unassigned",
            "ASSIGNED — @TheHalfMoon (https://github.com/TheHalfMoon/SafeEvidence/issues/3#issuecomment-100)",
        )
        tracker_path.write_text(text, encoding="utf-8")
        self.assert_deny("missing fail-closed marker OWNER_ASSIGNED_PRE_ENTRY_PENDING")

        tracker_path.write_text(
            text.replace("OPEN_OWNER_ASSIGNMENT", "OWNER_ASSIGNED_PRE_ENTRY_PENDING"),
            encoding="utf-8",
        )
        out = self.validate_fixture()
        self.assertEqual(out["structure"], "PASS", out["errors"])
        self.assertEqual(out["assigned_owners_recorded"], 41)
        self.assertEqual(out["named_human_approvals_verified"], 0)
        self.assertEqual(out["p01_g01_activation"], "BLOCKED")

    def test_loss_of_clinical_blocker_rejected(self):
        self.edit(check.CHARTER, "DRAFT_UNAPPROVED", "SIGNED")
        self.assert_deny("missing fail-closed marker")

    def test_hidden_charter_denials_do_not_supply_visible_approval_state(self):
        original = (self.root / check.CHARTER).read_text(encoding="utf-8")
        for marker in ("DRAFT_UNAPPROVED", "NOT_SIGNED", "NOT_IDENTIFIED"):
            self.assertIn(marker, original)
            original = original.replace(marker, "OMITTED_FROM_VISIBLE_CHARTER")
        self.write(
            check.CHARTER,
            original + "\n<!-- DRAFT_UNAPPROVED NOT_SIGNED NOT_IDENTIFIED -->\n",
        )
        self.assert_deny("missing fail-closed marker")

    def test_fenced_charter_denials_do_not_supply_approval_state(self):
        original = (self.root / check.CHARTER).read_text(encoding="utf-8")
        self.assertIn("NOT_SIGNED", original)
        original = original.replace("NOT_SIGNED", "OMITTED_FROM_VISIBLE_CHARTER")
        for opener, closer in (("~~~~markdown", "~~~~"), (chr(96) * 3 + "md", chr(96) * 3)):
            with self.subTest(opener=opener):
                self.write(check.CHARTER, original + "\n" + opener + "\nNOT_SIGNED\n"
                           + closer + "\n")
                self.assert_deny("missing fail-closed marker")

    def test_indented_charter_denials_are_not_active_governance(self):
        original = (self.root / check.CHARTER).read_text(encoding="utf-8")
        for marker in ("DRAFT_UNAPPROVED", "NOT_SIGNED", "NOT_IDENTIFIED"):
            self.assertIn(marker, original)
            original = original.replace(marker, "MARKER_REMOVED")
        for indent in ("    ", "\t"):
            with self.subTest(indent=repr(indent)):
                self.write(
                    check.CHARTER,
                    original + "\n\n" + indent
                    + "DRAFT_UNAPPROVED NOT_SIGNED NOT_IDENTIFIED\n",
                )
                self.assert_deny("missing fail-closed marker")

    def test_indented_rights_denial_is_not_active_governance(self):
        original = (self.root / check.RIGHTS).read_text(encoding="utf-8")
        self.assertIn("NO_ADMISSIONS", original)
        self.write(
            check.RIGHTS,
            original.replace("NO_ADMISSIONS", "RIGHTS_UNVERIFIED")
            + "\n\n    NO_ADMISSIONS\n",
        )
        self.assert_deny("missing fail-closed marker")

    def test_hidden_rights_denial_is_not_active_authority(self):
        original = (self.root / check.RIGHTS).read_text(encoding="utf-8")
        self.assertIn("NO_ADMISSIONS", original)
        self.write(
            check.RIGHTS,
            original.replace("NO_ADMISSIONS", "NEEDS_GENUINE_APPROVAL")
            + "\n<!-- NO_ADMISSIONS -->\n",
        )
        self.assert_deny("missing fail-closed marker")

    def test_hidden_entry_blocker_is_not_active_authority(self):
        original = (self.root / check.ENTRY).read_text(encoding="utf-8")
        self.assertIn("PREPARED_NOT_ACTIVATED", original)
        self.write(
            check.ENTRY,
            original.replace("PREPARED_NOT_ACTIVATED", "NOT_CANONICAL")
            + "\n~~~~\nPREPARED_NOT_ACTIVATED\n~~~~\n",
        )
        self.assert_deny("missing fail-closed marker")

    def test_loss_of_import_denial_rejected(self):
        self.edit(check.RIGHTS, "NO_ADMISSIONS", "FULL_ADMISSIONS")
        self.assert_deny("missing fail-closed marker")

    def test_missing_issue_link_rejected(self):
        self.edit(check.TRACKER, "issues/3", "issues/99")
        self.assert_deny("missing durable issue")

    def test_issue_label_url_mismatch_rejected(self):
        self.edit(check.TRACKER,
                  "[#3](https://github.com/TheHalfMoon/SafeEvidence/issues/3)",
                  "[#5](https://github.com/TheHalfMoon/SafeEvidence/issues/3)")
        self.assert_deny("missing durable issue")

    def test_source_finding_missing_rejected(self):
        p = check.ORIGINAL_PATHS["CODEX"]
        self.edit(p, "| CODEX-P00-07 |", "| NON-P1-07 |")
        self.assert_deny("source IDs missing")


if __name__ == "__main__":
    unittest.main()
