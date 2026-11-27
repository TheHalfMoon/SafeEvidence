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
        "decision_ref": "https://github.com/TheHalfMoon/SafeEvidence/issues/5#issuecomment-1",
        "notices": "THIRD_PARTY_NOTICES.md",
        "transitive": "none",
        "assets": "none",
        "security_test_owner": "founder",
        "files": [
            {
                "source_path": "src/a.rs",
                "git_blob_oid": check.git_blob_oid(BYTES),
                "bytes": len(BYTES),
                "dest_path": "product/x/a.rs",
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
        (self.root / "product/x").mkdir(parents=True)
        (self.root / "product/x/a.rs").write_bytes(BYTES)

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
        (self.root / "product/x/a.rs").write_bytes(BYTES + b"tampered")
        self.assertTrue(self.errors(good_row()))

    def test_same_size_different_bytes_denies(self):
        (self.root / "product/x/a.rs").write_bytes(BYTES.replace(b"s", b"z", 1))
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

    def test_malformed_identity_fields_deny(self):
        for field, value in (
            ("repo", None), ("repo", 3), ("repo", " "), ("packet", ""), ("packet", ["T01"]),
            ("license_spdx", "not-a-licence"), ("license_spdx", "GPL-3.0-only"),
            ("source_commit", "0" * 40), ("state", ["VERIFIED_ALLOWED"]), ("basis", ["x"]),
            ("decision_ref", "https://github.com/TheHalfMoon/SafeEvidence/issues/"),
            ("decision_ref", "https://github.com/TheHalfMoon/SafeEvidence/issues/../../evil/x"),
        ):
            with self.subTest(field=field, value=value):
                self.assertTrue(self.errors(self.mutated(**{field: value})))

    def test_dest_outside_admitted_roots_denies(self):
        for dest in (
            ".git/hooks/pre-commit", ".github/workflows/x.yml", "crates/g01a-synthetic/src/lib.rs",
            "docs/evidence/source_admissions.json", "product/.git/config",
            "C:product/x/a.rs", "product/x/a.rs.", "product/x/a.rs::$DATA",
        ):
            with self.subTest(dest=dest):
                row = good_row()
                row["files"][0]["dest_path"] = dest
                self.assertTrue(self.errors(row))

    def test_windows_source_path_denies(self):
        row = good_row()
        row["files"][0]["source_path"] = "C:/Windows/x"
        self.assertTrue(self.errors(row))

    def test_dest_used_by_two_rows_denies(self):
        self.assertTrue(self.errors(good_row(), self.mutated(admission_id="ADM-0002")))

    def test_unmodified_copy_cannot_be_labelled_adapted(self):
        row = good_row()
        row["files"][0]["modification"] = "adapted"
        self.assertTrue(self.errors(row))
        (self.root / "product/x/a.rs").write_bytes(BYTES + b"// adapted\n")
        self.assertEqual(self.errors(row), [])

    def test_crlf_checkout_of_lf_blob_passes_but_other_edits_do_not(self):
        (self.root / "product/x/a.rs").write_bytes(BYTES.replace(b"\n", b"\r\n"))
        self.assertEqual(self.errors(good_row()), [])
        (self.root / "product/x/a.rs").write_bytes(b"x" + BYTES.replace(b"\n", b"\r\n"))
        self.assertTrue(self.errors(good_row()))

    def test_unhashable_and_deep_values_fail_cleanly(self):
        row = good_row()
        row["files"][0]["modification"] = ["none"]
        self.assertTrue(self.errors(row))
        (self.root / check.MANIFEST).write_text("[" * 200000, encoding="utf-8")
        self.assertTrue(check.validate(self.root))

    def test_boolean_schema_version_denies(self):
        (self.root / check.MANIFEST).write_text(
            '{"schema_version":true,"admissions":[]}', encoding="utf-8"
        )
        self.assertTrue(check.validate(self.root))

    def test_non_canonical_dest_cannot_evade_shared_destination_check(self):
        for dest in ("product/./x/a.rs", "product//x/a.rs", "product/x/a.rs/"):
            with self.subTest(dest=dest):
                other = self.mutated(admission_id="ADM-0002")
                other["files"][0]["dest_path"] = dest
                self.assertTrue(self.errors(good_row(), other))

    def test_mixed_line_endings_are_not_a_checkout_difference(self):
        data = BYTES + b"second line\n"
        row = good_row()
        row["files"][0].update(git_blob_oid=check.git_blob_oid(data), bytes=len(data))
        (self.root / "product/x/a.rs").write_bytes(data.replace(b"\n", b"\r\n", 1))
        self.assertTrue(self.errors(row))

    def test_blank_admission_id_denies(self):
        self.assertTrue(self.errors(self.mutated(admission_id=" ")))

    def test_float_schema_version_denies(self):
        (self.root / check.MANIFEST).write_text(
            '{"schema_version":1.0,"admissions":[]}', encoding="utf-8"
        )
        self.assertTrue(check.validate(self.root))

    def write_notices(self, text):
        (self.root / check.NOTICES).write_text(text, encoding="utf-8")

    def test_admitted_row_needs_an_exact_notice_row(self):
        self.errors(good_row())
        for text in (
            "no rows here",
            "ADM-0001 mentioned in prose",
            "| ADM-00012 | c | s | l | `product/x` |",
            "| ADM-000 | c | s | l | `product/x` |",
        ):
            with self.subTest(text=text):
                self.write_notices(text)
                self.assertEqual(check.missing_notices(self.root), ["ADM-0001"])
        self.write_notices("| ADM-0001 | c | s | l | `product/x` |")
        self.assertEqual(check.missing_notices(self.root), [])

    def test_notice_row_must_cover_each_copied_destination(self):
        self.errors(good_row())
        for dest in ("product/y", "product/xy", "product/x/a.rs.txt"):
            with self.subTest(dest=dest):
                self.write_notices(f"| ADM-0001 | c | s | l | `{dest}` |")
                self.assertEqual(
                    check.missing_notices(self.root), ["ADM-0001: product/x/a.rs"]
                )
        self.write_notices("| ADM-0001 | c | s | l | `product/x/a.rs` |")
        self.assertEqual(check.missing_notices(self.root), [])

    def test_unknown_keys_deny(self):
        self.assertTrue(self.errors(self.mutated(extra="x")))

    def test_repository_crate_closures_cover_product_and_desktop_locks(self):
        repo_root = Path(__file__).resolve().parents[3]
        self.assertEqual(check.validate(repo_root), [])
        self.assertEqual(check.missing_notices(repo_root), [])
        manifest = json.loads((repo_root / check.MANIFEST).read_text(encoding="utf-8"))
        lockfiles = {row["lockfile"] for row in manifest["crate_closures"]}
        self.assertEqual(
            lockfiles,
            {
                "product/Cargo.lock",
                "product/apps/desktop/src-tauri/Cargo.lock",
                "product/apps/desktop/package-lock.json",
            },
        )

    def test_crate_closure_tamper_unapproved_license_and_script_drift_deny(self):
        cargo_lock = (
            b'version = 4\n\n[[package]]\nname = "a"\nversion = "0.1.0"\n'
            b'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
            b'checksum = "' + (b"b" * 64) + b'"\n'
        )
        deny_toml = b'[licenses]\nallow = ["MIT"]\n'
        (self.root / "product/Cargo.lock").write_bytes(cargo_lock)
        (self.root / "product/deny.toml").write_bytes(deny_toml)
        good_closure = {
            "admission_id": "ADM-0010",
            "packet": "CRATE-product-cargo",
            "ecosystem": "cargo",
            "lockfile": "product/Cargo.lock",
            "lockfile_lf_sha256": check.hashlib.sha256(cargo_lock).hexdigest(),
            "lockfile_lf_bytes": len(cargo_lock),
            "package_count": 1,
            "state": "VERIFIED_ALLOWED",
            "copy_authorized": True,
            "basis": "PUBLIC_LICENSE",
            "allowed_licenses": ["MIT"],
            "decision_ref": "https://github.com/TheHalfMoon/SafeEvidence/issues/5#issuecomment-1",
            "policy_file": "product/deny.toml",
            "notices": "THIRD_PARTY_NOTICES.md",
            "allowed_install_scripts_ignored": [],
            "security_test_owner": "founder",
        }
        (self.root / check.MANIFEST).write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "admissions": [good_row()],
                    "crate_closures": [good_closure],
                }
            ),
            encoding="utf-8",
        )
        self.assertEqual(check.validate(self.root), [])

        # CRLF checkout of an LF lockfile still passes.
        (self.root / "product/Cargo.lock").write_bytes(cargo_lock.replace(b"\n", b"\r\n"))
        self.assertEqual(check.validate(self.root), [])

        # Tampered package count or unapproved git source fails closed.
        bad_count = copy.deepcopy(good_closure)
        bad_count["package_count"] = 2
        (self.root / check.MANIFEST).write_text(
            json.dumps({"schema_version": 1, "admissions": [], "crate_closures": [bad_count]}),
            encoding="utf-8",
        )
        self.assertTrue(check.validate(self.root))

        # npm closure rejects unapproved license or undeclared install script.
        npm_lock = json.dumps(
            {
                "name": "app",
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "app", "version": "0.0.0"},
                    "node_modules/bad": {
                        "version": "1.0.0",
                        "resolved": "https://registry.npmjs.org/bad/-/bad-1.0.0.tgz",
                        "integrity": "sha512-abc==",
                        "license": "WTFPL",
                        "hasInstallScript": True,
                    },
                },
            }
        ).encode("utf-8")
        (self.root / "product/package-lock.json").write_bytes(npm_lock)
        (self.root / "product/package.json").write_bytes(b"{}\n")
        npm_closure = {
            "admission_id": "ADM-0012",
            "packet": "CRATE-desktop-npm",
            "ecosystem": "npm",
            "lockfile": "product/package-lock.json",
            "lockfile_lf_sha256": check.hashlib.sha256(npm_lock).hexdigest(),
            "lockfile_lf_bytes": len(npm_lock),
            "package_count": 1,
            "state": "VERIFIED_ALLOWED",
            "copy_authorized": True,
            "basis": "PUBLIC_LICENSE",
            "allowed_licenses": ["MIT"],
            "decision_ref": "https://github.com/TheHalfMoon/SafeEvidence/issues/5#issuecomment-1",
            "policy_file": "product/package.json",
            "notices": "THIRD_PARTY_NOTICES.md",
            "allowed_install_scripts_ignored": [],
            "security_test_owner": "founder",
        }
        (self.root / check.MANIFEST).write_text(
            json.dumps({"schema_version": 1, "admissions": [], "crate_closures": [npm_closure]}),
            encoding="utf-8",
        )
        errs = check.validate(self.root)
        self.assertTrue(any("license" in e for e in errs), errs)
        self.assertTrue(any("install-script" in e for e in errs), errs)

    def test_unadmitted_candidate_ledger_keeps_copy_blocked_and_private_paths_withheld(self):
        repo_root = Path(__file__).resolve().parents[3]
        manifest = json.loads((repo_root / check.MANIFEST).read_text(encoding="utf-8"))
        pins = json.loads(
            (repo_root / "docs/evidence/source_transplant_pins_2026-10-19.json").read_text(
                encoding="utf-8"
            )
        )["packets"]
        unadmitted = [r for r in manifest["admissions"] if r["state"] != "VERIFIED_ALLOWED"]
        self.assertEqual(len(unadmitted), 29)
        withheld_private_repos = {
            "thehalfmoon/dal",
            "thehalfmoon/kernux",
            "thehalfmoon/morize",
            "thehalfmoon/inercative",
            "thehalfmoon/signthos",
            "thehalfmoon/wispral",
            "thehalfmoon/sentrdel",
            "thehalfmoon/ecra",
        }
        ottari_entries = 0
        for row in manifest["admissions"]:
            repo_lower = row["repo"].lower()
            self.assertNotIn(repo_lower, withheld_private_repos)
            if repo_lower == "thehalfmoon/ottari":
                ottari_entries += len(row["files"])
            if row["state"] != "VERIFIED_ALLOWED":
                self.assertFalse(row["copy_authorized"], row["admission_id"])
                self.assertIsNone(row["decision_ref"], row["admission_id"])
                pkt = pins[row["packet"]]
                self.assertEqual(row["source_commit"], pkt["commit"], row["admission_id"])
                pinned_by_path = {
                    f["path"]: (f["git_blob_oid"], f["bytes"]) for f in pkt["files"]
                }
                if row["admission_id"] == "ADM-0041":
                    self.assertEqual(len(row["files"]), 6)
                else:
                    self.assertEqual(len(row["files"]), len(pinned_by_path), row["admission_id"])
                for entry in row["files"]:
                    self.assertIsNone(entry["dest_path"], row["admission_id"])
                    self.assertEqual(entry["modification"], "not_copied", row["admission_id"])
                    self.assertEqual(
                        (entry["git_blob_oid"], entry["bytes"]),
                        pinned_by_path[entry["source_path"]],
                        row["admission_id"],
                    )
        self.assertEqual(ottari_entries, 41)

    def test_dal_and_t14_are_permanently_banned(self):
        self.assertTrue(
            any(
                "DAL" in e
                for e in self.errors(self.mutated(repo="TheHalfMoon/DAL", packet="T99"))
            )
        )
        self.assertTrue(
            any("DAL" in e for e in self.errors(self.mutated(packet="T14")))
        )

    def test_public_license_adr_ref_and_bench_only_licenses(self):
        adr_rel = "docs/adr/0004-public-license.md"
        (self.root / "docs/adr").mkdir(parents=True, exist_ok=True)
        (self.root / adr_rel).write_text("# ADR\n", encoding="utf-8")
        (self.root / "bench/scifact").mkdir(parents=True, exist_ok=True)
        (self.root / "bench/scifact/claims.jsonl").write_bytes(BYTES)

        pub_row = self.mutated(basis="PUBLIC_LICENSE", decision_ref=adr_rel)
        self.assertEqual(self.errors(pub_row), [])

        # Missing ADR file or non-PUBLIC_LICENSE basis fails closed:
        self.assertTrue(
            self.errors(
                self.mutated(
                    basis="PUBLIC_LICENSE", decision_ref="docs/adr/9999-missing.md"
                )
            )
        )
        self.assertTrue(
            self.errors(
                self.mutated(basis="FOUNDER_OWNED", decision_ref=adr_rel)
            )
        )
        self.assertTrue(
            self.errors(
                self.mutated(
                    basis="SEPARATE_PERMISSION_VERIFIED", decision_ref=adr_rel
                )
            )
        )

        # CC-BY-4.0 allowed strictly under bench/, denied under product/:
        bench_row = self.mutated(
            basis="PUBLIC_LICENSE",
            license_spdx="CC-BY-4.0",
            decision_ref=adr_rel,
            files=[
                {
                    "source_path": "data/claims.jsonl",
                    "git_blob_oid": check.git_blob_oid(BYTES),
                    "bytes": len(BYTES),
                    "dest_path": "bench/scifact/claims.jsonl",
                    "modification": "none",
                }
            ],
        )
        self.assertEqual(self.errors(bench_row), [])
        self.assertTrue(
            self.errors(
                self.mutated(
                    basis="PUBLIC_LICENSE",
                    license_spdx="CC-BY-4.0",
                    decision_ref=adr_rel,
                )
            )
        )


if __name__ == "__main__":
    unittest.main()
