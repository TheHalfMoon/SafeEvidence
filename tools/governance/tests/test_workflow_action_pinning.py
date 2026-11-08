"""Keep foundation and pre-entry checkout actions pinned to immutable commits."""
from __future__ import annotations

import hashlib
import re
import shutil
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
WORKFLOWS = (
    ".github/workflows/p00-foundation-docs.yml",
    ".github/workflows/p01-preentry-governance.yml",
    ".github/workflows/g01a-synthetic-reproducibility.yml",
    ".github/workflows/product-ci.yml",
    ".github/workflows/desktop-ci.yml",
    ".github/workflows/desktop-e2e.yml",
    ".github/workflows/desktop-e2e-linux.yml",
)
WINDOWS_ONLY_WORKFLOW = ".github/workflows/desktop-e2e.yml"
LINUX_ONLY_WORKFLOW = ".github/workflows/desktop-e2e-linux.yml"
EXPECTED_CHECKOUT_SHA = "d23441a48e516b6c34aea4fa41551a30e30af803"
# Exact reviewed workflow snapshots. Normalize checkout newlines through
# read_text() so Windows CRLF checkouts retain the same audited content hash.
# A change in any YAML syntax, including escaped keys and anchors, requires
# an explicitly reviewed re-pin rather than relying on a partial regex parser.
PINNED_WORKFLOW_SHA256 = {
    ".github/workflows/p00-foundation-docs.yml": "ffc5b4246ee09dad96caed7cf759e8565fe0e80b2e6ffe8642cfa6ad2d1b8db6",
    ".github/workflows/p01-preentry-governance.yml": "efe37c703ed5c24ec230e355ef2579070507d626b00f6f17f93a418ebe6dbfab",
    ".github/workflows/g01a-synthetic-reproducibility.yml": "51eee1d5a8f2863ca28556cc5b4dc34a99634c4615926a5a0579e4b1f527cd7b",
    ".github/workflows/product-ci.yml": "2fd5dd9537e2c2886e8dc7663d3afc2f19c3e9280a56681ebb6ad8a230c6ced8",
    ".github/workflows/desktop-ci.yml": "47e48dbb7e11a289039ed7192fd0de65367a124558021181662d7a667d2e94ea",
    ".github/workflows/desktop-e2e.yml": "4fbfd43f9ada63bfdaa02076aac92aa836206dffdde13317eb43b70c1597d089",
    ".github/workflows/desktop-e2e-linux.yml": "500ec98cc8cebe690d8568d6cf84a4f8ef928d4afaaa25df80901d00b8d9506d",
}

# The TA-03 gate runs from this script, so it is pinned like a workflow.
CORE_SOCKET_SCRIPT = "tools/ci/core_no_sockets.py"
CORE_SOCKET_SCRIPT_SHA256 = "7363a273e45ce5e3f167142327828e167f275ccb91c1891c59622c99ef404e87"
TA03_SCRIPT = "tools/ci/ta03_isolated.sh"
TA29_SCRIPT = "tools/ci/ta29_dependency_denial.py"
TA29_SCRIPT_SHA256 = "b77022615499713081f2fd621a253d9be96bbb824363d947c1e07cb98a4fe768"
TA29_DESKTOP_SCRIPT = "tools/ci/ta29_desktop_denial.py"
TA29_DESKTOP_SCRIPT_SHA256 = "4acd672c1a495d7e4ff1149d58fc3c02636d2c76d64c3c92d4bb546fefcd4d54"
NETWORK_TRACE_SCRIPT = "tools/ci/network_trace_report.py"
NETWORK_TRACE_SCRIPT_SHA256 = "1626491e01a4284ce219111da1859c6d1c9e8b26fb247448bc98eb5ff66caf6f"
TA03_SCRIPT_SHA256 = "fa83a8a0b1abc085d5cb8e3ca0be5dbd2ff401d5cdf3c1e707aa792fb230c22b"

CHECKOUT_LINE = re.compile(r"^\s*uses:\s*actions/checkout@([^\s#]+)", re.MULTILINE)
# Reject additions to the execution surface, not just a moving checkout tag.
# These workflows require exactly one external action each.
# This line-level inventory includes step uses and reusable job-level uses.
# Scan executable action keys in both block and inline YAML mappings. Quoted
# keys are semantically the same as bare "uses" and must not evade inventory.
# An unrecognised or aliased value is not accepted by the exact allowlist.
USES_LINE = re.compile(
    r"(?:^[ \t]*(?:-[ \t]*)?|[{,][ \t]*)"
    r"(?:uses|\"uses\"|\x27uses\x27)[ \t]*:[ \t]*"
    r"([^#\r\n,}]*)",
    re.MULTILINE,
)
FULL_SHA = re.compile(r"[0-9a-f]{40}\Z")


def workflow_content_digest(source: str) -> str:
    """Hash canonical decoded checkout text across Unix and Windows."""
    return hashlib.sha256(source.replace("\r\n", "\n").encode("utf-8")).hexdigest()


def workflow_action_references(source: str) -> list[str]:
    """Extract all action/reusable-workflow references, including unknown ones."""
    return [reference.strip() for reference in USES_LINE.findall(source)]


def action_checkout_pins(text: str) -> list[str]:
    return CHECKOUT_LINE.findall(text)


def workflow_inventory(root: Path) -> set[str]:
    """Include every entry, not just known *.yml files or action uses.

    A fourth workflow would otherwise bypass checks confined to WORKFLOWS;
    an unexpected directory, symlink or alternate *.yaml is also unreviewed.
    """
    directory = root / ".github/workflows"
    if (root / ".github").is_symlink() or directory.is_symlink() or not directory.is_dir():
        return set()
    entries = list(directory.iterdir())
    if any(path.is_symlink() for path in entries):
        return set()
    return {path.relative_to(root).as_posix() for path in entries}


class WorkflowCheckoutPinTests(unittest.TestCase):
    def test_workflow_contents_match_pinned_reviewed_revisions(self):
        self.assertEqual(set(WORKFLOWS), set(PINNED_WORKFLOW_SHA256))
        for workflow in WORKFLOWS:
            with self.subTest(workflow=workflow):
                source = (ROOT / workflow).read_text(encoding="utf-8")
                self.assertEqual(
                    PINNED_WORKFLOW_SHA256[workflow],
                    workflow_content_digest(source),
                    "Any workflow change requires separately reviewed digest re-pinning",
                )

    def test_ta03_gate_script_matches_pinned_revision(self):
        source = (ROOT / TA03_SCRIPT).read_text(encoding="utf-8")
        self.assertEqual(TA03_SCRIPT_SHA256, workflow_content_digest(source))

    def test_core_socket_gate_script_matches_pinned_revision(self):
        source = (ROOT / CORE_SOCKET_SCRIPT).read_text(encoding="utf-8")
        self.assertEqual(CORE_SOCKET_SCRIPT_SHA256, workflow_content_digest(source))

    def test_ta29_gate_script_matches_pinned_revision(self):
        source = (ROOT / TA29_SCRIPT).read_text(encoding="utf-8")
        self.assertEqual(TA29_SCRIPT_SHA256, workflow_content_digest(source))

    def test_network_trace_report_matches_pinned_revision(self):
        source = (ROOT / NETWORK_TRACE_SCRIPT).read_text(encoding="utf-8")
        self.assertEqual(hashlib.sha256(source.encode("utf-8")).hexdigest(), NETWORK_TRACE_SCRIPT_SHA256)

    def test_ta29_desktop_gate_script_matches_pinned_revision(self):
        source = (ROOT / TA29_DESKTOP_SCRIPT).read_text(encoding="utf-8")
        self.assertEqual(TA29_DESKTOP_SCRIPT_SHA256, workflow_content_digest(source))

    def test_semantic_yaml_escape_bypass_fails_frozen_workflow_digest(self):
        workflow = WORKFLOWS[0]
        approved = f"actions/checkout@{EXPECTED_CHECKOUT_SHA}"
        source = (ROOT / workflow).read_text(encoding="utf-8")
        anchor = "      - name: Checkout exact evaluated head\n"
        self.assertIn(anchor, source)
        for escaped_key in (r'"\u0075ses"', r'"u\u0073es"'):
            with self.subTest(escaped_key=escaped_key):
                unreviewed_step = (
                    "      - name: Unexpected external step\n"
                    f"        {escaped_key}: attacker/unreviewed@v1\n"
                )
                modified = source.replace(anchor, unreviewed_step + anchor, 1)
                # The legacy line regex misses escaped keys, even though
                # a YAML parser resolves both of them to the key "uses".
                self.assertEqual([approved], workflow_action_references(modified))
                self.assertNotEqual(
                    PINNED_WORKFLOW_SHA256[workflow],
                    workflow_content_digest(modified),
                )

    def test_other_edits_and_crlf_normalization_stay_fail_closed(self):
        workflow = WORKFLOWS[0]
        source = (ROOT / workflow).read_text(encoding="utf-8")
        expected = PINNED_WORKFLOW_SHA256[workflow]
        self.assertEqual(expected, workflow_content_digest(source.replace("\n", "\r\n")))
        self.assertNotEqual(expected, workflow_content_digest(source + "# changed\n"))

    def test_all_workflows_use_identical_immutable_checkout(self):
        for workflow in WORKFLOWS:
            with self.subTest(workflow=workflow):
                source = (ROOT / workflow).read_text(encoding="utf-8")
                self.assertEqual(
                    [EXPECTED_CHECKOUT_SHA],
                    action_checkout_pins(source),
                    "Checkout must be a reviewed immutable action revision",
                )

    def test_entire_workflow_directory_is_the_reviewed_allowlist(self):
        self.assertEqual(set(WORKFLOWS), workflow_inventory(ROOT))
        workflow_directory = ROOT / ".github/workflows"
        self.assertFalse(workflow_directory.is_symlink())
        for name in WORKFLOWS:
            with self.subTest(path=name):
                self.assertTrue((ROOT / name).is_file())
                self.assertFalse((ROOT / name).is_symlink())

    def test_new_yaml_workflow_or_unreviewed_directory_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            folder = root / ".github/workflows"
            folder.mkdir(parents=True)
            for name in WORKFLOWS:
                shutil.copyfile(ROOT / name, root / name)
            self.assertEqual(set(WORKFLOWS), workflow_inventory(root))
            for extra in ("unreviewed.yml", "unreviewed.yaml", "unreviewed"):
                with self.subTest(unreviewed=extra):
                    path = folder / extra
                    if extra == "unreviewed":
                        path.mkdir()
                    else:
                        path.write_text(
                            "name: Unreviewed\non: [pull_request]\n"
                            "jobs:\n  external:\n    runs-on: ubuntu-latest\n"
                            "    steps:\n      - uses: attacker/unreviewed@v1\n",
                            encoding="utf-8",
                        )
                    try:
                        self.assertNotEqual(
                            set(WORKFLOWS), workflow_inventory(root),
                            "New workflow/executable surface must fail PR CI",
                        )
                    finally:
                        if path.is_dir():
                            path.rmdir()
                        else:
                            path.unlink()

    def test_unreviewed_symlinked_workflow_not_silently_allowed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            folder = root / ".github/workflows"
            folder.mkdir(parents=True)
            for name in WORKFLOWS:
                shutil.copyfile(ROOT / name, root / name)
            target = root / "external.yml"
            target.write_text("name: external\n", encoding="utf-8")
            injected = folder / "extra.yml"
            try:
                injected.symlink_to(target)
            except OSError as exc:
                self.skipTest(f"Symlinks unavailable on host: {exc}")
            self.assertNotEqual(set(WORKFLOWS), workflow_inventory(root))
            self.assertTrue(injected.is_symlink())

    def test_existing_workflow_symlink_is_not_trusted(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            folder = root / ".github/workflows"
            folder.mkdir(parents=True)
            for name in WORKFLOWS:
                shutil.copyfile(ROOT / name, root / name)
            source = root / WORKFLOWS[0]
            outside = root / "external-copy.yml"
            shutil.copyfile(source, outside)
            source.unlink()
            try:
                source.symlink_to(outside)
            except OSError as exc:
                self.skipTest(f"Symlinks unavailable on host: {exc}")
            self.assertNotEqual(set(WORKFLOWS), workflow_inventory(root))

    def test_parent_directory_symlink_is_not_trusted(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            folder = root / ".github/workflows"
            folder.mkdir(parents=True)
            for name in WORKFLOWS:
                shutil.copyfile(ROOT / name, root / name)
            outside = root / "external-workflows"
            folder.rename(outside)
            try:
                folder.symlink_to(outside, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"Symlinks unavailable on host: {exc}")
            self.assertNotEqual(set(WORKFLOWS), workflow_inventory(root))

    def test_no_unreviewed_actions_in_any_governance_workflow(self):
        only_approved = [f"actions/checkout@{EXPECTED_CHECKOUT_SHA}"]
        for workflow in WORKFLOWS:
            with self.subTest(workflow=workflow):
                source = (ROOT / workflow).read_text(encoding="utf-8")
                self.assertEqual(
                    only_approved,
                    workflow_action_references(source),
                    "All action/reusable workflow uses must be explicitly reviewed",
                )

    def test_extra_unpinned_action_does_not_hide_behind_pinned_checkout(self):
        source = ("steps:\n"
                  "  - uses: attacker/unreviewed-egress@v1\n"
                  f"    uses: actions/checkout@{EXPECTED_CHECKOUT_SHA}\n")
        self.assertEqual([EXPECTED_CHECKOUT_SHA], action_checkout_pins(source))
        self.assertNotEqual(
            [f"actions/checkout@{EXPECTED_CHECKOUT_SHA}"],
            workflow_action_references(source),
        )

    def test_quoted_action_key_cannot_bypass_reviewed_inventory(self):
        approved = f"actions/checkout@{EXPECTED_CHECKOUT_SHA}"
        for additional in (
            '  - "uses": attacker/unreviewed@v1\n',
            "  - 'uses': attacker/unreviewed@v1\n",
            '  - { "uses": attacker/unreviewed@v1 }\n',
            '  - { uses: attacker/unreviewed@v1 }\n',
        ):
            with self.subTest(additional=additional):
                source = f"steps:\n  - uses: {approved}\n" + additional
                self.assertNotEqual([approved], workflow_action_references(source))

    def test_quoted_unapproved_value_cannot_be_hidden(self):
        source = (
            f"steps:\n  - uses: actions/checkout@{EXPECTED_CHECKOUT_SHA}\n"
            '  - "uses": "attacker/extra@v1"\n'
        )
        self.assertEqual(2, len(workflow_action_references(source)))

    def test_extra_sha_pinned_action_still_needs_explicit_review(self):
        source = ("steps:\n"
                  f"  - uses: actions/checkout@{EXPECTED_CHECKOUT_SHA}\n"
                  "  - uses: attacker/unreviewed@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n")
        self.assertEqual(2, len(workflow_action_references(source)))
        self.assertNotEqual(
            [f"actions/checkout@{EXPECTED_CHECKOUT_SHA}"],
            workflow_action_references(source),
        )

    def test_unreviewed_job_level_reusable_workflow_rejected(self):
        source = ("jobs:\n"
                  "  run-external:\n"
                  "    uses: attacker/repo/.github/workflows/unsafe.yml@v1\n"
                  f"  - uses: actions/checkout@{EXPECTED_CHECKOUT_SHA}\n")
        self.assertNotEqual(
            [f"actions/checkout@{EXPECTED_CHECKOUT_SHA}"],
            workflow_action_references(source),
        )

    def test_missing_uses_value_is_not_valid_action(self):
        source = f"steps:\n  - uses:\n  - uses: actions/checkout@{EXPECTED_CHECKOUT_SHA}\n"
        self.assertEqual(2, len(workflow_action_references(source)))
        self.assertEqual("", workflow_action_references(source)[0])

    def test_the_end_to_end_workflow_runs_only_where_its_protocol_exists(self):
        # WebView2's debugging protocol exists only on Windows, so this one workflow is the exception below.
        source = (ROOT / WINDOWS_ONLY_WORKFLOW).read_text(encoding="utf-8")
        self.assertIn("runs-on: windows-latest", source)
        self.assertNotIn("matrix.os", source)
        self.assertIn('test "$(git rev-parse HEAD)" = "$EXPECTED_SHA"', source)

    def test_the_linux_end_to_end_workflow_runs_only_where_its_driver_exists(self):
        # WebKitWebDriver exists only on Linux, so this workflow is an exception below too.
        source = (ROOT / LINUX_ONLY_WORKFLOW).read_text(encoding="utf-8")
        self.assertIn("runs-on: ubuntu-latest", source)
        self.assertNotIn("matrix.os", source)
        self.assertIn('test "$(git rev-parse HEAD)" = "$EXPECTED_SHA"', source)

    def test_synthetic_and_preentry_ci_include_macos(self):
        for workflow in [item for item in WORKFLOWS[1:] if item not in (WINDOWS_ONLY_WORKFLOW, LINUX_ONLY_WORKFLOW)]:
            with self.subTest(workflow=workflow):
                source = (ROOT / workflow).read_text(encoding="utf-8")
                self.assertIn(
                    "os: [ubuntu-latest, windows-latest, macos-15]",
                    source,
                )
                self.assertIn("matrix.os", source)

    def test_g01a_macos_ci_preserves_exact_head_and_source_guard(self):
        source = (ROOT / WORKFLOWS[2]).read_text(encoding="utf-8")
        self.assertIn('test "$(git rev-parse HEAD)" = "$EXPECTED_SHA"', source)
        self.assertLess(
            source.index("- name: Gate frozen source and cargo configuration"),
            source.index("- name: Install explicitly pinned development toolchain"),
        )
        self.assertIn("cargo test --offline --locked --workspace --all-targets", source)

    def test_moving_action_tag_is_rejected(self):
        self.assertNotEqual(
            [EXPECTED_CHECKOUT_SHA],
            action_checkout_pins("steps:\n  - uses: actions/checkout@v4\n"),
        )

    def test_short_sha_is_rejected(self):
        self.assertIsNone(FULL_SHA.fullmatch("d23441a"))

    def test_pinned_sha_is_full_length(self):
        self.assertIsNotNone(FULL_SHA.fullmatch(EXPECTED_CHECKOUT_SHA))


if __name__ == "__main__":
    unittest.main()
