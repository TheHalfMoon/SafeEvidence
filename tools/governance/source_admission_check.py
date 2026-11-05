#!/usr/bin/env python3
"""Fail-closed validator for exact-slice source admission rows (TA-01).

Checks structure and in-tree byte identity only. It cannot establish rights: a
row is authority only through its recorded founder decision and signed PR.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path, PurePosixPath

MANIFEST = "docs/evidence/source_admissions.json"
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
STATES = {"CANDIDATE", "RIGHTS_UNKNOWN", "VERIFIED_ALLOWED", "REFERENCE_ONLY", "DENIED"}
BASES = {"FOUNDER_OWNED", "PUBLIC_LICENSE", "SEPARATE_PERMISSION_VERIFIED"}
DECISION_PREFIX = "https://github.com/TheHalfMoon/SafeEvidence/issues/"
TOP_KEYS = {"schema_version", "admissions"}
ROW_KEYS = {
    "admission_id", "packet", "repo", "source_commit", "state", "copy_authorized",
    "basis", "license_spdx", "decision_ref", "notices", "transitive", "assets",
    "security_test_owner", "files",
}
FILE_KEYS = {"source_path", "git_blob_oid", "bytes", "dest_path", "modification"}
MODIFICATIONS = {"none", "adapted", "not_copied"}


def reject_duplicates(pairs):
    seen = {}
    for key, value in pairs:
        if key in seen:
            raise ValueError(f"duplicate JSON key: {key}")
        seen[key] = value
    return seen


def git_blob_oid(data: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(data) + data, usedforsecurity=False).hexdigest()


def safe_relative(path: object) -> bool:
    if not isinstance(path, str) or not path or "\\" in path:
        return False
    pure = PurePosixPath(path)
    return not pure.is_absolute() and ".." not in pure.parts


def check_file(root: Path, label: str, entry: object, errors: list[str]) -> None:
    if not isinstance(entry, dict) or set(entry) != FILE_KEYS:
        errors.append(f"{label}: file entry keys differ")
        return
    if not safe_relative(entry["source_path"]):
        errors.append(f"{label}: unsafe source path")
    oid = entry["git_blob_oid"]
    if not isinstance(oid, str) or not HEX40.fullmatch(oid):
        errors.append(f"{label}: git_blob_oid must be 40 hex")
    size = entry["bytes"]
    if isinstance(size, bool) or not isinstance(size, int) or size < 0:
        errors.append(f"{label}: bytes must be a non-negative integer")
    modification, dest = entry["modification"], entry["dest_path"]
    if modification not in MODIFICATIONS:
        errors.append(f"{label}: unknown modification")
        return
    if modification == "not_copied":
        if dest is not None:
            errors.append(f"{label}: not_copied entry cannot have dest_path")
        return
    if not safe_relative(dest):
        errors.append(f"{label}: unsafe dest_path")
        return
    current = root
    for part in PurePosixPath(dest).parts:
        current = current / part
        if current.is_symlink():
            errors.append(f"{label}: dest_path passes through a symlink")
            return
    if not current.is_file():
        errors.append(f"{label}: dest_path missing from tree")
        return
    if modification == "none":
        data = current.read_bytes()
        if len(data) != size or git_blob_oid(data) != oid:
            errors.append(f"{label}: in-tree bytes differ from pinned blob")


def check_row(root: Path, index: int, row: object, ids: set, errors: list[str]) -> None:
    label = f"Row {index}"
    if not isinstance(row, dict) or set(row) != ROW_KEYS:
        errors.append(f"{label}: row keys differ")
        return
    identifier = row["admission_id"]
    if not isinstance(identifier, str) or not identifier or identifier in ids:
        errors.append(f"{label}: admission_id missing or duplicated")
    ids.add(identifier)
    commit = row["source_commit"]
    if not isinstance(commit, str) or not HEX40.fullmatch(commit):
        errors.append(f"{label}: source_commit must be 40 hex")
    state = row["state"]
    if state not in STATES:
        errors.append(f"{label}: unknown state")
    if row["copy_authorized"] is not (state == "VERIFIED_ALLOWED"):
        errors.append(f"{label}: copy_authorized must be true only for VERIFIED_ALLOWED")
    if state == "VERIFIED_ALLOWED":
        if row["basis"] not in BASES:
            errors.append(f"{label}: basis cannot admit")
        decision = row["decision_ref"]
        if not isinstance(decision, str) or not decision.startswith(DECISION_PREFIX):
            errors.append(f"{label}: decision_ref must cite a recorded decision")
        for key in ("license_spdx", "notices", "transitive", "assets", "security_test_owner"):
            if not isinstance(row[key], str) or not row[key].strip():
                errors.append(f"{label}: {key} required for admission")
    files = row["files"]
    if not isinstance(files, list) or (state == "VERIFIED_ALLOWED" and not files):
        errors.append(f"{label}: files required")
        return
    seen_paths = set()
    for position, entry in enumerate(files):
        check_file(root, f"{label} file {position}", entry, errors)
        path = entry.get("source_path") if isinstance(entry, dict) else None
        if isinstance(path, str):
            if path in seen_paths:
                errors.append(f"{label}: duplicate source path")
            seen_paths.add(path)
        if (
            state != "VERIFIED_ALLOWED"
            and isinstance(entry, dict)
            and entry.get("modification") != "not_copied"
        ):
            errors.append(f"{label}: bytes cannot be in tree without admission")


def validate(root: Path, relative: str = MANIFEST) -> list[str]:
    path = root / relative
    if not path.is_file() or path.is_symlink():
        return ["admission manifest missing or not a regular file"]
    try:
        document = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates
        )
    except (OSError, ValueError) as exc:
        return [f"admission manifest unreadable: {exc}"]
    if not isinstance(document, dict) or set(document) != TOP_KEYS:
        return ["admission manifest top-level keys differ"]
    if document["schema_version"] != 1 or not isinstance(document["admissions"], list):
        return ["admission manifest schema differs"]
    errors: list[str] = []
    ids: set = set()
    for index, row in enumerate(document["admissions"]):
        check_row(root, index, row, ids, errors)
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".")
    args = parser.parse_args()
    errors = validate(Path(args.root).resolve())
    for error in errors:
        print(f"FAIL: {error}")
    if errors:
        return 1
    print("Source admissions: structure PASS (rights are not established by this check)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
