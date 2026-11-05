#!/usr/bin/env python3
"""Fail-closed validator for exact-slice source admission rows (TA-01).

Checks structure and in-tree byte identity only. It cannot establish rights: a
row is authority only through its recorded founder decision and signed PR. It
cannot detect donor bytes that no row declares, or confirm a pinned blob against
the donor repository; adapted files are checked for presence and difference only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path, PurePosixPath

MANIFEST = "docs/evidence/source_admissions.json"
NOTICES = "THIRD_PARTY_NOTICES.md"
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
STATES = {"CANDIDATE", "RIGHTS_UNKNOWN", "VERIFIED_ALLOWED", "REFERENCE_ONLY", "DENIED"}
BASES = {"FOUNDER_OWNED", "PUBLIC_LICENSE", "SEPARATE_PERMISSION_VERIFIED"}
DECISION_REF = re.compile(
    r"https://github\.com/TheHalfMoon/SafeEvidence/issues/[0-9]+#issuecomment-[0-9]+\Z"
)
REPO = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9][A-Za-z0-9._-]*\Z")
PACKET = re.compile(r"(T[0-9]{2}[a-z]?|CRATE-[a-z0-9-]+)\Z")
LICENSES = {
    "Apache-2.0", "MIT", "MIT OR Apache-2.0", "BSD-2-Clause", "BSD-3-Clause",
    "ISC", "Zlib", "Unicode-3.0", "MPL-2.0",
}
DEST_ROOTS = ("product/", "workers/", "bench/", "tools/release/", "tools/governance/donor/")
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
    if not isinstance(path, str) or not path or "\\" in path or ":" in path:
        return False
    pure = PurePosixPath(path)
    if str(pure) != path or pure.is_absolute() or ".." in pure.parts or ".git" in pure.parts:
        return False
    return not any(part.endswith((".", " ")) for part in pure.parts)


def is_full_oid(value: object) -> bool:
    return isinstance(value, str) and bool(HEX40.fullmatch(value)) and set(value) != {"0"}


def matches_blob(data: bytes, oid: str, size: int) -> bool:
    """Accept a checkout whose only difference is CRLF conversion of an LF blob."""
    if len(data) == size and git_blob_oid(data) == oid:
        return True
    if data.count(b"\n") != data.count(b"\r\n"):
        return False
    normalized = data.replace(b"\r\n", b"\n")
    return len(normalized) == size and git_blob_oid(normalized) == oid


def check_file(root: Path, label: str, entry: object, errors: list[str]) -> None:
    if not isinstance(entry, dict) or set(entry) != FILE_KEYS:
        errors.append(f"{label}: file entry keys differ")
        return
    if not safe_relative(entry["source_path"]):
        errors.append(f"{label}: unsafe source path")
    oid = entry["git_blob_oid"]
    if not is_full_oid(oid):
        errors.append(f"{label}: git_blob_oid must be 40 hex")
    size = entry["bytes"]
    if isinstance(size, bool) or not isinstance(size, int) or size < 0:
        errors.append(f"{label}: bytes must be a non-negative integer")
    modification, dest = entry["modification"], entry["dest_path"]
    if not isinstance(modification, str) or modification not in MODIFICATIONS:
        errors.append(f"{label}: unknown modification")
        return
    if modification == "not_copied":
        if dest is not None:
            errors.append(f"{label}: not_copied entry cannot have dest_path")
        return
    if not safe_relative(dest) or not dest.startswith(DEST_ROOTS):
        errors.append(f"{label}: dest_path unsafe or outside admitted roots")
        return
    current = root
    for part in PurePosixPath(dest).parts:
        current = current / part
        if current.is_symlink() or os.path.isjunction(current):
            errors.append(f"{label}: dest_path passes through a symlink")
            return
    if not current.is_file():
        errors.append(f"{label}: dest_path missing from tree")
        return
    if not is_full_oid(oid) or isinstance(size, bool) or not isinstance(size, int):
        return
    matches = matches_blob(current.read_bytes(), oid, size)
    if modification == "none" and not matches:
        errors.append(f"{label}: in-tree bytes differ from pinned blob")
    if modification == "adapted" and matches:
        errors.append(f"{label}: unmodified copy labelled adapted")


def check_row(
    root: Path, index: int, row: object, ids: set, dests: set, errors: list[str]
) -> None:
    label = f"Row {index}"
    if not isinstance(row, dict) or set(row) != ROW_KEYS:
        errors.append(f"{label}: row keys differ")
        return
    identifier = row["admission_id"]
    if not isinstance(identifier, str) or not identifier.strip() or identifier in ids:
        errors.append(f"{label}: admission_id missing or duplicated")
    if isinstance(identifier, str):
        ids.add(identifier)
    if not isinstance(row["repo"], str) or not REPO.fullmatch(row["repo"]):
        errors.append(f"{label}: repo must be owner/name")
    if not isinstance(row["packet"], str) or not PACKET.fullmatch(row["packet"]):
        errors.append(f"{label}: packet id invalid")
    if not is_full_oid(row["source_commit"]):
        errors.append(f"{label}: source_commit must be 40 hex")
    state = row["state"]
    if not isinstance(state, str) or state not in STATES:
        errors.append(f"{label}: unknown state")
    if row["copy_authorized"] is not (state == "VERIFIED_ALLOWED"):
        errors.append(f"{label}: copy_authorized must be true only for VERIFIED_ALLOWED")
    if state == "VERIFIED_ALLOWED":
        if not isinstance(row["basis"], str) or row["basis"] not in BASES:
            errors.append(f"{label}: basis cannot admit")
        decision = row["decision_ref"]
        if not isinstance(decision, str) or not DECISION_REF.fullmatch(decision):
            errors.append(f"{label}: decision_ref must cite a recorded decision")
        spdx = row["license_spdx"]
        if not isinstance(spdx, str) or spdx not in LICENSES:
            errors.append(f"{label}: license not on the admitted allowlist")
        for key in ("notices", "transitive", "assets", "security_test_owner"):
            if not isinstance(row[key], str) or not row[key].strip():
                errors.append(f"{label}: {key} required for admission")
    files = row["files"]
    if not isinstance(files, list) or (state == "VERIFIED_ALLOWED" and not files):
        errors.append(f"{label}: files required")
        return
    seen_paths = set()
    for position, entry in enumerate(files):
        check_file(root, f"{label} file {position}", entry, errors)
        dest = entry.get("dest_path") if isinstance(entry, dict) else None
        if isinstance(dest, str):
            if dest in dests:
                errors.append(f"{label}: dest_path used twice")
            dests.add(dest)
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
    except (OSError, ValueError, RecursionError) as exc:
        return [f"admission manifest unreadable: {exc}"]
    if not isinstance(document, dict) or set(document) != TOP_KEYS:
        return ["admission manifest top-level keys differ"]
    version = document["schema_version"]
    if type(version) is not int or version != 1 or not isinstance(document["admissions"], list):
        return ["admission manifest schema differs"]
    errors: list[str] = []
    ids: set = set()
    dests: set = set()
    for index, row in enumerate(document["admissions"]):
        check_row(root, index, row, ids, dests, errors)
    return errors


def missing_notices(root: Path, relative: str = MANIFEST) -> list[str]:
    """TA-02: every admitted row must be listed in the public notices file."""
    document = json.loads((root / relative).read_text(encoding="utf-8"))
    notices = (root / NOTICES).read_text(encoding="utf-8")
    return [
        row["admission_id"]
        for row in document["admissions"]
        if row["state"] == "VERIFIED_ALLOWED" and row["admission_id"] not in notices
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".")
    args = parser.parse_args()
    root = Path(args.root).resolve()
    errors = validate(root)
    if not errors:
        errors = [f"{item} missing from {NOTICES}" for item in missing_notices(root)]
    for error in errors:
        print(f"FAIL: {error}")
    if errors:
        return 1
    print("Source admissions: structure PASS (rights are not established by this check)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
