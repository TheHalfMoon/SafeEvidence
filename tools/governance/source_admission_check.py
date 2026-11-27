#!/usr/bin/env python3
"""Fail-closed validator for exact-slice source admissions and lockfile closures (TA-01).

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
import tomllib
from pathlib import Path, PurePosixPath

MANIFEST = "docs/evidence/source_admissions.json"
NOTICES = "THIRD_PARTY_NOTICES.md"
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
ADM_ID = re.compile(r"ADM-[0-9]{4}\Z")
STATES = {"CANDIDATE", "RIGHTS_UNKNOWN", "VERIFIED_ALLOWED", "REFERENCE_ONLY", "DENIED"}
BASES = {"FOUNDER_OWNED", "PUBLIC_LICENSE", "SEPARATE_PERMISSION_VERIFIED"}
DECISION_REF = re.compile(
    r"https://github\.com/TheHalfMoon/SafeEvidence/issues/[0-9]+#issuecomment-[0-9]+\Z"
)
PUBLIC_LICENSE_ADR_REFS = {
    "docs/adr/0004-public-license-source-admission-and-zero-cost-governance-simplification.md",
    "docs/plan/PLAN_AMENDMENT_V1_7.md",
}
ADR0004_EXCLUDED_REPOS = {
    "ijmarshall/robotreviewer",
    "ijmarshall/trialstreamer",
    "bwallace/rrnlp",
    "dwadden/multivers",
}
ADR0004_EXCLUDED_PACKETS = {"T27b", "T28b", "T34", "T35"}
ADR0004_VERIFIED_PUBLIC_REPOS = {
    "abdulazizshehri/medscale",
    "thehalfmoon/medorigin",
    "abdulazizshehri/safeocr",
    "thehalfmoon/commandmed",
    "maziyarpanahi/openmed",
    "asreview/asreview",
    "asreview/synergy-dataset",
    "statsmodels/statsmodels",
    "xberg-io/xberg",
    "docling-project/docling.rs",
    "anush008/fastembed-rs",
    "asg017/sqlite-vec",
    "mozilla/uniffi-rs",
    "awslabs/tough",
    "allenai/scifact",
    "jayded/evidence-inference",
    "wenglab-informaticsresearch/picox",
    "paddlepaddle/paddleocr",
    "beir-cellar/beir",
    "ncbi/medcpt",
}
WITHHELD_PRIVATE_REPOS = {
    "thehalfmoon/dal",
    "thehalfmoon/kernux",
    "thehalfmoon/morize",
    "thehalfmoon/inercative",
    "thehalfmoon/signthos",
    "thehalfmoon/wispral",
    "thehalfmoon/sentrdel",
    "thehalfmoon/ecra",
}
REPO = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9][A-Za-z0-9._-]*\Z")
PACKET = re.compile(r"(T[0-9]{2}[a-z]?|CRATE-[a-z0-9-]+)\Z")
CRATE_PACKET = re.compile(r"CRATE-[a-z0-9-]+\Z")
LICENSES = {
    "Apache-2.0",
    "MIT",
    "MIT OR Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "Zlib",
    "Unicode-3.0",
    "MPL-2.0",
}
BENCHMARK_ONLY_LICENSES = {
    "CC0-1.0",
    "CC-BY-4.0",
    "ODC-By-1.0",
}
CLOSURE_ALLOWED_LICENSES = LICENSES | {
    "Apache-2.0 OR MIT",
    "Apache-2.0 WITH LLVM-exception",
}
DEST_ROOTS = ("product/", "workers/", "bench/", "tools/release/", "tools/governance/donor/")
REQUIRED_TOP_KEYS = {"schema_version", "admissions"}
ALLOWED_TOP_KEYS = {"schema_version", "admissions", "crate_closures"}
ROW_KEYS = {
    "admission_id",
    "packet",
    "repo",
    "source_commit",
    "state",
    "copy_authorized",
    "basis",
    "license_spdx",
    "decision_ref",
    "notices",
    "transitive",
    "assets",
    "security_test_owner",
    "files",
}
CLOSURE_KEYS = {
    "admission_id",
    "packet",
    "ecosystem",
    "lockfile",
    "lockfile_lf_sha256",
    "lockfile_lf_bytes",
    "package_count",
    "state",
    "copy_authorized",
    "basis",
    "allowed_licenses",
    "decision_ref",
    "policy_file",
    "notices",
    "allowed_install_scripts_ignored",
    "security_test_owner",
}
FILE_KEYS = {"source_path", "git_blob_oid", "bytes", "dest_path", "modification"}
MODIFICATIONS = {"none", "adapted", "not_copied"}
CRATES_IO_REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
NPM_REGISTRY_PREFIX = "https://registry.npmjs.org/"


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


def is_full_sha256(value: object) -> bool:
    return isinstance(value, str) and bool(HEX64.fullmatch(value)) and set(value) != {"0"}


def resolve_regular_file(root: Path, relative: str) -> Path | None:
    current = root
    for part in PurePosixPath(relative).parts:
        current = current / part
        if current.is_symlink() or os.path.isjunction(current):
            return None
    return current if current.is_file() else None


def matches_blob(data: bytes, oid: str, size: int) -> bool:
    """Accept a checkout whose only difference is CRLF conversion of an LF blob."""
    if len(data) == size and git_blob_oid(data) == oid:
        return True
    if data.count(b"\n") != data.count(b"\r\n"):
        return False
    normalized = data.replace(b"\r\n", b"\n")
    return len(normalized) == size and git_blob_oid(normalized) == oid


def normalize_lf_if_consistent(data: bytes, expected_lf_size: int) -> bytes | None:
    """Return LF bytes if data is pure LF or pure CRLF matching expected_lf_size."""
    if len(data) == expected_lf_size and b"\r\n" not in data:
        return data
    if data.count(b"\n") != data.count(b"\r\n"):
        return None
    normalized = data.replace(b"\r\n", b"\n")
    return normalized if len(normalized) == expected_lf_size else None


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
        repo_lower = ""
    else:
        repo_lower = row["repo"].lower()
    pkt_str = row["packet"] if isinstance(row["packet"], str) else ""
    if repo_lower == "thehalfmoon/dal" or pkt_str.startswith("T14"):
        errors.append(f"{label}: DAL (T14) is permanently banned from SafeEvidence")
    elif repo_lower in WITHHELD_PRIVATE_REPOS:
        errors.append(f"{label}: withheld private repository cannot appear in public manifest")
    if not pkt_str or not PACKET.fullmatch(pkt_str):
        errors.append(f"{label}: packet id invalid")
    if not is_full_oid(row["source_commit"]):
        errors.append(f"{label}: source_commit must be 40 hex")
    state = row["state"]
    if not isinstance(state, str) or state not in STATES:
        errors.append(f"{label}: unknown state")
    if row["copy_authorized"] is not (state == "VERIFIED_ALLOWED"):
        errors.append(f"{label}: copy_authorized must be true only for VERIFIED_ALLOWED")
    files = row["files"]
    excluded_pkt = pkt_str in ADR0004_EXCLUDED_PACKETS or pkt_str.startswith(
        ("T27b", "T28b", "T34", "T35")
    )
    if state == "VERIFIED_ALLOWED":
        if repo_lower in ADR0004_EXCLUDED_REPOS or excluded_pkt:
            errors.append(
                f"{label}: copyleft, unlicensed, or dropped packet/repository cannot be admitted under ADR-0004"
            )
        basis = row["basis"]
        if not isinstance(basis, str) or basis not in BASES:
            errors.append(f"{label}: basis cannot admit")
        decision = row["decision_ref"]
        valid_github_ref = isinstance(decision, str) and bool(DECISION_REF.fullmatch(decision))
        valid_adr_ref = (
            basis == "PUBLIC_LICENSE"
            and repo_lower in ADR0004_VERIFIED_PUBLIC_REPOS
            and repo_lower not in ADR0004_EXCLUDED_REPOS
            and not excluded_pkt
            and isinstance(decision, str)
            and decision in PUBLIC_LICENSE_ADR_REFS
            and resolve_regular_file(root, decision) is not None
        )
        if not (valid_github_ref or valid_adr_ref):
            errors.append(f"{label}: decision_ref must cite a recorded decision")
        spdx = row["license_spdx"]
        bench_only_ok = (
            isinstance(spdx, str)
            and spdx in BENCHMARK_ONLY_LICENSES
            and basis == "PUBLIC_LICENSE"
            and isinstance(files, list)
            and bool(files)
            and all(
                isinstance(e, dict)
                and isinstance(e.get("dest_path"), str)
                and e["dest_path"].startswith("bench/")
                for e in files
            )
        )
        if not ((isinstance(spdx, str) and spdx in LICENSES) or bench_only_ok):
            errors.append(f"{label}: license not on the admitted allowlist")
        for key in ("notices", "transitive", "assets", "security_test_owner"):
            if not isinstance(row[key], str) or not row[key].strip():
                errors.append(f"{label}: {key} required for admission")
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


def check_cargo_closure(
    label: str,
    lf_bytes: bytes,
    policy_path: Path,
    expected_count: int,
    allowed_licenses: set[str],
    ignored_scripts: list[str],
    errors: list[str],
) -> None:
    if ignored_scripts:
        errors.append(f"{label}: cargo closures cannot ignore npm install scripts")
    try:
        lock = tomllib.loads(lf_bytes.decode("utf-8"))
        policy = tomllib.loads(policy_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        errors.append(f"{label}: unreadable cargo lock or policy: {exc}")
        return
    packages = lock.get("package")
    if not isinstance(packages, list) or len(packages) != expected_count:
        errors.append(f"{label}: cargo package count differs from lockfile")
        return
    for pkg in packages:
        if not isinstance(pkg, dict):
            errors.append(f"{label}: malformed cargo package entry")
            break
        source = pkg.get("source")
        if source is not None:
            if source != CRATES_IO_REGISTRY:
                errors.append(f"{label}: unreviewed cargo package source {source}")
                break
            if not is_full_sha256(pkg.get("checksum")):
                errors.append(f"{label}: cargo registry package missing 64-hex checksum")
                break
    licenses_section = policy.get("licenses", {})
    if not isinstance(licenses_section, dict):
        errors.append(f"{label}: policy_file [licenses] invalid")
        return
    deny_allow = licenses_section.get("allow")
    if not isinstance(deny_allow, list) or not deny_allow:
        errors.append(f"{label}: policy_file missing [licenses].allow")
        return
    if not set(deny_allow).issubset(allowed_licenses):
        errors.append(f"{label}: policy_file allows licenses outside closure allowlist")
    if licenses_section.get("exceptions"):
        errors.append(f"{label}: policy_file cannot carry per-crate license exceptions")


def check_npm_closure(
    label: str,
    lf_bytes: bytes,
    policy_path: Path,
    expected_count: int,
    allowed_licenses: set[str],
    ignored_scripts: list[str],
    errors: list[str],
) -> None:
    try:
        plock = json.loads(lf_bytes.decode("utf-8"), object_pairs_hook=reject_duplicates)
        pkg_json = json.loads(
            policy_path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates
        )
    except (OSError, UnicodeError, ValueError, RecursionError) as exc:
        errors.append(f"{label}: unreadable package-lock.json or package.json: {exc}")
        return
    if not isinstance(pkg_json, dict) or not isinstance(plock, dict):
        errors.append(f"{label}: package.json or package-lock.json is not an object")
        return
    if plock.get("lockfileVersion") != 3 or "dependencies" in plock:
        errors.append(f"{label}: package-lock.json must be v3 without legacy dependencies")
        return
    packages = plock.get("packages") if isinstance(plock, dict) else None
    if not isinstance(packages, dict):
        errors.append(f"{label}: package-lock.json missing packages map")
        return
    npm_entries = {key: value for key, value in packages.items() if key != ""}
    if len(npm_entries) != expected_count:
        errors.append(f"{label}: npm package count differs from package-lock.json")
        return
    observed_scripts = []
    for key, meta in sorted(npm_entries.items()):
        if not isinstance(meta, dict):
            errors.append(f"{label}: malformed npm entry {key}")
            return
        spdx = meta.get("license")
        if not isinstance(spdx, str) or spdx not in allowed_licenses:
            errors.append(f"{label}: npm package {key} license {spdx!r} not allowed")
        resolved = meta.get("resolved")
        if not isinstance(resolved, str) or not resolved.startswith(NPM_REGISTRY_PREFIX):
            errors.append(f"{label}: npm package {key} uses non-registry resolved URL")
        integrity = meta.get("integrity")
        if not isinstance(integrity, str) or not integrity.startswith("sha512-"):
            errors.append(f"{label}: npm package {key} missing sha512 integrity")
        if meta.get("hasInstallScript") is True:
            observed_scripts.append(key)
    if sorted(observed_scripts) != sorted(ignored_scripts):
        errors.append(
            f"{label}: install-script package inventory differs ({observed_scripts})"
        )


def check_closure(
    root: Path, index: int, row: object, ids: set, lockfiles: set, errors: list[str]
) -> None:
    label = f"Closure {index}"
    if not isinstance(row, dict) or set(row) != CLOSURE_KEYS:
        errors.append(f"{label}: closure keys differ")
        return
    identifier = row["admission_id"]
    if (
        not isinstance(identifier, str)
        or not ADM_ID.fullmatch(identifier)
        or identifier in ids
    ):
        errors.append(f"{label}: admission_id invalid or duplicated")
    if isinstance(identifier, str):
        ids.add(identifier)
    if not isinstance(row["packet"], str) or not CRATE_PACKET.fullmatch(row["packet"]):
        errors.append(f"{label}: packet must match CRATE-<name>")
    ecosystem = row["ecosystem"]
    if ecosystem not in ("cargo", "npm"):
        errors.append(f"{label}: ecosystem must be cargo or npm")
    state = row["state"]
    if state != "VERIFIED_ALLOWED":
        errors.append(f"{label}: in-tree lockfile closures must be VERIFIED_ALLOWED")
    if row["copy_authorized"] is not True:
        errors.append(f"{label}: copy_authorized must be true for in-tree lockfile closures")
    if row["basis"] != "PUBLIC_LICENSE":
        errors.append(f"{label}: lockfile closures must use PUBLIC_LICENSE basis")
    decision = row["decision_ref"]
    valid_github_ref = isinstance(decision, str) and bool(DECISION_REF.fullmatch(decision))
    valid_adr_ref = (
        isinstance(decision, str)
        and decision in PUBLIC_LICENSE_ADR_REFS
        and resolve_regular_file(root, decision) is not None
    )
    if not (valid_github_ref or valid_adr_ref):
        errors.append(f"{label}: decision_ref must cite a recorded decision")
    for key in ("notices", "security_test_owner"):
        if not isinstance(row[key], str) or not row[key].strip():
            errors.append(f"{label}: {key} required")
    allowed = row["allowed_licenses"]
    if (
        not isinstance(allowed, list)
        or not allowed
        or not all(isinstance(x, str) and x in CLOSURE_ALLOWED_LICENSES for x in allowed)
    ):
        errors.append(f"{label}: allowed_licenses invalid or outside allowlist")
        allowed_set: set[str] = set()
    else:
        allowed_set = set(allowed)
    ignored = row["allowed_install_scripts_ignored"]
    if not isinstance(ignored, list) or not all(
        isinstance(x, str) and x.startswith("node_modules/") for x in ignored
    ):
        errors.append(f"{label}: allowed_install_scripts_ignored invalid")
        ignored = []
    sha = row["lockfile_lf_sha256"]
    if not is_full_sha256(sha):
        errors.append(f"{label}: lockfile_lf_sha256 must be 64 hex")
    lf_size = row["lockfile_lf_bytes"]
    pkg_count = row["package_count"]
    if (
        isinstance(lf_size, bool)
        or not isinstance(lf_size, int)
        or lf_size <= 0
        or isinstance(pkg_count, bool)
        or not isinstance(pkg_count, int)
        or pkg_count <= 0
    ):
        errors.append(f"{label}: lockfile_lf_bytes and package_count must be positive ints")
        return
    lock_rel, policy_rel = row["lockfile"], row["policy_file"]
    if not safe_relative(lock_rel) or not lock_rel.startswith("product/"):
        errors.append(f"{label}: lockfile path unsafe or outside product/")
        return
    if lock_rel in lockfiles:
        errors.append(f"{label}: lockfile listed twice")
    lockfiles.add(lock_rel)
    if not safe_relative(policy_rel) or not policy_rel.startswith("product/"):
        errors.append(f"{label}: policy_file path unsafe or outside product/")
        return
    lock_path = resolve_regular_file(root, lock_rel)
    policy_path = resolve_regular_file(root, policy_rel)
    if lock_path is None or policy_path is None:
        errors.append(f"{label}: lockfile or policy_file missing or symlinked")
        return
    lf_bytes = normalize_lf_if_consistent(lock_path.read_bytes(), lf_size)
    if lf_bytes is None or hashlib.sha256(lf_bytes).hexdigest() != sha:
        errors.append(f"{label}: lockfile digest or byte length differs from pinned closure")
        return
    if not allowed_set:
        return
    if ecosystem == "cargo":
        check_cargo_closure(
            label, lf_bytes, policy_path, pkg_count, allowed_set, ignored, errors
        )
    elif ecosystem == "npm":
        check_npm_closure(
            label, lf_bytes, policy_path, pkg_count, allowed_set, ignored, errors
        )


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
    if (
        not isinstance(document, dict)
        or not REQUIRED_TOP_KEYS.issubset(document)
        or not set(document).issubset(ALLOWED_TOP_KEYS)
    ):
        return ["admission manifest top-level keys differ"]
    version = document["schema_version"]
    if type(version) is not int or version != 1 or not isinstance(document["admissions"], list):
        return ["admission manifest schema differs"]
    closures = document.get("crate_closures", [])
    if not isinstance(closures, list):
        return ["admission manifest crate_closures must be a list"]
    errors: list[str] = []
    ids: set = set()
    dests: set = set()
    lockfiles: set = set()
    for index, row in enumerate(document["admissions"]):
        check_row(root, index, row, ids, dests, errors)
    for index, row in enumerate(closures):
        check_closure(root, index, row, ids, lockfiles, errors)
    return errors


def notice_rows(text: str) -> tuple[dict[str, list[str]], list[str]]:
    """Exact `| ADM-nnnn | ... | `destination` |` table rows, rejecting duplicate IDs."""
    rows: dict[str, list[str]] = {}
    duplicates: list[str] = []
    for line in text.splitlines():
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) == 5 and re.fullmatch(r"ADM-[0-9]{4}", cells[0]):
            if cells[0] in rows:
                duplicates.append(f"{cells[0]}: duplicate notice row")
            rows[cells[0]] = re.findall(r"`([^`]+)`", cells[4])
    return rows, duplicates


def missing_notices(root: Path, relative: str = MANIFEST) -> list[str]:
    """TA-02: each admitted row and closure needs a notices row covering its destination."""
    manifest_path = resolve_regular_file(root, relative)
    notices_path = resolve_regular_file(root, NOTICES)
    if manifest_path is None or notices_path is None:
        return ["missing or symlinked manifest or notices"]
    document = json.loads(
        manifest_path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates
    )
    rows, duplicates = notice_rows(notices_path.read_text(encoding="utf-8"))
    problems = list(duplicates)
    for row in document["admissions"]:
        if row["state"] != "VERIFIED_ALLOWED":
            continue
        identifier = row["admission_id"]
        if identifier not in rows:
            problems.append(identifier)
            continue
        for entry in row["files"]:
            dest = entry["dest_path"]
            if dest and not any(
                dest == d or dest.startswith(d.rstrip("/") + "/")
                for d in rows[identifier]
            ):
                problems.append(f"{identifier}: {dest}")
    for closure in document.get("crate_closures", []):
        if closure["state"] != "VERIFIED_ALLOWED":
            continue
        identifier = closure["admission_id"]
        lockfile = closure["lockfile"]
        if identifier not in rows:
            problems.append(identifier)
        elif not any(
            lockfile == d or lockfile.startswith(d.rstrip("/") + "/")
            for d in rows[identifier]
        ):
            problems.append(f"{identifier}: {lockfile}")
    return problems


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
