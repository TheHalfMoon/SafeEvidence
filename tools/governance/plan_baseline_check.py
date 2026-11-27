#!/usr/bin/env python3
"""Validate the V1 planning baseline; never authorize imports or clinical use.

Standard library only. No network. Checks that the frozen planning artifacts
exist, match the digests recorded in docs/PLAN_FREEZE.md, cross-reference
each other consistently, and that transplant pins remain discovery-only.
A PASS means the planning documents are internally consistent, NOT that any
source is admitted, any feature is built, or any clinical gate has passed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

from p01_candidate_integrity import (
    reject_duplicate_keys,
    trusted_path_has_symlink,
    visible_markdown_lines,
)

FREEZE = "docs/PLAN_FREEZE.md"
PINS = "docs/evidence/source_transplant_pins_2026-10-19.json"
MATRIX = "docs/plan/SOURCE_TRANSPLANT_MATRIX_V1.md"
FEATURES = "docs/plan/FEATURE_COVERAGE_MATRIX_V1.md"
PACKETS = "docs/plan/IMPLEMENTATION_WORK_PACKETS_V1.md"
TESTS = "docs/plan/TEST_ACCEPTANCE_MATRIX_V1.md"
ARTIFACTS = (
    "docs/plan/SAFEEVIDENCE_MASTER_PLAN_V1.md",
    "docs/plan/ARCHITECTURE_SPEC_V1.md",
    MATRIX,
    FEATURES,
    PACKETS,
    TESTS,
    "docs/research/REA_RESEARCH_DOSSIER_V1_2026-10-19.md",
    "docs/reviews/PLAN_V1_INDEPENDENT_VALIDATION_2026-10-19.md",
    PINS,
)
FREEZE_STATES = ("FREEZE_PENDING", "FROZEN")
GATES = ("GATE_ADMISSION", "GATE_CLINICAL", "GATE_TRUST", "DEFERRED")
SCOPES = ("VS-1", "V1", "V1-PARTIAL", "DEFERRED")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
PACKET_ID = re.compile(r"^T\d{2}[a-z]?$")
WP_ID = re.compile(r"WP-(?:\d{2}[a-z]?|M0)")
WP_REF = re.compile(r"\bWP-(?:\d{2}[a-z]?|M0)\b")
TA_REF = re.compile(r"\bTA-(?:\d{2}|M0)\b")


def normalized_digest(data: bytes) -> str:
    """SHA-256 of LF-normalized bytes so Windows and Linux checkouts agree."""
    return hashlib.sha256(data.replace(b"\r\n", b"\n")).hexdigest()


def table_rows(text: str) -> list[list[str]]:
    """Visible Markdown table body rows (header and separator rows excluded)."""
    rows: list[list[str]] = []
    previous_was_table = False
    for line in visible_markdown_lines(text):
        if not line.startswith("|"):
            previous_was_table = False
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if not previous_was_table:
            previous_was_table = True  # header row
            continue
        if cells and set(cells[0]) <= set("-: "):
            continue
        rows.append(cells)
    return rows


def first_column_ids(text: str, pattern: re.Pattern[str]) -> dict[str, list[str]]:
    found: dict[str, list[str]] = {}
    for cells in table_rows(text):
        if cells and pattern.fullmatch(cells[0]):
            found.setdefault(cells[0], cells)
    return found


def read_text(root: Path, relative: str, problems: list[str]) -> str:
    if trusted_path_has_symlink(root, relative):
        problems.append(f"Symbolic link in planning input: {relative}")
        return ""
    try:
        return (root / relative).read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        problems.append(f"Missing or unreadable planning artifact: {relative} ({type(exc).__name__})")
        return ""


def check_freeze(root: Path, problems: list[str]) -> str:
    text = read_text(root, FREEZE, problems)
    visible = "\n".join(visible_markdown_lines(text))
    states = [s for s in FREEZE_STATES if re.search(rf"\bFreeze state:\s*`?{s}`?", visible)]
    if len(states) != 1:
        problems.append("PLAN_FREEZE.md must declare exactly one 'Freeze state:' value")
        state = "UNKNOWN"
    else:
        state = states[0]
    if state == "FROZEN":
        if not re.search(r"Freeze tag:\s*`plan-v\d+\.\d+\.\d+`", visible):
            problems.append("FROZEN baseline requires a 'Freeze tag: `plan-vX.Y.Z`' line")
        if not re.search(r"Freeze commit:\s*`[0-9a-f]{40}`", visible):
            problems.append("FROZEN baseline requires a 'Freeze commit:' 40-hex SHA")
    recorded: dict[str, str] = {}
    for cells in table_rows(text):
        if len(cells) >= 2 and cells[0].startswith("`") and HEX64.match(cells[1].strip("`")):
            recorded[cells[0].strip("`")] = cells[1].strip("`")
    for artifact in ARTIFACTS:
        if artifact not in recorded:
            problems.append(f"PLAN_FREEZE.md lacks a digest row for {artifact}")
            continue
        if trusted_path_has_symlink(root, artifact):
            problems.append(f"Symbolic link in planning input: {artifact}")
            continue
        try:
            actual = normalized_digest((root / artifact).read_bytes())
        except OSError:
            problems.append(f"Frozen artifact missing: {artifact}")
            continue
        if actual != recorded[artifact]:
            problems.append(f"Digest drift from PLAN_FREEZE.md: {artifact}")
    return state


def check_pins(root: Path, problems: list[str]) -> dict[str, str]:
    """Return {packet_id: commit} for well-formed packets."""
    raw = read_text(root, PINS, problems)
    if not raw:
        return {}
    try:
        data = json.loads(raw, object_pairs_hook=reject_duplicate_keys)
    except (ValueError, TypeError) as exc:
        problems.append(f"Transplant pins are not strict JSON: {exc}")
        return {}
    if not isinstance(data, dict):
        problems.append("Transplant pins root must be a JSON object")
        return {}
    if data.get("admission_state") != "NO_ADMISSIONS":
        problems.append("Transplant pins must stay NO_ADMISSIONS (discovery only)")
    if data.get("copy_authorized") is not False:
        problems.append("Transplant pins must keep copy_authorized=false")
    packets = data.get("packets")
    if not isinstance(packets, dict) or not packets:
        problems.append("Transplant pins have no packets")
        return {}
    commits: dict[str, str] = {}
    for packet_id, packet in packets.items():
        if not PACKET_ID.match(packet_id) or not isinstance(packet, dict):
            problems.append(f"Bad packet id or non-object packet {packet_id}")
            continue
        if not HEX40.match(str(packet.get("commit", ""))):
            problems.append(f"{packet_id}: commit is not a full 40-hex SHA")
        else:
            commits[packet_id] = packet["commit"]
        redacted = packet.get("redacted_file_manifest")
        if redacted is not None:
            # Private-repository pins: only a commitment is public (AGENTS.md).
            if "files" in packet:
                problems.append(f"{packet_id}: redacted packet must not also list files")
            if (not isinstance(redacted, dict)
                    or not HEX64.match(str(redacted.get("commitment_sha256", "")))
                    or not isinstance(redacted.get("file_count"), int)
                    or isinstance(redacted.get("file_count"), bool)
                    or redacted["file_count"] <= 0):
                problems.append(f"{packet_id}: malformed redacted_file_manifest")
            if packet.get("repo_visibility_2026_10_19") != "private":
                problems.append(f"{packet_id}: only private repositories may be redacted")
            continue
        files = packet.get("files")
        if not isinstance(files, list) or not files:
            problems.append(f"{packet_id}: no pinned files")
            continue
        seen: set[str] = set()
        for entry in files:
            if not isinstance(entry, dict):
                problems.append(f"{packet_id}: non-object file entry")
                continue
            path = entry.get("path")
            if not isinstance(path, str) or path in seen:
                problems.append(f"{packet_id}: missing or duplicate path")
            seen.add(str(path))
            if not HEX40.match(str(entry.get("git_blob_oid", ""))):
                problems.append(f"{packet_id}: bad blob OID for {path}")
            size = entry.get("bytes")
            # Empty files (e.g. package __init__.py) are legitimate pins.
            if not isinstance(size, int) or isinstance(size, bool) or size < 0:
                problems.append(f"{packet_id}: bad byte count for {path}")
    return commits


def dependency_cycle(graph: dict[str, set[str]]) -> list[str]:
    """Return one dependency cycle among work packets, or [] when acyclic."""
    state: dict[str, int] = {}
    stack: list[str] = []

    def visit(node: str) -> list[str]:
        state[node] = 1
        stack.append(node)
        for nxt in sorted(graph.get(node, ())):
            if state.get(nxt) == 1:
                return stack[stack.index(nxt):] + [nxt]
            if nxt not in state:
                found = visit(nxt)
                if found:
                    return found
        stack.pop()
        state[node] = 2
        return []

    for node in sorted(graph):
        if node not in state:
            found = visit(node)
            if found:
                return found
    return []


def check_cross_references(root: Path, commits: dict[str, str], problems: list[str]) -> dict[str, int]:
    pinned = set(commits)
    matrix = first_column_ids(read_text(root, MATRIX, problems), PACKET_ID)
    packets = first_column_ids(read_text(root, PACKETS, problems), WP_ID)
    tests = first_column_ids(read_text(root, TESTS, problems), re.compile(r"TA-(?:\d{2}|M0)"))
    features = first_column_ids(read_text(root, FEATURES, problems), re.compile(r"F\d{2}"))

    for packet_id in sorted(pinned - set(matrix)):
        problems.append(f"Pinned packet {packet_id} missing from transplant matrix")
    for packet_id, cells in matrix.items():
        if "COPY_BOUNDED" in " ".join(cells) and packet_id not in pinned:
            problems.append(f"COPY_BOUNDED packet {packet_id} has no file pins")
        for sha in re.findall(r"`([0-9a-f]{40})`", " ".join(cells)):
            if packet_id in commits and sha != commits[packet_id]:
                problems.append(f"{packet_id}: matrix commit {sha[:12]} differs from pins JSON")

    depends: dict[str, set[str]] = {}

    for wp_id, cells in packets.items():
        row = " | ".join(cells)
        if not any(gate in cells[-1] for gate in GATES):
            problems.append(f"{wp_id}: gate column must name one of {', '.join(GATES)}")
        for ref in TA_REF.findall(row):
            if ref not in tests:
                problems.append(f"{wp_id}: references unknown test {ref}")
        for ref in WP_REF.findall(" | ".join(cells[1:])):
            if ref not in packets:
                problems.append(f"{wp_id}: depends on unknown packet {ref}")
        dep_cell = cells[3] if len(cells) > 3 else ""
        depends[wp_id] = {ref for ref in WP_REF.findall(dep_cell) if ref != wp_id}
    cycle = dependency_cycle(depends)
    if cycle:
        problems.append("Work-packet dependency cycle: " + " -> ".join(cycle))

    for ta_id, cells in tests.items():
        refs = WP_REF.findall(cells[2] if len(cells) > 2 else "")
        if not refs and "all runtime WPs" not in " ".join(cells):
            problems.append(f"{ta_id}: no owning work packet")
        for ref in refs:
            if ref not in packets:
                problems.append(f"{ta_id}: owned by unknown packet {ref}")

    for f_id, cells in features.items():
        scope = cells[-1]
        if not any(scope.startswith(s) for s in SCOPES):
            problems.append(f"{f_id}: scope must start with one of {', '.join(SCOPES)}")
        row = " | ".join(cells)
        if not scope.startswith("DEFERRED") and not WP_REF.search(row):
            problems.append(f"{f_id}: scheduled feature without a work packet")
        if not scope.startswith("DEFERRED") and not TA_REF.search(row):
            problems.append(f"{f_id}: scheduled feature without an acceptance test")
        for ref in WP_REF.findall(row):
            if ref not in packets:
                problems.append(f"{f_id}: references unknown packet {ref}")
        for ref in TA_REF.findall(row):
            if ref not in tests:
                problems.append(f"{f_id}: references unknown test {ref}")
        for ref in re.findall(r"\bT\d{2}[a-z]?\b", row):
            if ref not in matrix:
                problems.append(f"{f_id}: references unknown source {ref}")
    return {
        "transplant_rows": len(matrix),
        "pinned_packets": len(pinned),
        "work_packets": len(packets),
        "acceptance_tests": len(tests),
        "features": len(features),
    }


def validate(root: Path) -> dict[str, object]:
    problems: list[str] = []
    state = check_freeze(root, problems)
    commits = check_pins(root, problems)
    counts = check_cross_references(root, commits, problems)
    return {
        "check": "SafeEvidence V1 planning baseline consistency",
        "structure": "PASS" if not problems else "FAIL",
        "freeze_state": state,
        "counts": counts,
        "source_imports_authorized": False,
        "clinical_validation": "NOT_PERFORMED",
        "note": "Planning consistency only; not an admission, build, clinical or release approval.",
        "errors": problems,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--json", action="store_true")
    opts = parser.parse_args()
    report = validate(opts.root.resolve())
    if opts.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"Planning baseline: {report['structure']} (freeze state {report['freeze_state']})")
        for issue in report["errors"]:
            print("ERROR:", issue)
    return 0 if report["structure"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
