#!/usr/bin/env python3
"""Benchmark-only Evidence-Inference PICO prompt and span schema (ADM-0032 / T28).

Adapted from jayded/evidence-inference @ a661e8c14f973398380c8865cf2f27a535aaaf6d
(`evidence_inference/preprocess/preprocessor.py`, MIT; see `bench/evidence_inference/LICENSE`
and `bench/evidence_inference/PROVENANCE.md`), replacing `pandas`/`numpy`/`scikit-learn`
with Python standard-library dataclasses and CSV/JSONL loaders. Strictly confined to
`bench/evidence_inference/` and never shipped in product binaries.
"""
from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

PROMPT_ID_COL_NAME = "PromptID"
LBL_COL_NAME = "Label Code"
LABEL_COL_NAME = "Label"
EVIDENCE_COL_NAME = "Annotations"
EVIDENCE_START_COL = "Evidence Start"
EVIDENCE_END_COL = "Evidence End"
STUDY_ID_COL = "PMCID"
VALID_LABEL_COL = "Valid Label"
VALID_REASONING_COL = "Valid Reasoning"


class SignificanceClass(IntEnum):
    SIGNIFICANTLY_DECREASED = -1
    NO_SIGNIFICANT_DIFFERENCE = 0
    SIGNIFICANTLY_INCREASED = 1

    @classmethod
    def parse(cls, value: int | str) -> "SignificanceClass":
        if isinstance(value, bool):
            raise ValueError("Boolean is not a valid Evidence-Inference significance class")
        if isinstance(value, int):
            return cls(value)
        norm = str(value).strip().lower()
        mapping = {
            "-1": cls.SIGNIFICANTLY_DECREASED,
            "significantly decreased": cls.SIGNIFICANTLY_DECREASED,
            "0": cls.NO_SIGNIFICANT_DIFFERENCE,
            "no significant difference": cls.NO_SIGNIFICANT_DIFFERENCE,
            "1": cls.SIGNIFICANTLY_INCREASED,
            "+1": cls.SIGNIFICANTLY_INCREASED,
            "significantly increased": cls.SIGNIFICANTLY_INCREASED,
        }
        if norm not in mapping:
            raise ValueError(f"Unsupported Evidence-Inference significance label: {value!r}")
        return mapping[norm]


@dataclass(frozen=True)
class PicoPrompt:
    prompt_id: str
    study_id: str
    intervention: str
    comparator: str
    outcome: str

    def __post_init__(self) -> None:
        for field_name, val in (
            ("prompt_id", self.prompt_id),
            ("study_id", self.study_id),
            ("intervention", self.intervention),
            ("comparator", self.comparator),
            ("outcome", self.outcome),
        ):
            if not isinstance(val, str) or not val.strip():
                raise ValueError(f"PicoPrompt.{field_name} must be a non-empty string")


@dataclass(frozen=True)
class EvidenceAnnotation:
    prompt_id: str
    study_id: str
    significance: SignificanceClass
    evidence_text: str
    evidence_start: int
    evidence_end: int

    def validate_against_article(self, article_text: str) -> None:
        if not self.evidence_text.strip():
            raise ValueError("evidence_text must be non-empty")
        if self.evidence_start < 0 or self.evidence_end <= self.evidence_start:
            raise ValueError("Invalid evidence character span bounds")
        if self.evidence_end > len(article_text):
            raise ValueError("Evidence span exceeds article length")
        extracted = article_text[self.evidence_start : self.evidence_end]
        if extracted != self.evidence_text:
            raise ValueError(
                f"Span [{self.evidence_start}:{self.evidence_end}]={extracted!r} != {self.evidence_text!r}"
            )


def load_prompts_csv(csv_path: str | Path) -> Dict[str, PicoPrompt]:
    out: Dict[str, PicoPrompt] = {}
    with Path(csv_path).open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            i = (row.get("Intervention") or "").strip()
            c = (row.get("Comparator") or "").strip()
            o = (row.get("Outcome") or "").strip()
            pid = (row.get(PROMPT_ID_COL_NAME) or "").strip()
            sid = (row.get(STUDY_ID_COL) or "").strip()
            if i and c and o and pid and sid:
                out[pid] = PicoPrompt(
                    prompt_id=pid,
                    study_id=sid,
                    intervention=i,
                    comparator=c,
                    outcome=o,
                )
    return out


def filter_valid_annotations(rows: Iterable[dict]) -> List[EvidenceAnnotation]:
    valid: List[EvidenceAnnotation] = []
    for row in rows:
        valid_lbl = str(row.get(VALID_LABEL_COL, "True")).strip().lower() in ("true", "1")
        valid_rsn = str(row.get(VALID_REASONING_COL, "True")).strip().lower() in ("true", "1")
        ev_text = str(row.get(EVIDENCE_COL_NAME, ""))
        raw_lbl = str(row.get(LABEL_COL_NAME, "")).strip().lower()
        if not (valid_lbl and valid_rsn and ev_text.strip() and raw_lbl != "invalid prompt"):
            continue
        raw_code = row.get(LBL_COL_NAME)
        code_source = (
            raw_code
            if raw_code is not None and str(raw_code).strip() != ""
            else row.get(LABEL_COL_NAME)
        )
        valid.append(
            EvidenceAnnotation(
                prompt_id=str(row[PROMPT_ID_COL_NAME]).strip(),
                study_id=str(row[STUDY_ID_COL]).strip(),
                significance=SignificanceClass.parse(code_source),
                evidence_text=ev_text,
                evidence_start=int(row[EVIDENCE_START_COL]),
                evidence_end=int(row[EVIDENCE_END_COL]),
            )
        )
    return valid


def load_jsonl_records(path: str | Path) -> list[dict]:
    with Path(path).open("r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def span_overlap_iou(span_a: Tuple[int, int], span_b: Tuple[int, int]) -> float:
    a0, a1 = span_a
    b0, b1 = span_b
    if a1 <= a0 or b1 <= b0:
        return 0.0
    inter = max(0, min(a1, b1) - max(a0, b0))
    union = (a1 - a0) + (b1 - b0) - inter
    return 0.0 if union <= 0 else inter / union
