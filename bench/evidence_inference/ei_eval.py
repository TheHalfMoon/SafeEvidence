#!/usr/bin/env python3
"""Benchmark-only Evidence-Inference PICO classification & span evaluator (ADM-0032 / T28).

Adapted from jayded/evidence-inference @ a661e8c14f973398380c8865cf2f27a535aaaf6d
(`evidence_inference/models/pipeline.py`, MIT; see `bench/evidence_inference/LICENSE`
and `bench/evidence_inference/PROVENANCE.md`), replacing `torch`/`transformers`/`sklearn`
with deterministic Python standard-library evaluation primitives for offline verification.
"""
from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Dict, Iterable, Sequence, Tuple

try:
    from .ei_schema import EvidenceAnnotation, SignificanceClass, span_overlap_iou
except ImportError:  # pragma: no cover
    from ei_schema import EvidenceAnnotation, SignificanceClass, span_overlap_iou


@dataclass(frozen=True)
class InferencePrediction:
    prompt_id: str
    predicted_significance: SignificanceClass
    predicted_span: Tuple[int, int]


def _safe_div(num: float, den: float) -> float:
    return 0.0 if den == 0.0 else num / den


def evaluate_predictions(
    gold_annotations: Sequence[EvidenceAnnotation],
    predictions: Iterable[InferencePrediction],
    iou_threshold: float = 0.5,
) -> Dict[str, object]:
    if not math.isfinite(iou_threshold) or iou_threshold <= 0.0 or iou_threshold > 1.0:
        raise ValueError(f"iou_threshold must lie in (0.0, 1.0], got {iou_threshold!r}")
    gold_by_prompt: Dict[str, EvidenceAnnotation] = {}
    for ann in gold_annotations:
        if ann.prompt_id in gold_by_prompt:
            raise ValueError(f"Duplicate gold prompt_id={ann.prompt_id}")
        gold_by_prompt[ann.prompt_id] = ann

    pred_by_prompt: Dict[str, InferencePrediction] = {}
    for pred in predictions:
        if pred.prompt_id in pred_by_prompt:
            raise ValueError(f"Duplicate predicted prompt_id={pred.prompt_id}")
        pred_by_prompt[pred.prompt_id] = pred

    if set(gold_by_prompt) != set(pred_by_prompt):
        raise ValueError("Prediction prompt_id set must match gold prompt_id set exactly.")

    classes = (
        SignificanceClass.SIGNIFICANTLY_DECREASED,
        SignificanceClass.NO_SIGNIFICANT_DIFFERENCE,
        SignificanceClass.SIGNIFICANTLY_INCREASED,
    )
    tp = {c: 0 for c in classes}
    fp = {c: 0 for c in classes}
    fn = {c: 0 for c in classes}

    exact_cls = 0
    span_hits = 0
    joint_hits = 0

    for pid, gold in gold_by_prompt.items():
        pred = pred_by_prompt[pid]
        cls_ok = pred.predicted_significance == gold.significance
        if cls_ok:
            exact_cls += 1
            tp[gold.significance] += 1
        else:
            fp[pred.predicted_significance] += 1
            fn[gold.significance] += 1

        iou = span_overlap_iou((gold.evidence_start, gold.evidence_end), pred.predicted_span)
        span_ok = iou >= iou_threshold
        if span_ok:
            span_hits += 1
        if cls_ok and span_ok:
            joint_hits += 1

    per_class: Dict[str, Dict[str, float]] = {}
    f1_values = []
    for c in classes:
        p = _safe_div(tp[c], tp[c] + fp[c])
        r = _safe_div(tp[c], tp[c] + fn[c])
        f1 = _safe_div(2.0 * p * r, p + r)
        per_class[c.name] = {"precision": p, "recall": r, "f1": f1}
        f1_values.append(f1)

    total = len(gold_by_prompt)
    return {
        "count": total,
        "accuracy": _safe_div(exact_cls, total),
        "macro_f1": _safe_div(sum(f1_values), len(f1_values)),
        "span_hit_rate": _safe_div(span_hits, total),
        "joint_grounded_accuracy": _safe_div(joint_hits, total),
        "per_class": per_class,
    }
