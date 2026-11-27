#!/usr/bin/env python3
"""Benchmark-only SciFact sentence-level and abstract-level F1 evaluator (ADM-0030 / T27).

Adapted from allenai/scifact @ 68b98a56d93e0f9da0d2aab4e6c3294699a0f72e
(`verisci/evaluate/lib/metrics.py`, Apache-2.0; see `bench/scifact/LICENSE.md` and
`bench/scifact/PROVENANCE.md`), replacing `pandas.DataFrame` with deterministic
Python standard-library dictionaries so benchmark tests execute offline with zero
third-party packages.
"""
from __future__ import annotations

from collections import Counter
from typing import Dict, Iterable, Set

try:
    from .scifact_data import Claim, ClaimPredictions, Label, PredictedAbstract, PredictedDataset
except ImportError:  # pragma: no cover
    from scifact_data import Claim, ClaimPredictions, Label, PredictedAbstract, PredictedDataset

MAX_ABSTRACT_SENTS = 3


def safe_divide(num: float, denom: float) -> float:
    return 0.0 if denom == 0 else num / denom


def compute_f1(counts: Counter, difficulty: str | None = None) -> Dict[str, float]:
    correct_key = "correct" if difficulty is None else f"correct_{difficulty}"
    precision = safe_divide(counts[correct_key], counts["retrieved"])
    recall = safe_divide(counts[correct_key], counts["relevant"])
    f1 = safe_divide(2.0 * precision * recall, precision + recall)
    return {"precision": precision, "recall": recall, "f1": f1}


def contains_evidence(predicted: Set[int], gold: Iterable[Set[int]]) -> bool:
    return any(gold_rat.issubset(predicted) for gold_rat in gold)


def is_correct(doc_id: int, doc_pred: PredictedAbstract, gold: Claim) -> tuple[bool, bool]:
    pred_rationales = doc_pred.rationale[:MAX_ABSTRACT_SENTS]
    if doc_id not in gold.evidence:
        return False, False
    gold_label = gold.evidence[doc_id].label
    if doc_pred.label != gold_label:
        return False, False
    gold_rationales = [set(x) for x in gold.evidence[doc_id].rationales]
    good_rationalized = contains_evidence(set(pred_rationales), gold_rationales)
    return True, good_rationalized


def update_counts_abstract(
    pred: ClaimPredictions, gold: Claim, counts_abstract: Counter
) -> Counter:
    counts_abstract["relevant"] += len(gold.evidence)
    for doc_id, doc_pred in pred.predictions.items():
        if doc_pred.label == Label.NEI:
            continue
        counts_abstract["retrieved"] += 1
        good_label_only, good_rationalized = is_correct(doc_id, doc_pred, gold)
        if good_label_only:
            counts_abstract["correct_label_only"] += 1
        if good_rationalized:
            counts_abstract["correct_rationalized"] += 1
    return counts_abstract


def count_rationale_sents(predicted: Set[int], gold: list[Set[int]]) -> int:
    n_correct = 0
    for ix in predicted:
        gold_sets = [entry for entry in gold if ix in entry]
        if len(gold_sets) >= 2:
            raise ValueError("Sentence index cannot appear in multiple disjoint SciFact rationale sets.")
        if not gold_sets:
            continue
        if gold_sets[0].issubset(predicted):
            n_correct += 1
    return n_correct


def count_correct(doc_id: int, doc_pred: PredictedAbstract, gold: Claim) -> tuple[int, int]:
    if doc_id not in gold.evidence:
        return 0, 0
    gold_rationales = [set(x) for x in gold.evidence[doc_id].rationales]
    n_correct = count_rationale_sents(set(doc_pred.rationale), gold_rationales)
    correct_label = int(doc_pred.label == gold.evidence[doc_id].label)
    return n_correct, correct_label * n_correct


def update_counts_sentence(
    pred: ClaimPredictions, gold: Claim, counts_sentence: Counter
) -> Counter:
    for gold_doc in gold.evidence.values():
        counts_sentence["relevant"] += sum(len(x) for x in gold_doc.rationales)
    for doc_id, doc_pred in pred.predictions.items():
        if doc_pred.label == Label.NEI:
            continue
        counts_sentence["retrieved"] += len(doc_pred.rationale)
        n_sel, n_lbl = count_correct(doc_id, doc_pred, gold)
        counts_sentence["correct_selection"] += n_sel
        counts_sentence["correct_label"] += n_lbl
    return counts_sentence


def compute_metrics(preds: PredictedDataset) -> Dict[str, Dict[str, float]]:
    counts_abstract: Counter = Counter()
    counts_sentence: Counter = Counter()
    for pred in preds:
        gold = preds.gold.get_claim(pred.claim_id)
        counts_abstract = update_counts_abstract(pred, gold, counts_abstract)
        counts_sentence = update_counts_sentence(pred, gold, counts_sentence)
    return {
        "sentence_selection": compute_f1(counts_sentence, "selection"),
        "sentence_label": compute_f1(counts_sentence, "label"),
        "abstract_label_only": compute_f1(counts_abstract, "label_only"),
        "abstract_rationalized": compute_f1(counts_abstract, "rationalized"),
    }
