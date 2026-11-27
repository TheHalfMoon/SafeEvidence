#!/usr/bin/env python3
"""Unit tests for the benchmark-only SciFact evaluator harness (ADM-0030 / T27)."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from scifact_data import Corpus, GoldDataset, PredictedDataset  # noqa: E402
from scifact_metrics import compute_metrics  # noqa: E402


class SciFactHarnessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.corpus = Corpus.from_records(
            [
                {
                    "doc_id": 101,
                    "title": "Synthetic Trial 101",
                    "abstract": [
                        "Background statement.",
                        "Intervention X reduced synthetic biomarker B.",
                        "Adverse events were comparable.",
                    ],
                },
                {
                    "doc_id": 202,
                    "title": "Synthetic Trial 202",
                    "abstract": [
                        "Cohort overview.",
                        "Intervention Y did not alter endpoint Z.",
                    ],
                },
            ]
        )
        self.gold = GoldDataset(
            self.corpus,
            [
                {
                    "id": 1,
                    "claim": "Intervention X reduces synthetic biomarker B.",
                    "cited_doc_ids": [101],
                    "evidence": {"101": [{"sentences": [1], "label": "SUPPORT"}]},
                },
                {
                    "id": 2,
                    "claim": "Intervention Y improves endpoint Z.",
                    "cited_doc_ids": [202],
                    "evidence": {"202": [{"sentences": [1], "label": "CONTRADICT"}]},
                },
            ],
        )

    def test_exact_predictions_score_unit_f1(self) -> None:
        preds = PredictedDataset(
            self.gold,
            [
                {"id": 1, "evidence": {"101": {"label": "SUPPORT", "sentences": [1]}}},
                {"id": 2, "evidence": {"202": {"label": "CONTRADICT", "sentences": [1]}}},
            ],
        )
        metrics = compute_metrics(preds)
        for key in (
            "sentence_selection",
            "sentence_label",
            "abstract_label_only",
            "abstract_rationalized",
        ):
            self.assertAlmostEqual(metrics[key]["f1"], 1.0)

    def test_wrong_polarity_penalizes_label_f1_and_nei_rejected(self) -> None:
        preds = PredictedDataset(
            self.gold,
            [
                {"id": 1, "evidence": {"101": {"label": "SUPPORT", "sentences": [1]}}},
                {"id": 2, "evidence": {"202": {"label": "SUPPORT", "sentences": [1]}}},
            ],
        )
        metrics = compute_metrics(preds)
        self.assertAlmostEqual(metrics["sentence_selection"]["f1"], 1.0)
        self.assertAlmostEqual(metrics["sentence_label"]["f1"], 0.5)
        self.assertAlmostEqual(metrics["abstract_label_only"]["f1"], 0.5)

        with self.assertRaises(ValueError):
            PredictedDataset(
                self.gold,
                [{"id": 1, "evidence": {"101": {"label": "NOT_ENOUGH_INFO", "sentences": [1]}}}],
            )


if __name__ == "__main__":
    unittest.main()
