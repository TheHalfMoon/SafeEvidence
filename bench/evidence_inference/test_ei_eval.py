#!/usr/bin/env python3
"""Unit tests for the benchmark-only Evidence-Inference evaluator harness (ADM-0032 / T28)."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ei_eval import InferencePrediction, evaluate_predictions  # noqa: E402
from ei_schema import (  # noqa: E402
    EvidenceAnnotation,
    PicoPrompt,
    SignificanceClass,
    filter_valid_annotations,
)


class EvidenceInferenceHarnessTests(unittest.TestCase):
    def test_pico_span_validation_and_three_class_macro_f1(self) -> None:
        article = (
            "Synthetic RCT report. "
            "Arm A reduced systolic pressure compared with placebo. "
            "Heart rate showed no significant difference between arms. "
            "Serum potassium increased in Arm A."
        )
        s1 = "Arm A reduced systolic pressure compared with placebo."
        s2 = "Heart rate showed no significant difference between arms."
        s3 = "Serum potassium increased in Arm A."
        i1 = article.index(s1)
        i2 = article.index(s2)
        i3 = article.index(s3)

        prompt = PicoPrompt(
            prompt_id="P-1",
            study_id="SYN-PMC-1",
            intervention="Arm A",
            comparator="Placebo",
            outcome="Systolic pressure",
        )
        self.assertEqual(prompt.prompt_id, "P-1")

        gold = filter_valid_annotations(
            [
                {
                    "PromptID": "P-1",
                    "PMCID": "SYN-PMC-1",
                    "Label Code": -1,
                    "Label": "significantly decreased",
                    "Annotations": s1,
                    "Evidence Start": i1,
                    "Evidence End": i1 + len(s1),
                    "Valid Label": True,
                    "Valid Reasoning": True,
                },
                {
                    "PromptID": "P-2",
                    "PMCID": "SYN-PMC-1",
                    "Label Code": 0,
                    "Label": "no significant difference",
                    "Annotations": s2,
                    "Evidence Start": i2,
                    "Evidence End": i2 + len(s2),
                    "Valid Label": True,
                    "Valid Reasoning": True,
                },
                {
                    "PromptID": "P-3",
                    "PMCID": "SYN-PMC-1",
                    "Label Code": 1,
                    "Label": "significantly increased",
                    "Annotations": s3,
                    "Evidence Start": i3,
                    "Evidence End": i3 + len(s3),
                    "Valid Label": True,
                    "Valid Reasoning": True,
                },
                {
                    "PromptID": "P-INVALID",
                    "PMCID": "SYN-PMC-1",
                    "Label Code": 0,
                    "Label": "invalid prompt",
                    "Annotations": s3,
                    "Evidence Start": i3,
                    "Evidence End": i3 + len(s3),
                    "Valid Label": True,
                    "Valid Reasoning": True,
                },
            ]
        )
        self.assertEqual(len(gold), 3)
        for ann in gold:
            ann.validate_against_article(article)

        preds = [
            InferencePrediction("P-1", SignificanceClass.SIGNIFICANTLY_DECREASED, (i1, i1 + len(s1))),
            InferencePrediction("P-2", SignificanceClass.NO_SIGNIFICANT_DIFFERENCE, (i2, i2 + len(s2))),
            InferencePrediction("P-3", SignificanceClass.SIGNIFICANTLY_INCREASED, (i3, i3 + len(s3))),
        ]
        res = evaluate_predictions(gold, preds)
        self.assertAlmostEqual(float(res["accuracy"]), 1.0)
        self.assertAlmostEqual(float(res["macro_f1"]), 1.0)
        self.assertAlmostEqual(float(res["joint_grounded_accuracy"]), 1.0)

        bad_ann = EvidenceAnnotation(
            prompt_id="P-BAD",
            study_id="SYN-PMC-1",
            significance=SignificanceClass.NO_SIGNIFICANT_DIFFERENCE,
            evidence_text="wrong slice",
            evidence_start=0,
            evidence_end=11,
        )
        with self.assertRaises(ValueError):
            bad_ann.validate_against_article(article)


if __name__ == "__main__":
    unittest.main()
