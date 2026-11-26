"""Generates TA-09's harder synthetic study-labelled retrieval set (`WP-07`, `bench/ta09_hard/`).

Standard library only. Every compound, condition, population and result is invented; nothing here
is medical information. Unlike the small 52-report VS-1a `bench/ta09` set, this set constructs
multi-study, distractor-heavy candidate pools (>55 FTS5 hits per query across shared-term background
mentions, reference arms, multi-report studies, and abbreviated-condition misses) so both the
`@10` (`nDCG@10`) and `@50` (`study-level recall@50`) cutoffs genuinely bind (`< 1.0`).

Usage: python bench/ta09_hard/generate_set.py <output directory>
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

CONDITIONS = [
    ("glimmer syndrome", "GS", "glimmer"),
    ("ember fatigue", "EF", "ember"),
    ("hollow cough", "HC", "cough"),
    ("marble rash", "MR", "rash"),
    ("quiet tremor", "QT", "tremor"),
    ("amber gait", "AG", "gait"),
]

INTERVENTIONS = [
    "veltrixamine",
    "orbalin",
    "quenzil",
    "tessarine",
    "calvoride",
    "nimbutrel",
]

POPULATIONS = ("adults", "children", "elderly")

DESCRIPTION = (
    "Invented harder engineering fixture for TA-09 (`WP-07`). Compounds, conditions, populations "
    "and results do not exist. Not medical information."
)


def pick(seed: str, n: int) -> int:
    return int(hashlib.sha256(seed.encode("utf-8")).hexdigest(), 16) % n


def make_report(
    doc_id: str,
    study_id: str,
    title: str,
    opening: str,
    finding: str,
    population: str,
    condition: str,
    intervention: str,
    benefit: bool,
) -> dict:
    return {
        "doc_id": doc_id,
        "study_id": study_id,
        "title": title,
        "text": f"{opening} {finding}",
        "population": population,
        "condition": condition,
        "intervention": intervention,
        "finding": finding,
        "direction": "benefit" if benefit else "no_benefit",
        "publication_state": "CURRENT",
        "rights": "synthetic_owned",
    }


def build() -> tuple[dict, dict]:
    studies = []
    documents = []

    # 1. Core primary studies across all (condition, intervention, population) triples, with 2
    # independent trials per (condition, intervention, "adults") and 1 trial for selected
    # pediatric/elderly strata.
    for c_idx, cond_tuple in enumerate(CONDITIONS):
        condition, abbrev, score = cond_tuple
        for i_idx, intervention in enumerate(INTERVENTIONS):
            for rep_trial in range(2):
                for pop in POPULATIONS:
                    key = f"core|{condition}|{intervention}|{pop}|{rep_trial}"
                    if pop != "adults" and (rep_trial == 1 or pick(key, 2) == 1):
                        continue
                    study_id = "study-h-" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:10]
                    benefit = pick(key + "|dir", 3) != 0
                    studies.append(
                        {
                            "study_id": study_id,
                            "condition": cond_tuple,
                            "intervention": intervention,
                            "population": pop,
                            "benefit": benefit,
                        }
                    )
                    weeks = 8 + 4 * pick(study_id + "|w", 4)
                    pts = 2 + pick(study_id + "|p", 7)
                    finding = (
                        f"The {score} score improved by {pts} points compared with placebo at {weeks} weeks."
                        if benefit
                        else f"The {score} score did not improve compared with placebo at {weeks} weeks."
                    )
                    # Abbreviate condition on ~25% of secondary trials so lexical recall@50 < 1.0:
                    use_abbrev = rep_trial == 1 and pick(study_id + "|abbr", 4) == 0
                    named_cond = abbrev if use_abbrev else condition
                    opening = (
                        f"{pop.capitalize()} with synthetic {named_cond} received {intervention} "
                        f"in a randomized protocol."
                    )
                    title = (
                        f"Trial of {intervention} in {pop} with synthetic {named_cond}"
                        if not use_abbrev
                        else f"Protocol {abbrev} study of {intervention} in {pop}"
                    )
                    documents.append(
                        make_report(
                            f"{study_id}-r0",
                            study_id,
                            title,
                            opening,
                            finding,
                            pop,
                            condition,
                            intervention,
                            benefit,
                        )
                    )
                    if pick(study_id + "|fu", 3) == 0 and not use_abbrev:
                        fu_weeks = weeks + 12
                        fu_finding = (
                            f"The {score} score improved by {pts} points compared with placebo at {fu_weeks} weeks."
                            if benefit
                            else f"The {score} score did not improve compared with placebo at {fu_weeks} weeks."
                        )
                        fu_open = (
                            f"Follow-up cohort of {pop} with synthetic {condition} treated with "
                            f"{intervention}."
                        )
                        documents.append(
                            make_report(
                                f"{study_id}-r1",
                                study_id,
                                f"Extended follow-up of {intervention} for synthetic {condition}",
                                fu_open,
                                fu_finding,
                                pop,
                                condition,
                                intervention,
                                benefit,
                            )
                        )

    # 2. Shared-term distractors (grade 0 for other conditions/interventions): each distractor
    # evaluates ONE true (condition_a, intervention_a) while discussing background literature across
    # two other conditions and two other interventions in its introduction sentence, creating >50
    # FTS5 candidate hits per query so both @10 and @50 cutoffs genuinely bind!
    for d_idx in range(180):
        c_true = CONDITIONS[d_idx % len(CONDITIONS)]
        i_true = INTERVENTIONS[(d_idx // len(CONDITIONS)) % len(INTERVENTIONS)]
        c_noise_1 = CONDITIONS[(d_idx + 1) % len(CONDITIONS)][0]
        c_noise_2 = CONDITIONS[(d_idx + 2) % len(CONDITIONS)][0]
        i_noise_1 = INTERVENTIONS[(d_idx + 1) % len(INTERVENTIONS)]
        i_noise_2 = INTERVENTIONS[(d_idx + 3) % len(INTERVENTIONS)]
        key = f"distractor|{d_idx}"
        study_id = "study-d-" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:10]
        benefit = pick(key + "|b", 2) == 0
        pts = 2 + (d_idx % 5)
        score = c_true[2]
        finding = (
            f"The {score} score improved by {pts} points compared with placebo at 16 weeks."
            if benefit
            else f"The {score} score did not improve compared with placebo at 16 weeks."
        )
        # Mention noise terms twice in title/background so some distractors outscore sparse true
        # reports under raw BM25, making nDCG@10 and recall@50 non-trivial!
        title = (
            f"Comparative background of {i_noise_1} and {i_noise_2} across {c_noise_1} and "
            f"{c_noise_2} versus {i_true}"
        )
        opening = (
            f"Prior work examined {i_noise_1} and {i_noise_2} in {c_noise_1} and {c_noise_2}; "
            f"here adults with synthetic {c_true[0]} received {i_true} daily."
        )
        studies.append(
            {
                "study_id": study_id,
                "condition": c_true,
                "intervention": i_true,
                "population": "adults",
                "benefit": benefit,
            }
        )
        documents.append(
            make_report(
                f"aaa-distractor-{d_idx:03d}",
                study_id,
                title,
                opening,
                finding,
                "adults",
                c_true[0],
                i_true,
                benefit,
            )
        )

    documents.sort(key=lambda d: d["doc_id"])

    queries = []
    for condition, _, _ in CONDITIONS:
        for intervention in INTERVENTIONS:
            for pop in ("adults", "children"):
                grades = {}
                for study in studies:
                    if study["condition"][0] == condition and study["intervention"] == intervention:
                        grades[study["study_id"]] = 2 if study["population"] == pop else 1
                if not any(g == 2 for g in grades.values()):
                    continue
                queries.append(
                    {
                        "query_id": f"qh{len(queries) + 1:02d}",
                        "question": f"Does {intervention} help {pop} with {condition}?",
                        "qrels": dict(sorted(grades.items())),
                    }
                )

    corpus = {
        "description": DESCRIPTION,
        "validity_epoch": 1,
        "rights_grant_version": "synthetic-owned-ta09-hard-1",
        "documents": documents,
    }
    return corpus, {"description": DESCRIPTION, "queries": queries}


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    out = Path(sys.argv[1])
    out.mkdir(parents=True, exist_ok=True)
    corpus, queries = build()
    for name, value in (("ta09_hard_corpus.json", corpus), ("ta09_hard_queries.json", queries)):
        data = (json.dumps(value, indent=2, ensure_ascii=True) + "\n").encode("utf-8")
        (out / name).write_bytes(data)
        print(f"{name} sha256 {hashlib.sha256(data).hexdigest()}")
    print(f"{len(corpus['documents'])} documents, {len(queries['queries'])} queries")
    return 0


if __name__ == "__main__":
    sys.exit(main())
