"""Generates TA-09's synthetic, study-labelled retrieval set for VS-1a. Standard library only.

Every compound, condition, population and result is invented. Nothing here is medical
information. The output is deterministic: the same script always writes the same bytes, and
`REGISTRATION.md` pins their digests before any measurement.

Usage: python bench/ta09/generate_set.py <output directory>
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
    ("lumen fever", "LF", "fever"),
    ("drift palsy", "DP", "palsy"),
]
INTERVENTIONS = [
    "veltrixamine",
    "orbalin",
    "quenzil",
    "tessarine",
    "calvoride",
    "nimbutrel",
    "pexadone",
    "sorvane",
]
DESCRIPTION = (
    "Invented engineering fixture for TA-09. Compounds, conditions, populations and results do not "
    "exist. Not medical information."
)


def pick(seed: str, n: int) -> int:
    """A stable choice from `n` options, from text rather than a random generator."""
    return int(hashlib.sha256(seed.encode("utf-8")).hexdigest(), 16) % n


def report(study: dict, index: int, variant: str) -> dict:
    condition, abbreviation, score = study["condition"]
    intervention = study["intervention"]
    population = study["population"]
    benefit = study["benefit"]
    named = abbreviation if variant == "abbreviated" else condition
    weeks = 8 + 4 * pick(study["study_id"], 5) + 12 * index
    points = 3 + pick(study["study_id"] + "points", 9)
    if benefit:
        finding = f"The {score} score improved by {points} points compared with placebo at {weeks} weeks."
    else:
        finding = f"The {score} score did not improve compared with placebo at {weeks} weeks."
    opening = {
        "plain": f"{population.capitalize()} with synthetic {named} received {intervention} daily.",
        "abbreviated": f"{population.capitalize()} with synthetic {named} received {intervention} daily.",
        "follow-up": f"This follow-up reports the same {population} with synthetic {named} on {intervention} daily.",
        "comparator": (
            f"{population.capitalize()} with synthetic {named} received {intervention} daily, "
            f"and a reference arm received {study['reference']}."
        ),
    }[variant]
    title_prefix = "Follow-up report of " if variant == "follow-up" else ""
    return {
        "doc_id": f"{study['study_id']}-r{index}",
        "study_id": study["study_id"],
        "title": f"{title_prefix}{intervention.capitalize()} in {population} with synthetic {named}",
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
    for c, condition in enumerate(CONDITIONS):
        for k in range(3):
            intervention = INTERVENTIONS[(c + 3 * k) % len(INTERVENTIONS)]
            for population in ("adults", "children"):
                key = f"{condition[0]}|{intervention}|{population}"
                if population == "children" and pick(key, 3) != 0:
                    continue
                studies.append(
                    {
                        "study_id": "study-" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:10],
                        "condition": condition,
                        "intervention": intervention,
                        "population": population,
                        "benefit": pick(key + "benefit", 3) != 0,
                        "reference": INTERVENTIONS[(c + 3 * k + 1) % len(INTERVENTIONS)],
                    }
                )
    documents = []
    for study in studies:
        variants = ["plain", "abbreviated", "comparator"]
        first = variants[pick(study["study_id"] + "variant", len(variants))]
        documents.append(report(study, 0, first))
        if pick(study["study_id"] + "follow-up", 2) == 0:
            documents.append(report(study, 1, "follow-up"))

    queries = []
    for c, (condition, _, _) in enumerate(CONDITIONS):
        for k in range(3):
            intervention = INTERVENTIONS[(c + 3 * k) % len(INTERVENTIONS)]
            for population in ("adults", "children"):
                grades = {}
                for study in studies:
                    if study["condition"][0] == condition and study["intervention"] == intervention:
                        grades[study["study_id"]] = 2 if study["population"] == population else 1
                if not any(grade == 2 for grade in grades.values()):
                    continue
                queries.append(
                    {
                        "query_id": f"q{len(queries) + 1:02d}",
                        "question": f"Does {intervention} help {population} with {condition}?",
                        "qrels": dict(sorted(grades.items())),
                    }
                )

    corpus = {
        "description": DESCRIPTION,
        "validity_epoch": 1,
        "rights_grant_version": "synthetic-owned-ta09-1",
        "documents": documents,
    }
    return corpus, {"description": DESCRIPTION, "queries": queries}


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    out = Path(sys.argv[1])
    corpus, queries = build()
    for name, value in (("ta09_corpus.json", corpus), ("ta09_queries.json", queries)):
        data = (json.dumps(value, indent=2, ensure_ascii=True) + "\n").encode("utf-8")
        (out / name).write_bytes(data)
        print(f"{name} sha256 {hashlib.sha256(data).hexdigest()}")
    print(f"{len(corpus['documents'])} documents, {len(queries['queries'])} queries")
    return 0


if __name__ == "__main__":
    sys.exit(main())
