#!/usr/bin/env python3
"""Benchmark-only SciFact dataset and prediction representations (ADM-0030 / T27).

Adapted from allenai/scifact @ 68b98a56d93e0f9da0d2aab4e6c3294699a0f72e
(`verisci/evaluate/lib/data.py`, Apache-2.0; see `bench/scifact/LICENSE.md` and
`bench/scifact/PROVENANCE.md`) to use Python standard library only (`json`,
`dataclasses`, `enum`) with explicit UTF-8 context managers and zero external
runtime dependencies. Never imported or shipped by product binaries.
"""
from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Dict, Iterable, List, Tuple


def load_jsonl(fname: str | Path) -> list[dict]:
    path = Path(fname)
    with path.open("r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


class Label(Enum):
    SUPPORTS = 2
    NEI = 1
    REFUTES = 0


def make_label(label_str: str, allow_nei: bool = True) -> Label:
    lookup = {
        "SUPPORT": Label.SUPPORTS,
        "SUPPORTS": Label.SUPPORTS,
        "NOT_ENOUGH_INFO": Label.NEI,
        "CONTRADICT": Label.REFUTES,
        "REFUTES": Label.REFUTES,
    }
    if label_str not in lookup:
        raise ValueError(f"Unknown SciFact label: {label_str}")
    res = lookup[label_str]
    if not allow_nei and res is Label.NEI:
        raise ValueError("NEI predictions are not allowed in SciFact rationale predictions.")
    return res


def _validate_sentence_indices(indices: Iterable[int]) -> List[int]:
    out: List[int] = []
    for raw_ix in indices:
        if isinstance(raw_ix, bool) or not isinstance(raw_ix, int) or raw_ix < 0:
            raise ValueError(f"Sentence rationale index must be a non-negative int, got {raw_ix!r}")
        out.append(raw_ix)
    return out


@dataclass(frozen=True)
class Document:
    id: int
    title: str
    sentences: Tuple[str, ...]

    @classmethod
    def from_dict(cls, entry: dict) -> "Document":
        return cls(
            id=int(entry["doc_id"]),
            title=str(entry["title"]),
            sentences=tuple(str(s) for s in entry["abstract"]),
        )


@dataclass(frozen=True)
class Corpus:
    documents: Tuple[Document, ...]

    def __len__(self) -> int:
        return len(self.documents)

    def get_document(self, doc_id: int) -> Document:
        matches = [doc for doc in self.documents if doc.id == int(doc_id)]
        if len(matches) != 1:
            raise KeyError(f"Expected exactly 1 document for doc_id={doc_id}, got {len(matches)}")
        return matches[0]

    @classmethod
    def from_records(cls, entries: Iterable[dict]) -> "Corpus":
        return cls(tuple(Document.from_dict(entry) for entry in entries))

    @classmethod
    def from_jsonl(cls, corpus_file: str | Path) -> "Corpus":
        return cls.from_records(load_jsonl(corpus_file))


@dataclass(frozen=True)
class EvidenceAbstract:
    id: int
    label: Label
    rationales: List[List[int]]


@dataclass
class Claim:
    id: int
    claim: str
    evidence: Dict[int, EvidenceAbstract]
    cited_docs: List[Document]

    def __post_init__(self) -> None:
        self.evidence = self._format_evidence(self.evidence)

    @staticmethod
    def _format_evidence(evidence_dict: dict) -> Dict[int, EvidenceAbstract]:
        formatted: Dict[int, EvidenceAbstract] = {}
        for raw_doc_id, rationales in evidence_dict.items():
            if isinstance(rationales, EvidenceAbstract):
                formatted[int(raw_doc_id)] = rationales
                continue
            if not rationales:
                raise ValueError("Gold evidence entry cannot have an empty rationales list.")
            doc_id = int(raw_doc_id)
            labels = [r["label"] for r in rationales]
            if len(set(labels)) != 1:
                raise ValueError(
                    "Each SciFact claim/abstract pair must carry exactly one consistent label."
                )
            label = make_label(labels[0], allow_nei=True)
            rationale_sents = [_validate_sentence_indices(r["sentences"]) for r in rationales]
            if any(len(rs) == 0 for rs in rationale_sents):
                raise ValueError("Each gold rationale set must contain at least one sentence index.")
            formatted[doc_id] = EvidenceAbstract(doc_id, label, rationale_sents)
        return formatted


class GoldDataset:
    def __init__(self, corpus: Corpus, claim_records: Iterable[dict]) -> None:
        self.corpus = corpus
        self.claims = self._build_claims(claim_records)

    @classmethod
    def from_jsonl(cls, corpus_file: str | Path, data_file: str | Path) -> "GoldDataset":
        return cls(Corpus.from_jsonl(corpus_file), load_jsonl(data_file))

    def _build_claims(self, examples: Iterable[dict]) -> List[Claim]:
        built: List[Claim] = []
        seen_ids: set[int] = set()
        for raw in examples:
            entry = copy.deepcopy(raw)
            cid = int(entry["id"])
            if cid in seen_ids:
                raise ValueError(f"Duplicate gold claim id={cid}")
            seen_ids.add(cid)
            cited_ids = entry.pop("cited_doc_ids", [])
            cited_docs = [self.corpus.get_document(int(doc_id)) for doc_id in cited_ids]
            built.append(
                Claim(
                    id=cid,
                    claim=str(entry["claim"]),
                    evidence=entry.get("evidence", {}),
                    cited_docs=cited_docs,
                )
            )
        return sorted(built, key=lambda c: c.id)

    def get_claim(self, claim_id: int) -> Claim:
        matches = [c for c in self.claims if c.id == int(claim_id)]
        if len(matches) != 1:
            raise KeyError(f"Expected 1 claim for id={claim_id}, got {len(matches)}")
        return matches[0]


@dataclass(frozen=True)
class PredictedAbstract:
    abstract_id: int
    label: Label
    rationale: List[int]


@dataclass(frozen=True)
class ClaimPredictions:
    claim_id: int
    predictions: Dict[int, PredictedAbstract]
    gold: Claim


class PredictedDataset:
    def __init__(self, gold: GoldDataset, prediction_records: Iterable[dict]) -> None:
        self.gold = gold
        self.predictions: List[ClaimPredictions] = []
        self.by_claim_id: Dict[int, ClaimPredictions] = {}
        for pred in prediction_records:
            parsed = self._parse_prediction(pred)
            if parsed.claim_id in self.by_claim_id:
                raise ValueError(f"Duplicate predicted claim id={parsed.claim_id}")
            self.by_claim_id[parsed.claim_id] = parsed
            self.predictions.append(parsed)

    @classmethod
    def from_jsonl(cls, gold: GoldDataset, prediction_file: str | Path) -> "PredictedDataset":
        return cls(gold, load_jsonl(prediction_file))

    def __iter__(self):
        return iter(self.predictions)

    def _parse_prediction(self, pred_dict: dict) -> ClaimPredictions:
        claim_id = int(pred_dict["id"])
        gold_claim = self.gold.get_claim(claim_id)
        parsed: Dict[int, PredictedAbstract] = {}
        for key, item in pred_dict.get("evidence", {}).items():
            doc_id = int(key)
            if doc_id in parsed:
                raise ValueError(f"Duplicate abstract prediction doc_id={doc_id} on claim {claim_id}")
            raw_indices = _validate_sentence_indices(item["sentences"])
            deduped_indices = list(dict.fromkeys(raw_indices))
            parsed[doc_id] = PredictedAbstract(
                abstract_id=doc_id,
                label=make_label(item["label"], allow_nei=False),
                rationale=deduped_indices,
            )
        return ClaimPredictions(claim_id=claim_id, predictions=parsed, gold=gold_claim)
