"""Local, offline Semantic Retriever.

RAVEN-style agentic RAG queries an expansive vector database of historical
vulnerability-fix pairs. This is a locally deployable approximation of that
component: it indexes a curated JSON corpus of CWE fix exemplars with TF-IDF
and cosine similarity (no network calls, no GPU, no external vector DB
service required). Retrieval is CWE-aware: exemplars matching the finding's
CWE category are always preferred over generic textual similarity, mirroring
how real vulnerabilities map onto established CWE patterns rather than being
entirely novel.
"""

from __future__ import annotations

import json
from pathlib import Path

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from slm_avr.models import FixExemplar


class SemanticRetriever:
    def __init__(self, exemplars_path: str):
        self.exemplars_path = exemplars_path
        self._exemplars: list[FixExemplar] = self._load(exemplars_path)
        self._vectorizer = TfidfVectorizer(stop_words="english")
        corpus = [self._doc_text(e) for e in self._exemplars]
        self._matrix = self._vectorizer.fit_transform(corpus) if corpus else None

    @staticmethod
    def _load(path: str) -> list[FixExemplar]:
        raw = json.loads(Path(path).read_text())
        return [
            FixExemplar(
                cwe_id=r["cwe_id"],
                title=r["title"],
                vulnerable_code=r["vulnerable_code"],
                fixed_code=r["fixed_code"],
                explanation=r["explanation"],
            )
            for r in raw
        ]

    @staticmethod
    def _doc_text(e: FixExemplar) -> str:
        return f"{e.title}\n{e.vulnerable_code}\n{e.explanation}"

    def retrieve(
        self, cwe_id: str, query_code: str, query_message: str = "", top_k: int = 3
    ) -> list[FixExemplar]:
        if not self._exemplars or self._matrix is None:
            return []

        query = f"{query_message}\n{query_code}"
        query_vec = self._vectorizer.transform([query])
        sims = cosine_similarity(query_vec, self._matrix)[0]

        scored = list(zip(self._exemplars, sims))

        # CWE-category match is a strong prior signal (paper: "vulnerabilities
        # frequently map to established patterns within CWE categories").
        same_cwe = [(e, s) for e, s in scored if e.cwe_id == cwe_id]
        pool = same_cwe if same_cwe else scored

        pool.sort(key=lambda pair: pair[1], reverse=True)

        results = []
        for exemplar, score in pool[:top_k]:
            results.append(
                FixExemplar(
                    cwe_id=exemplar.cwe_id,
                    title=exemplar.title,
                    vulnerable_code=exemplar.vulnerable_code,
                    fixed_code=exemplar.fixed_code,
                    explanation=exemplar.explanation,
                    score=float(score),
                )
            )
        return results
