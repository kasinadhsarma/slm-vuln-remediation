"""A tiny, dependency-free TF-IDF + cosine similarity implementation.

Swapped in for scikit-learn: our exemplar corpus is a few dozen short
documents at most, well within the range where a pure-Python
implementation is both fast enough and exact enough -- and it saves
~255MB of numpy/scipy/scikit-learn from the deployment bundle, which
matters when the SAST engine (semgrep) already accounts for the bulk of
a size-constrained deployment (e.g. Vercel's 500MB function limit).
"""

from __future__ import annotations

import math
import re

_TOKEN_RE = re.compile(r"[a-zA-Z_][a-zA-Z0-9_]*")

# A short, standard English stopword list -- approximates sklearn's
# built-in "english" list closely enough for reranking short code+prose
# documents; exact parity with sklearn's list isn't required here.
_STOPWORDS = frozenset(
    """
    a an the this that these those is are was were be been being
    to of in on for with as at by from into over under above below
    and or but if then else not no nor so than too very
    it its it's they them their there here
    do does did doing have has had having
    i you he she we our your his her
    """.split()
)


def tokenize(text: str) -> list[str]:
    return [
        t.lower()
        for t in _TOKEN_RE.findall(text)
        if t.lower() not in _STOPWORDS and len(t) > 1
    ]


class TfidfCorpus:
    """Fit once on a corpus, then score arbitrary query strings against it."""

    def __init__(self, documents: list[str]):
        self._doc_term_counts: list[dict[str, int]] = [
            _term_counts(tokenize(doc)) for doc in documents
        ]
        self._idf = _compute_idf(self._doc_term_counts)
        self._doc_vectors = [
            _normalize(_tfidf_vector(counts, self._idf))
            for counts in self._doc_term_counts
        ]

    def similarities(self, query: str) -> list[float]:
        """Cosine similarity between the query and every fitted document,
        in original document order."""
        if not self._doc_vectors:
            return []
        query_vec = _normalize(_tfidf_vector(_term_counts(tokenize(query)), self._idf))
        return [_dot(query_vec, doc_vec) for doc_vec in self._doc_vectors]


def _term_counts(tokens: list[str]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for t in tokens:
        counts[t] = counts.get(t, 0) + 1
    return counts


def _compute_idf(doc_term_counts: list[dict[str, int]]) -> dict[str, float]:
    n_docs = len(doc_term_counts)
    doc_freq: dict[str, int] = {}
    for counts in doc_term_counts:
        for term in counts:
            doc_freq[term] = doc_freq.get(term, 0) + 1

    # Smoothed IDF, matching sklearn's default (smooth_idf=True):
    # idf(t) = ln((1 + n) / (1 + df(t))) + 1
    return {
        term: math.log((1 + n_docs) / (1 + df)) + 1.0
        for term, df in doc_freq.items()
    }


def _tfidf_vector(term_counts: dict[str, int], idf: dict[str, float]) -> dict[str, float]:
    return {
        term: count * idf[term]
        for term, count in term_counts.items()
        if term in idf
    }


def _normalize(vector: dict[str, float]) -> dict[str, float]:
    norm = math.sqrt(sum(v * v for v in vector.values()))
    if norm == 0:
        return vector
    return {k: v / norm for k, v in vector.items()}


def _dot(a: dict[str, float], b: dict[str, float]) -> float:
    # Iterate the shorter dict for efficiency; correctness doesn't depend on it.
    if len(a) > len(b):
        a, b = b, a
    return sum(v * b[k] for k, v in a.items() if k in b)
