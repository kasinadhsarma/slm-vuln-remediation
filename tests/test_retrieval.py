from pathlib import Path

from slm_avr.retrieval.vector_store import SemanticRetriever

EXEMPLARS_PATH = str(
    Path(__file__).resolve().parents[1]
    / "src" / "slm_avr" / "retrieval" / "exemplars" / "cwe_fixes.json"
)


def test_same_cwe_exemplars_are_preferred():
    retriever = SemanticRetriever(EXEMPLARS_PATH)
    results = retriever.retrieve("CWE-89", "cursor.execute(query)", "sql injection", top_k=2)

    assert len(results) == 2
    assert all(e.cwe_id == "CWE-89" for e in results)


def test_falls_back_to_text_similarity_for_unknown_cwe():
    retriever = SemanticRetriever(EXEMPLARS_PATH)
    results = retriever.retrieve("CWE-9999", "os.system(cmd)", "command injection", top_k=1)

    assert len(results) == 1
