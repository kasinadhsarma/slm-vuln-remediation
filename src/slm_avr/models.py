"""Shared data models passed between pipeline stages."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


@dataclass
class Finding:
    """A single vulnerability reported by the SAST engine."""

    rule_id: str
    cwe: str
    message: str
    path: str
    start_line: int
    end_line: int
    start_col: int
    end_col: int
    severity: str
    lines: str

    @property
    def cwe_id(self) -> str:
        """Short form, e.g. 'CWE-89' extracted from a longer description."""
        return self.cwe.split(":")[0].strip() if self.cwe else "UNKNOWN"


@dataclass
class CodeSlice:
    """The reduced context handed to the SLM: the vulnerable statement plus
    only the surrounding code it actually depends on."""

    file_path: str
    enclosing_name: str
    slice_source: str
    imports: list[str] = field(default_factory=list)
    included_lines: list[int] = field(default_factory=list)
    vulnerable_line: int = 0
    full_function_source: str = ""
    func_start_line: int = 0
    func_end_line: int = 0


@dataclass
class FixExemplar:
    """A historical vulnerability-fix pair used for retrieval augmentation."""

    cwe_id: str
    title: str
    vulnerable_code: str
    fixed_code: str
    explanation: str
    score: float = 0.0


@dataclass
class CrossFileContext:
    """Repository-wide context gathered by the Curator Agent."""

    callers: list[str] = field(default_factory=list)
    callees: list[str] = field(default_factory=list)
    related_definitions: list[str] = field(default_factory=list)
    imported_by: list[str] = field(default_factory=list)


class Verdict(str, Enum):
    FIXED = "fixed"
    STILL_VULNERABLE = "still_vulnerable"
    NEW_VULNERABILITY = "new_vulnerability"
    BROKE_TESTS = "broke_tests"
    SYNTAX_ERROR = "syntax_error"
    UNDEFINED_NAME = "undefined_name"
    MAX_ITERATIONS_EXCEEDED = "max_iterations_exceeded"
    NO_CHANGE = "no_change"


@dataclass
class PatchAttempt:
    """One round of the generator -> reviewer loop."""

    iteration: int
    patched_source: str
    verdict: Verdict
    reviewer_feedback: str
    remaining_findings: list[Finding] = field(default_factory=list)
    new_findings: list[Finding] = field(default_factory=list)
    tests_passed: bool | None = None
    tests_output: str = ""


@dataclass
class RemediationResult:
    """Final output of the orchestrator for a single finding."""

    finding: Finding
    verdict: Verdict
    attempts: list[PatchAttempt] = field(default_factory=list)
    final_patched_source: str | None = None
    exemplars_used: list[FixExemplar] = field(default_factory=list)
    cross_file_context: CrossFileContext | None = None

    @property
    def iterations_used(self) -> int:
        return len(self.attempts)

    @property
    def success(self) -> bool:
        return self.verdict == Verdict.FIXED


@dataclass
class FileRemediationReport:
    """Cumulative result of remediating every finding in one file."""

    file_path: str
    original_source: str
    final_source: str
    results: list[RemediationResult] = field(default_factory=list)

    @property
    def fixed_count(self) -> int:
        return sum(1 for r in self.results if r.success)

    @property
    def total_count(self) -> int:
        return len(self.results)
