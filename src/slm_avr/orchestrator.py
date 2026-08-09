"""RAVEN-style orchestrator: wires SAST -> slicing -> retrieval -> curator
-> generator -> reviewer into an iterative refinement loop per finding.

Each iteration regenerates a full candidate function from the *original*
source, steered by the Patch Reviewer's structured feedback from the
previous attempt (rather than trying to patch-on-a-patch), which keeps every
attempt independently well-formed and easy to reason about.
"""

from __future__ import annotations

import ast
import builtins
from pathlib import Path

from slm_avr.agents.curator import CuratorAgent
from slm_avr.agents.generator import PatchGenerator
from slm_avr.agents.reviewer import PatchReviewer
from slm_avr.config import Config
from slm_avr.llm.base import LLMProvider
from slm_avr.llm.mock_provider import MockProvider
from slm_avr.llm.ollama_provider import OllamaProvider
from slm_avr.models import (
    FileRemediationReport,
    Finding,
    PatchAttempt,
    RemediationResult,
    Verdict,
)
from slm_avr.retrieval.vector_store import SemanticRetriever
from slm_avr.sast.semgrep_runner import SemgrepRunner
from slm_avr.slicing.slicer import ProgramSlicer

_BUILTIN_NAMES = set(dir(builtins))


def _free_names(function_source: str) -> set[str]:
    """Names read inside the function that aren't parameters, locals, or
    Python builtins -- candidates for cross-file lookup by the Curator Agent."""
    try:
        tree = ast.parse(function_source)
    except SyntaxError:
        return set()

    reads: set[str] = set()
    writes: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            if isinstance(node.ctx, ast.Store):
                writes.add(node.id)
            elif isinstance(node.ctx, ast.Load):
                reads.add(node.id)
        elif isinstance(node, ast.arg):
            writes.add(node.arg)

    return {n for n in (reads - writes) if n not in _BUILTIN_NAMES}


class Orchestrator:
    def __init__(self, config: Config | None = None, llm: LLMProvider | None = None):
        self.config = config or Config.load()
        self.sast = SemgrepRunner(self.config.semgrep_config_paths)
        self.slicer = ProgramSlicer()
        self.retriever = SemanticRetriever(self.config.exemplars_path)
        self.llm = llm or self._build_llm(self.config)
        self.generator = PatchGenerator(self.llm)
        self.reviewer = PatchReviewer(self.sast)

    @staticmethod
    def _build_llm(config: Config) -> LLMProvider:
        if config.llm_provider == "mock":
            return MockProvider()
        return OllamaProvider(
            host=config.ollama.host,
            model=config.ollama.model,
            temperature=config.ollama.temperature,
            timeout=config.ollama.timeout,
        )

    def scan(self, file_path: str) -> list[Finding]:
        return self.sast.scan_file(file_path)

    def remediate_file(
        self, file_path: str, repo_root: str | None = None, test_dir: str | None = None
    ) -> FileRemediationReport:
        """Remediate every finding in a file, applying fixes cumulatively:
        once a finding is resolved, later findings are sliced and generated
        against the already-patched source so multi-vulnerability files
        converge to one fully-repaired file rather than N independent
        single-fix diffs."""
        original_source = Path(file_path).read_text()
        baseline_findings = self.sast.scan_file(file_path)
        curator = CuratorAgent(repo_root or str(Path(file_path).resolve().parent))

        current_source = original_source
        results: list[RemediationResult] = []

        for finding in baseline_findings:
            current_findings = self.sast.rescan_source(current_source, file_path)
            match = next(
                (f for f in current_findings if f.rule_id == finding.rule_id), None
            )
            if match is None:
                # Already resolved as a side effect of an earlier fix in this run.
                results.append(
                    RemediationResult(
                        finding=finding,
                        verdict=Verdict.FIXED,
                        attempts=[],
                        final_patched_source=current_source,
                        exemplars_used=[],
                        cross_file_context=None,
                    )
                )
                continue

            result = self.remediate_finding(
                match, current_source, current_findings, curator, test_dir
            )
            results.append(result)
            if result.success and result.final_patched_source:
                current_source = result.final_patched_source

        return FileRemediationReport(
            file_path=file_path,
            original_source=original_source,
            final_source=current_source,
            results=results,
        )

    def remediate_finding(
        self,
        finding: Finding,
        source: str,
        baseline_findings: list[Finding],
        curator: CuratorAgent,
        test_dir: str | None = None,
    ) -> RemediationResult:
        code_slice = self.slicer.slice(source, finding.path, finding.start_line)
        exemplars = self.retriever.retrieve(
            finding.cwe_id,
            finding.lines,
            finding.message,
            top_k=self.config.top_k_exemplars,
        )
        referenced = _free_names(code_slice.full_function_source)
        cross_ctx = curator.gather(finding.path, code_slice.enclosing_name, referenced)

        attempts: list[PatchAttempt] = []
        feedback: str | None = None

        for iteration in range(1, self.config.max_iterations + 1):
            candidate = self.generator.generate(
                finding, code_slice, exemplars, cross_ctx, reviewer_feedback=feedback
            )
            review = self.reviewer.review(
                finding, baseline_findings, source, code_slice, candidate, test_dir=test_dir
            )

            attempt = PatchAttempt(
                iteration=iteration,
                patched_source=candidate,
                verdict=review.verdict,
                reviewer_feedback=review.feedback,
                remaining_findings=review.remaining_findings,
                new_findings=review.new_findings,
                tests_passed=review.tests_passed,
                tests_output=review.tests_output,
            )
            attempts.append(attempt)

            if review.verdict == Verdict.FIXED:
                return RemediationResult(
                    finding=finding,
                    verdict=Verdict.FIXED,
                    attempts=attempts,
                    final_patched_source=review.patched_full_source,
                    exemplars_used=exemplars,
                    cross_file_context=cross_ctx,
                )

            feedback = review.feedback

        return RemediationResult(
            finding=finding,
            verdict=Verdict.MAX_ITERATIONS_EXCEEDED,
            attempts=attempts,
            final_patched_source=None,
            exemplars_used=exemplars,
            cross_file_context=cross_ctx,
        )
