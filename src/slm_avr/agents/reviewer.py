"""Patch Reviewer agent: the automated, adversarial critic.

Operates as the safeguard described in the report's "compiler-in-the-loop"
section: it never trusts the generator's output. It (1) checks the patch
still parses, (2) re-runs the SAST engine against the patched source to
deterministically confirm the original vulnerability is gone and no new one
was introduced, and (3) optionally runs the repository's test suite in an
isolated sandbox copy to confirm functional behavior wasn't broken. Any
failure produces structured natural-language feedback fed back to the
Patch Generator for the next iteration.
"""

from __future__ import annotations

import ast
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from pyflakes.checker import Checker
from pyflakes.messages import UndefinedName

from slm_avr.models import CodeSlice, Finding, Verdict
from slm_avr.sast.semgrep_runner import SemgrepRunner


@dataclass
class ReviewResult:
    verdict: Verdict
    feedback: str
    remaining_findings: list[Finding]
    new_findings: list[Finding]
    patched_full_source: str | None
    tests_passed: bool | None = None
    tests_output: str = ""


# Common stdlib modules the generator might reach for in a security fix
# (e.g. switching pickle.loads -> json.loads) without re-emitting the import,
# even though it was explicitly told not to repeat existing imports.
_KNOWN_STDLIB_MODULES = {
    "json", "os", "sys", "re", "hashlib", "hmac", "subprocess", "base64",
    "secrets", "uuid", "datetime", "time", "socket", "ssl", "shutil",
    "tempfile", "pickle", "csv", "sqlite3", "itertools", "collections",
    "functools", "pathlib", "logging", "random", "string", "urllib",
}


def _infer_missing_imports(function_source: str, existing_imports: list[str]) -> list[str]:
    """Best-effort detection of stdlib modules referenced as `mod.attr(...)`
    in the candidate patch that aren't already imported at module level --
    catches the common failure mode where a model swaps to e.g. json.loads
    without emitting `import json` despite being told imports already exist."""
    try:
        tree = ast.parse(function_source)
    except SyntaxError:
        return []

    already = set()
    for imp in existing_imports:
        already.update(_module_names_from_import_line(imp))

    bound_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store,)):
            bound_names.add(node.id)
        if isinstance(node, ast.arg):
            bound_names.add(node.arg)

    referenced: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            referenced.add(node.value.id)

    missing = [
        name
        for name in sorted(referenced)
        if name in _KNOWN_STDLIB_MODULES
        and name not in already
        and name not in bound_names
    ]
    return [f"import {name}" for name in missing]


def _module_names_from_import_line(line: str) -> set[str]:
    names: set[str] = set()
    try:
        node = ast.parse(line).body[0]
    except (SyntaxError, IndexError):
        return names
    if isinstance(node, ast.Import):
        for alias in node.names:
            names.add((alias.asname or alias.name).split(".")[0])
    elif isinstance(node, ast.ImportFrom) and node.module:
        names.add(node.module.split(".")[0])
    return names


def apply_function_patch(
    original_source: str, code_slice: CodeSlice, new_function_source: str
) -> str:
    """Splice the generator's rewritten function back into the full file,
    auto-hoisting any stdlib import the patch newly depends on."""
    lines = original_source.splitlines()
    before = lines[: code_slice.func_start_line - 1]
    after = lines[code_slice.func_end_line :]

    missing_imports = _infer_missing_imports(new_function_source, code_slice.imports)
    if missing_imports:
        insert_at = len(before)
        for i, line in enumerate(before):
            stripped = line.strip()
            if stripped.startswith("import ") or stripped.startswith("from "):
                insert_at = i + 1
        before = before[:insert_at] + missing_imports + before[insert_at:]

    patched_lines = before + new_function_source.splitlines() + after
    return "\n".join(patched_lines) + "\n"


class PatchReviewer:
    def __init__(self, sast_runner: SemgrepRunner):
        self.sast = sast_runner

    def review(
        self,
        original_finding: Finding,
        baseline_findings: list[Finding],
        original_source: str,
        code_slice: CodeSlice,
        candidate_function_source: str,
        test_dir: str | None = None,
    ) -> ReviewResult:
        # 1. Syntax check
        try:
            patched_full_source = apply_function_patch(
                original_source, code_slice, candidate_function_source
            )
            patched_tree = ast.parse(patched_full_source)
        except SyntaxError as e:
            return ReviewResult(
                verdict=Verdict.SYNTAX_ERROR,
                feedback=(
                    f"The patched file fails to parse: {e.msg} at line {e.lineno}. "
                    "Re-emit a syntactically valid, complete function."
                ),
                remaining_findings=[],
                new_findings=[],
                patched_full_source=None,
            )

        # 2. Undefined-name check (catches "plausible but incorrect" patches
        # that reference a variable/import that doesn't actually exist --
        # syntactically valid and often passes SAST, but crashes at runtime).
        undefined = [
            m
            for m in Checker(patched_tree, filename=original_finding.path).messages
            if isinstance(m, UndefinedName)
        ]
        if undefined:
            names = ", ".join(sorted({m.message_args[0] for m in undefined}))
            return ReviewResult(
                verdict=Verdict.UNDEFINED_NAME,
                feedback=(
                    f"The patch references undefined name(s): {names}. This would raise a "
                    "NameError at runtime. Either define them, import them properly, or "
                    "rewrite the fix to not depend on names that don't exist in this file."
                ),
                remaining_findings=[],
                new_findings=[],
                patched_full_source=None,
            )

        # 3. SAST re-scan (deterministic ground truth)
        rescan_findings = self.sast.rescan_source(
            patched_full_source, original_finding.path
        )
        remaining = [
            f for f in rescan_findings if f.rule_id == original_finding.rule_id
        ]
        baseline_rule_ids = {f.rule_id for f in baseline_findings}
        new_findings = [
            f
            for f in rescan_findings
            if f.rule_id not in baseline_rule_ids
        ]

        if remaining:
            lines_desc = ", ".join(str(f.start_line) for f in remaining)
            return ReviewResult(
                verdict=Verdict.STILL_VULNERABLE,
                feedback=(
                    f"Static analysis still flags {original_finding.rule_id} "
                    f"({original_finding.cwe}) at line(s) {lines_desc} after your patch. "
                    f"Detail: {remaining[0].message}\n"
                    f"Vulnerable code still present:\n{remaining[0].lines}"
                ),
                remaining_findings=remaining,
                new_findings=new_findings,
                patched_full_source=patched_full_source,
            )

        if new_findings:
            nf = new_findings[0]
            return ReviewResult(
                verdict=Verdict.NEW_VULNERABILITY,
                feedback=(
                    f"Your patch removed the original vulnerability but introduced a new "
                    f"one: {nf.rule_id} ({nf.cwe}) at line {nf.start_line}. "
                    f"Detail: {nf.message}\nOffending code:\n{nf.lines}\n"
                    "Fix this without reintroducing the original vulnerability."
                ),
                remaining_findings=[],
                new_findings=new_findings,
                patched_full_source=patched_full_source,
            )

        # 4. Optional functional test run in an isolated sandbox
        tests_passed = None
        tests_output = ""
        if test_dir:
            tests_passed, tests_output = self._run_tests_sandboxed(
                test_dir, original_finding.path, patched_full_source
            )
            if not tests_passed:
                return ReviewResult(
                    verdict=Verdict.BROKE_TESTS,
                    feedback=(
                        "Static analysis confirms the vulnerability is fixed, but the "
                        "existing test suite now fails:\n"
                        f"{tests_output[-2000:]}\n"
                        "Fix the patch so it both resolves the vulnerability AND keeps "
                        "existing tests passing."
                    ),
                    remaining_findings=[],
                    new_findings=[],
                    patched_full_source=patched_full_source,
                    tests_passed=False,
                    tests_output=tests_output,
                )

        return ReviewResult(
            verdict=Verdict.FIXED,
            feedback="Vulnerability resolved; no new findings; tests pass.",
            remaining_findings=[],
            new_findings=[],
            patched_full_source=patched_full_source,
            tests_passed=tests_passed,
            tests_output=tests_output,
        )

    @staticmethod
    def _run_tests_sandboxed(
        test_dir: str, target_file_path: str, patched_full_source: str
    ) -> tuple[bool, str]:
        test_dir_path = Path(test_dir).resolve()
        target_path = Path(target_file_path).resolve()

        with tempfile.TemporaryDirectory(prefix="slm_avr_sandbox_") as tmp:
            sandbox_root = Path(tmp) / "case"
            shutil.copytree(test_dir_path, sandbox_root)

            rel = target_path.relative_to(test_dir_path)
            (sandbox_root / rel).write_text(patched_full_source)

            proc = subprocess.run(
                ["python3", "-m", "pytest", "-q", str(sandbox_root)],
                capture_output=True,
                text=True,
                timeout=60,
            )
            output = proc.stdout + "\n" + proc.stderr
            return proc.returncode == 0, output
