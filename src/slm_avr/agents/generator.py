"""Patch Generator agent.

Synthesizes a candidate patch by combining every context source the earlier
pipeline stages produced: the SAST finding (deterministic ground truth about
*what* is wrong and where), the program slice (focused *relevant* code,
reducing attention dilution), retrieved historical fix exemplars (how humans
have solved isomorphic CWEs before), and cross-file context from the Curator
Agent (repo-wide grounding). On refinement iterations it also receives the
Patch Reviewer's structured feedback from the previous attempt.
"""

from __future__ import annotations

import re

from slm_avr.llm.base import LLMProvider
from slm_avr.models import CodeSlice, CrossFileContext, Finding, FixExemplar

SYSTEM_PROMPT = """You are the Patch Generator agent in an autonomous, static-analysis-guided \
code vulnerability remediation pipeline. A deterministic static analyzer has already located an \
exact vulnerability; your only job is to rewrite the vulnerable function so the flaw is gone.

Rules:
- Fix ONLY the specific vulnerability described. Do not refactor unrelated code, rename things, \
or change the function's public behavior/signature for callers.
- If the vulnerable code is inside a function, preserve its exact name and parameter list.
- Do NOT repeat the module's `import` statements in your answer -- they already exist at the top \
of the file and will be added automatically if you need a new one.
- Your output must be a drop-in replacement for EXACTLY the code block shown under "Code to \
patch" below (a function, or a single module-level statement) -- nothing more, nothing less. Do \
not include any other function or statement from the file.
- Output ONLY the corrected code, nothing else: no explanations, no markdown prose, no diff \
syntax. Wrap it in a single ```python fenced code block and output nothing outside that block.
"""


class PatchGenerator:
    def __init__(self, llm: LLMProvider):
        self.llm = llm

    def generate(
        self,
        finding: Finding,
        code_slice: CodeSlice,
        exemplars: list[FixExemplar],
        cross_file_context: CrossFileContext | None,
        reviewer_feedback: str | None = None,
    ) -> str:
        prompt = self._build_prompt(
            finding, code_slice, exemplars, cross_file_context, reviewer_feedback
        )
        completion = self.llm.generate(SYSTEM_PROMPT, prompt)
        return self._extract_code(completion)

    @staticmethod
    def _build_prompt(
        finding: Finding,
        code_slice: CodeSlice,
        exemplars: list[FixExemplar],
        cross_file_context: CrossFileContext | None,
        reviewer_feedback: str | None,
    ) -> str:
        parts: list[str] = []

        parts.append(f"## Vulnerability (from static analysis)\nCWE: {finding.cwe}")
        parts.append(f"Rule: {finding.rule_id}")
        parts.append(f"Location: {finding.path}, line {finding.start_line}")
        parts.append(f"Finding detail: {finding.message}")
        parts.append(f"Vulnerable statement:\n```python\n{finding.lines}\n```")

        parts.append(
            "\n## Relevant code slice (dependency chain leading to the vulnerable "
            "statement -- irrelevant statements omitted)"
        )
        parts.append(f"```python\n{code_slice.slice_source}\n```")

        parts.append(
            "\n## Code to patch (rewrite exactly this block in your answer, nothing more)"
        )
        if code_slice.imports:
            parts.append("Relevant module-level imports already available:")
            parts.append("```python\n" + "\n".join(code_slice.imports) + "\n```")
        parts.append(f"```python\n{code_slice.full_function_source}\n```")

        if exemplars:
            parts.append(
                "\n## Historical fix exemplars (how this CWE class has been "
                "correctly remediated before -- adapt the pattern, don't copy verbatim)"
            )
            for i, ex in enumerate(exemplars, 1):
                parts.append(
                    f"### Exemplar {i}: {ex.title} ({ex.cwe_id})\n"
                    f"Vulnerable:\n```python\n{ex.vulnerable_code}\n```\n"
                    f"Fixed:\n```python\n{ex.fixed_code}\n```\n"
                    f"Why: {ex.explanation}"
                )

        if cross_file_context and any(
            [
                cross_file_context.callers,
                cross_file_context.callees,
                cross_file_context.related_definitions,
            ]
        ):
            parts.append("\n## Cross-file repository context")
            if cross_file_context.callers:
                parts.append(
                    "Callers of this function (don't break their expectations):\n- "
                    + "\n- ".join(cross_file_context.callers)
                )
            if cross_file_context.related_definitions:
                parts.append(
                    "Related definitions elsewhere in the repo you may reuse "
                    "(e.g. an allowed base path, an allowlist):\n- "
                    + "\n- ".join(cross_file_context.related_definitions)
                )
            if cross_file_context.callees:
                parts.append(
                    "Functions referenced here that are defined elsewhere:\n- "
                    + "\n- ".join(cross_file_context.callees)
                )

        if reviewer_feedback:
            parts.append(
                "\n## Your previous patch attempt was rejected\n"
                f"Reviewer feedback:\n{reviewer_feedback}\n"
                "Produce a corrected patch that addresses this specific feedback."
            )

        parts.append(
            "\nRespond with ONLY the corrected function in one ```python fenced block."
        )
        return "\n".join(parts)

    @staticmethod
    def _extract_code(completion: str) -> str:
        match = re.search(r"```(?:python)?\s*\n(.*?)```", completion, re.DOTALL)
        code = match.group(1).rstrip() if match else completion.strip()
        return PatchGenerator._strip_leading_imports(code)

    @staticmethod
    def _strip_leading_imports(code: str) -> str:
        """Models often re-emit the module's existing imports out of habit
        even when told not to. Drop any contiguous import/blank lines at the
        very top of the block so they aren't spliced into the middle of the
        file by apply_function_patch."""
        lines = code.split("\n")
        i = 0
        while i < len(lines):
            stripped = lines[i].strip()
            if stripped == "" or stripped.startswith("import ") or stripped.startswith("from "):
                i += 1
                continue
            break
        remainder = "\n".join(lines[i:]).strip()
        return remainder if remainder else code
