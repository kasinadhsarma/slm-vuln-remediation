"""L-AVRBench-style evaluation harness.

Unlike token-matching metrics (BLEU, Exact Match, CodeBLEU), this harness
grades every benchmark case purely on functional execution: the patched
file must (1) no longer trigger the original SAST finding, (2) introduce no
new finding, and (3) pass a real pytest suite containing both a functional
test AND a security/exploit test that specifically demonstrates the
vulnerability class is closed -- so a "plausible but incorrect" patch that
merely looks right cannot score a false positive.

Each case runs against an isolated temp-directory copy of its benchmark
fixture so remediation never mutates the checked-in benchmark files.
"""

from __future__ import annotations

import json
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from slm_avr.config import Config
from slm_avr.models import Verdict
from slm_avr.orchestrator import Orchestrator


@dataclass
class CaseResult:
    name: str
    cwe_id: str
    verdict: Verdict
    iterations_used: int
    findings_total: int
    findings_fixed: int
    detail: str = ""


@dataclass
class EvalSummary:
    cases: list[CaseResult] = field(default_factory=list)
    model: str = ""

    @property
    def total_count(self) -> int:
        return len(self.cases)

    @property
    def fixed_count(self) -> int:
        return sum(1 for c in self.cases if c.verdict == Verdict.FIXED)

    @property
    def success_rate(self) -> float:
        return self.fixed_count / self.total_count if self.total_count else 0.0

    def to_json(self) -> str:
        return json.dumps(
            {
                "model": self.model,
                "total_count": self.total_count,
                "fixed_count": self.fixed_count,
                "success_rate": self.success_rate,
                "cases": [
                    {
                        "name": c.name,
                        "cwe_id": c.cwe_id,
                        "verdict": c.verdict.value,
                        "iterations_used": c.iterations_used,
                        "findings_total": c.findings_total,
                        "findings_fixed": c.findings_fixed,
                        "detail": c.detail,
                    }
                    for c in self.cases
                ],
            },
            indent=2,
        )

    def to_markdown(self) -> str:
        lines = [
            "# slm-avr evaluation report",
            "",
            f"Model: `{self.model}`",
            "",
            f"**Repair success rate: {self.success_rate:.1%}** "
            f"({self.fixed_count}/{self.total_count})",
            "",
            "| Case | CWE | Verdict | Iterations | Findings fixed |",
            "|---|---|---|---|---|",
        ]
        for c in self.cases:
            lines.append(
                f"| {c.name} | {c.cwe_id} | {c.verdict.value} | "
                f"{c.iterations_used} | {c.findings_fixed}/{c.findings_total} |"
            )
        return "\n".join(lines) + "\n"


class EvalHarness:
    def __init__(self, config: Config | None = None, benchmark_dir: str = "benchmark"):
        self.config = config or Config.load()
        self.benchmark_dir = Path(benchmark_dir)
        self.orchestrator = Orchestrator(self.config)

    def discover_cases(self) -> list[Path]:
        return sorted(
            p.parent for p in self.benchmark_dir.glob("*/meta.json")
        )

    def run(self) -> EvalSummary:
        cases: list[CaseResult] = []
        for case_dir in self.discover_cases():
            cases.append(self._run_case(case_dir))
        return EvalSummary(cases=cases, model=self.config.ollama.model)

    def _run_case(self, case_dir: Path) -> CaseResult:
        meta = json.loads((case_dir / "meta.json").read_text())
        name = meta["name"]
        cwe_id = meta["cwe_id"]

        with tempfile.TemporaryDirectory(prefix="slm_avr_eval_") as tmp:
            sandbox = Path(tmp) / "case"
            shutil.copytree(case_dir, sandbox)
            sandbox_target = sandbox / meta["target_file"]

            report = self.orchestrator.remediate_file(
                str(sandbox_target), repo_root=str(sandbox), test_dir=str(sandbox)
            )

            if report.total_count == 0:
                return CaseResult(
                    name=name,
                    cwe_id=cwe_id,
                    verdict=Verdict.NO_CHANGE,
                    iterations_used=0,
                    findings_total=0,
                    findings_fixed=0,
                    detail="SAST reported no findings for this case's target file",
                )

            iterations_used = sum(r.iterations_used for r in report.results)
            findings_fixed = sum(1 for r in report.results if r.success)
            all_fixed = findings_fixed == report.total_count

            if all_fixed:
                verdict = Verdict.FIXED
                detail = "all findings resolved; tests pass"
            else:
                first_failure = next(r for r in report.results if not r.success)
                verdict = first_failure.verdict
                last_attempt = (
                    first_failure.attempts[-1] if first_failure.attempts else None
                )
                detail = last_attempt.reviewer_feedback if last_attempt else ""

            return CaseResult(
                name=name,
                cwe_id=cwe_id,
                verdict=verdict,
                iterations_used=iterations_used,
                findings_total=report.total_count,
                findings_fixed=findings_fixed,
                detail=detail,
            )
