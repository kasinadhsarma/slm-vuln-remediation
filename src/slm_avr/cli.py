"""slm-avr command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table

from slm_avr.config import Config
from slm_avr.models import Verdict
from slm_avr.orchestrator import Orchestrator

console = Console()

_VERDICT_STYLE = {
    Verdict.FIXED: "bold green",
    Verdict.STILL_VULNERABLE: "bold red",
    Verdict.NEW_VULNERABILITY: "bold red",
    Verdict.BROKE_TESTS: "bold yellow",
    Verdict.SYNTAX_ERROR: "bold red",
    Verdict.UNDEFINED_NAME: "bold red",
    Verdict.MAX_ITERATIONS_EXCEEDED: "bold yellow",
    Verdict.NO_CHANGE: "dim",
}


def cmd_scan(args: argparse.Namespace) -> int:
    config = Config.load(args.config)
    orch = Orchestrator(config)
    findings = orch.scan(args.path)

    if not findings:
        console.print(f"[green]No findings in {args.path}[/green]")
        return 0

    table = Table(title=f"Findings in {args.path}")
    table.add_column("CWE")
    table.add_column("Rule")
    table.add_column("Line")
    table.add_column("Severity")
    table.add_column("Snippet")
    for f in findings:
        table.add_row(f.cwe_id, f.rule_id, str(f.start_line), f.severity, f.lines.strip())
    console.print(table)
    return 0


def cmd_remediate(args: argparse.Namespace) -> int:
    config = Config.load(args.config)
    orch = Orchestrator(config)

    console.print(f"[bold]Remediating[/bold] {args.file} (model={config.ollama.model})")
    report = orch.remediate_file(
        args.file, repo_root=args.repo_root, test_dir=args.test_dir
    )

    if report.total_count == 0:
        console.print("[green]No findings -- nothing to remediate.[/green]")
        return 0

    table = Table(title="Remediation results")
    table.add_column("CWE")
    table.add_column("Rule")
    table.add_column("Line")
    table.add_column("Verdict")
    table.add_column("Iterations")
    for r in report.results:
        style = _VERDICT_STYLE.get(r.verdict, "")
        table.add_row(
            r.finding.cwe_id,
            r.finding.rule_id,
            str(r.finding.start_line),
            f"[{style}]{r.verdict.value}[/{style}]",
            str(r.iterations_used),
        )
    console.print(table)
    console.print(
        f"\n[bold]{report.fixed_count}/{report.total_count}[/bold] findings resolved."
    )

    if args.apply:
        Path(args.file).write_text(report.final_source)
        console.print(f"[bold green]Wrote patched file to {args.file}[/bold green]")
    elif report.fixed_count > 0:
        console.print("(dry run -- pass --apply to write the patched file)")

    if args.report:
        Path(args.report).write_text(_report_to_json(report))
        console.print(f"Report written to {args.report}")

    any_unresolved = any(not r.success for r in report.results)
    return 1 if any_unresolved else 0


def cmd_benchmark(args: argparse.Namespace) -> int:
    from slm_avr.eval.harness import EvalHarness

    config = Config.load(args.config)
    harness = EvalHarness(config, benchmark_dir=args.benchmark_dir)
    summary = harness.run()

    table = Table(title="L-AVRBench-style evaluation")
    table.add_column("Case")
    table.add_column("CWE")
    table.add_column("Verdict")
    table.add_column("Iterations")
    for case in summary.cases:
        style = _VERDICT_STYLE.get(case.verdict, "")
        table.add_row(
            case.name,
            case.cwe_id,
            f"[{style}]{case.verdict.value}[/{style}]",
            str(case.iterations_used),
        )
    console.print(table)
    console.print(
        f"\n[bold]Repair success rate: {summary.success_rate:.1%}[/bold] "
        f"({summary.fixed_count}/{summary.total_count})"
    )

    if args.report:
        Path(args.report).write_text(summary.to_json())
        console.print(f"JSON report written to {args.report}")
    if args.markdown:
        Path(args.markdown).write_text(summary.to_markdown())
        console.print(f"Markdown report written to {args.markdown}")

    return 0 if summary.fixed_count == summary.total_count else 1


def _report_to_json(report) -> str:
    return json.dumps(
        {
            "file_path": report.file_path,
            "fixed_count": report.fixed_count,
            "total_count": report.total_count,
            "results": [
                {
                    "cwe": r.finding.cwe_id,
                    "rule_id": r.finding.rule_id,
                    "line": r.finding.start_line,
                    "verdict": r.verdict.value,
                    "iterations": r.iterations_used,
                    "attempts": [
                        {
                            "iteration": a.iteration,
                            "verdict": a.verdict.value,
                            "feedback": a.reviewer_feedback,
                        }
                        for a in r.attempts
                    ],
                }
                for r in report.results
            ],
        },
        indent=2,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="slm-avr",
        description=(
            "Retrieval-Augmented Autonomous Code Vulnerability Remediation "
            "using Static Analysis-Guided Small Language Models"
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="Run static analysis only, no remediation")
    p_scan.add_argument("path")
    p_scan.add_argument("--config", default=None)
    p_scan.set_defaults(func=cmd_scan)

    p_rem = sub.add_parser("remediate", help="Detect and remediate vulnerabilities in a file")
    p_rem.add_argument("file")
    p_rem.add_argument("--repo-root", default=None, help="repo root for cross-file context")
    p_rem.add_argument("--test-dir", default=None, help="directory to sandbox-run pytest in")
    p_rem.add_argument("--apply", action="store_true", help="write the patched file back")
    p_rem.add_argument("--report", default=None, help="write a JSON report to this path")
    p_rem.add_argument("--config", default=None)
    p_rem.set_defaults(func=cmd_remediate)

    p_bench = sub.add_parser("benchmark", help="Run the L-AVRBench-style evaluation harness")
    p_bench.add_argument("--benchmark-dir", default="benchmark")
    p_bench.add_argument("--report", default="eval_report.json")
    p_bench.add_argument("--markdown", default="eval_report.md")
    p_bench.add_argument("--config", default=None)
    p_bench.set_defaults(func=cmd_benchmark)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
