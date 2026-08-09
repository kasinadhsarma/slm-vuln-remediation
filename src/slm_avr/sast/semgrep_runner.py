"""Wraps the Semgrep CLI: runs scans and parses results into Finding objects.

This is the deterministic ground-truth layer of the pipeline. It is used
twice per remediation attempt: once to detect the original vulnerability,
and again by the Patch Reviewer to verify a candidate patch actually
resolves it ("compiler-in-the-loop" verification).
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from slm_avr.models import Finding


class SemgrepError(RuntimeError):
    pass


class SemgrepRunner:
    def __init__(self, config_paths: list[str]):
        if not config_paths:
            raise ValueError("SemgrepRunner requires at least one config path")
        self.config_paths = config_paths

    def scan_file(self, file_path: str) -> list[Finding]:
        return self.scan_paths([file_path])

    def scan_paths(self, paths: list[str]) -> list[Finding]:
        cmd = ["semgrep", "--json", "--quiet", "--no-git-ignore", "--metrics=off"]
        for cfg in self.config_paths:
            cmd += ["--config", cfg]
        cmd += paths

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
            )
        except FileNotFoundError as e:
            raise SemgrepError(
                "semgrep executable not found. Install it with `pip install semgrep`."
            ) from e
        except subprocess.TimeoutExpired as e:
            raise SemgrepError(f"semgrep scan timed out for {paths}") from e

        if not proc.stdout.strip():
            raise SemgrepError(f"semgrep produced no output. stderr:\n{proc.stderr}")

        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError as e:
            raise SemgrepError(
                f"could not parse semgrep JSON output: {e}\nstdout:\n{proc.stdout[:2000]}"
            ) from e

        errors = data.get("errors", [])
        fatal_errors = [e for e in errors if e.get("level") == "error"]
        if fatal_errors and not data.get("results"):
            raise SemgrepError(f"semgrep reported fatal errors: {fatal_errors}")

        findings = [self._to_finding(r) for r in data.get("results", [])]
        self._fill_source_snippets(findings)
        return findings

    @staticmethod
    def _fill_source_snippets(findings: list[Finding]) -> None:
        """The free semgrep CLI redacts `extra.lines` ("requires login"), so
        pull the actual vulnerable snippet directly from the source file."""
        cache: dict[str, list[str]] = {}
        for f in findings:
            if f.lines and f.lines != "requires login":
                continue
            if f.path not in cache:
                try:
                    cache[f.path] = Path(f.path).read_text().splitlines()
                except OSError:
                    cache[f.path] = []
            file_lines = cache[f.path]
            start = max(f.start_line - 1, 0)
            end = min(f.end_line, len(file_lines))
            f.lines = "\n".join(file_lines[start:end])

    @staticmethod
    def _to_finding(raw: dict) -> Finding:
        extra = raw.get("extra", {})
        metadata = extra.get("metadata", {})
        cwe_field = metadata.get("cwe", "UNKNOWN")
        cwe = cwe_field[0] if isinstance(cwe_field, list) and cwe_field else str(cwe_field)

        return Finding(
            rule_id=raw.get("check_id", "unknown-rule"),
            cwe=cwe,
            message=extra.get("message", ""),
            path=raw.get("path", ""),
            start_line=raw.get("start", {}).get("line", 0),
            end_line=raw.get("end", {}).get("line", 0),
            start_col=raw.get("start", {}).get("col", 0),
            end_col=raw.get("end", {}).get("col", 0),
            severity=extra.get("severity", "INFO"),
            lines=extra.get("lines", ""),
        )

    def rescan_source(self, source: str, original_path: str) -> list[Finding]:
        """Write `source` to a scratch file with the same name/suffix as
        `original_path` and scan it, so rule languages resolve correctly."""
        import tempfile

        suffix = Path(original_path).suffix or ".py"
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=suffix, delete=False
        ) as tmp:
            tmp.write(source)
            tmp_path = tmp.name

        try:
            findings = self.scan_file(tmp_path)
            for f in findings:
                f.path = original_path
            return findings
        finally:
            Path(tmp_path).unlink(missing_ok=True)
