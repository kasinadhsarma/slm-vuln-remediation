from pathlib import Path

from conftest import VULNERABLE_SAMPLE

from slm_avr.sast.semgrep_runner import SemgrepRunner

RULES = [str(Path(__file__).resolve().parents[1] / "rules" / "custom_rules.yaml")]


def test_scan_file_detects_all_six_classes(tmp_path):
    target = tmp_path / "sample.py"
    target.write_text(VULNERABLE_SAMPLE)

    findings = SemgrepRunner(RULES).scan_file(str(target))
    cwes = {f.cwe_id for f in findings}

    assert cwes == {"CWE-89", "CWE-78", "CWE-22", "CWE-798", "CWE-327", "CWE-502"}


def test_rescan_source_reflects_a_fix(tmp_path):
    target = tmp_path / "sample.py"
    target.write_text(VULNERABLE_SAMPLE)
    runner = SemgrepRunner(RULES)

    baseline = runner.scan_file(str(target))
    patched = VULNERABLE_SAMPLE.replace(
        "return hashlib.md5(pw.encode()).hexdigest()",
        "return hashlib.sha256(pw.encode()).hexdigest()",
    )
    after = runner.rescan_source(patched, str(target))

    assert len(after) == len(baseline) - 1
    assert "CWE-327" not in {f.cwe_id for f in after}


def test_finding_snippet_is_populated_from_source(tmp_path):
    target = tmp_path / "sample.py"
    target.write_text(VULNERABLE_SAMPLE)

    findings = SemgrepRunner(RULES).scan_file(str(target))
    sqli = next(f for f in findings if f.cwe_id == "CWE-89")

    assert "cursor.execute(query)" in sqli.lines
