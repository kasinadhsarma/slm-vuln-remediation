from pathlib import Path

from conftest import VULNERABLE_SAMPLE

from slm_avr.agents.reviewer import PatchReviewer, apply_function_patch
from slm_avr.models import Verdict
from slm_avr.sast.semgrep_runner import SemgrepRunner
from slm_avr.slicing.slicer import ProgramSlicer

RULES = [str(Path(__file__).resolve().parents[1] / "rules" / "custom_rules.yaml")]


def test_apply_function_patch_hoists_missing_stdlib_import():
    code_slice = ProgramSlicer().slice(VULNERABLE_SAMPLE, "sample.py", target_line=22)
    patch = "def load_data(data):\n    return json.loads(data)"

    patched = apply_function_patch(VULNERABLE_SAMPLE, code_slice, patch)

    assert "import json" in patched
    # doesn't duplicate an import that already exists
    assert patched.count("import os") == 1


def test_review_fixed_verdict_on_a_correct_patch(tmp_path):
    target = tmp_path / "sample.py"
    target.write_text(VULNERABLE_SAMPLE)
    runner = SemgrepRunner(RULES)
    baseline = runner.scan_file(str(target))
    finding = next(f for f in baseline if f.cwe_id == "CWE-327")

    code_slice = ProgramSlicer().slice(VULNERABLE_SAMPLE, str(target), finding.start_line)
    good_patch = (
        "def hash_password(pw):\n"
        "    salt = os.urandom(16)\n"
        "    dk = hashlib.pbkdf2_hmac('sha256', pw.encode(), salt, 200_000)\n"
        "    return salt.hex() + ':' + dk.hex()"
    )

    result = PatchReviewer(runner).review(
        finding, baseline, VULNERABLE_SAMPLE, code_slice, good_patch
    )

    assert result.verdict == Verdict.FIXED


def test_review_undefined_name_verdict_on_a_bad_patch(tmp_path):
    target = tmp_path / "sample.py"
    target.write_text(VULNERABLE_SAMPLE)
    runner = SemgrepRunner(RULES)
    baseline = runner.scan_file(str(target))
    finding = next(f for f in baseline if f.cwe_id == "CWE-327")

    code_slice = ProgramSlicer().slice(VULNERABLE_SAMPLE, str(target), finding.start_line)
    bad_patch = "def hash_password(pw):\n    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt())"

    result = PatchReviewer(runner).review(
        finding, baseline, VULNERABLE_SAMPLE, code_slice, bad_patch
    )

    assert result.verdict == Verdict.UNDEFINED_NAME


def test_review_still_vulnerable_verdict_on_a_noop_patch(tmp_path):
    target = tmp_path / "sample.py"
    target.write_text(VULNERABLE_SAMPLE)
    runner = SemgrepRunner(RULES)
    baseline = runner.scan_file(str(target))
    finding = next(f for f in baseline if f.cwe_id == "CWE-327")

    code_slice = ProgramSlicer().slice(VULNERABLE_SAMPLE, str(target), finding.start_line)
    noop_patch = "def hash_password(pw):\n    return hashlib.md5(pw.encode()).hexdigest()"

    result = PatchReviewer(runner).review(
        finding, baseline, VULNERABLE_SAMPLE, code_slice, noop_patch
    )

    assert result.verdict == Verdict.STILL_VULNERABLE
