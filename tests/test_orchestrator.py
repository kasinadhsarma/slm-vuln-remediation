from pathlib import Path

from conftest import VULNERABLE_SAMPLE

from slm_avr.config import Config
from slm_avr.llm.mock_provider import MockProvider
from slm_avr.models import Verdict
from slm_avr.orchestrator import Orchestrator

RULES_PATH = str(Path(__file__).resolve().parents[1] / "rules" / "custom_rules.yaml")
EXEMPLARS_PATH = str(
    Path(__file__).resolve().parents[1]
    / "src" / "slm_avr" / "retrieval" / "exemplars" / "cwe_fixes.json"
)

_FIXES = {
    "CWE-89": "def get_user(cursor, username):\n"
    '    query = "SELECT * FROM users WHERE username = ?"\n'
    "    cursor.execute(query, (username,))\n"
    "    return cursor.fetchone()",
    "CWE-78": "def run_backup(target_dir):\n"
    '    subprocess.run(["tar", "-czf", "backup.tar.gz", target_dir], shell=False, check=True)',
    "CWE-22": "def read_file(base, filename):\n"
    "    safe_filename = os.path.basename(filename)\n"
    "    if safe_filename != filename:\n"
    '        raise ValueError("invalid filename")\n'
    "    return open(os.path.join(base, safe_filename)).read()",
    "CWE-798": 'password = os.environ.get("APP_PASSWORD", "")',
    "CWE-327": "def hash_password(pw):\n"
    "    salt = os.urandom(16)\n"
    "    dk = hashlib.pbkdf2_hmac('sha256', pw.encode(), salt, 200_000)\n"
    "    return salt.hex() + ':' + dk.hex()",
    "CWE-502": "def load_data(data):\n    return json.loads(data)",
}


def _scripted_responder(system_prompt, user_prompt):
    for cwe, fix in _FIXES.items():
        if cwe in user_prompt:
            return f"```python\n{fix}\n```"
    raise AssertionError(f"no scripted fix for prompt:\n{user_prompt[:300]}")


def test_orchestrator_fixes_every_finding_with_scripted_llm(tmp_path):
    target = tmp_path / "sample.py"
    target.write_text(VULNERABLE_SAMPLE)

    config = Config(
        semgrep_config_paths=[RULES_PATH],
        exemplars_path=EXEMPLARS_PATH,
        max_iterations=2,
    )
    orch = Orchestrator(config, llm=MockProvider(_scripted_responder))

    report = orch.remediate_file(str(target), repo_root=str(tmp_path))

    assert report.total_count == 6
    assert report.fixed_count == 6
    assert all(r.verdict == Verdict.FIXED for r in report.results)


def test_orchestrator_gives_up_after_max_iterations_on_a_stubborn_bad_llm(tmp_path):
    target = tmp_path / "sample.py"
    target.write_text(VULNERABLE_SAMPLE)

    config = Config(
        semgrep_config_paths=[RULES_PATH],
        exemplars_path=EXEMPLARS_PATH,
        max_iterations=2,
    )
    # Always re-emits the exact same vulnerable code, so the SAST re-scan
    # keeps flagging it and the loop can never reach FIXED.
    stubborn_noop = MockProvider(
        lambda s, u: "```python\n"
        "def hash_password(pw):\n"
        "    return hashlib.md5(pw.encode()).hexdigest()\n"
        "```"
    )
    orch = Orchestrator(config, llm=stubborn_noop)

    finding = orch.scan(str(target))
    cwe327 = next(f for f in finding if f.cwe_id == "CWE-327")
    from slm_avr.agents.curator import CuratorAgent

    result = orch.remediate_finding(
        cwe327, VULNERABLE_SAMPLE, finding, CuratorAgent(str(tmp_path))
    )

    assert result.verdict == Verdict.MAX_ITERATIONS_EXCEEDED
    assert result.iterations_used == 2
