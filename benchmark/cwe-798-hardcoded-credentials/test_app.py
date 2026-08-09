from pathlib import Path

from app import get_db_config

_LIKELY_ENV_VAR_NAMES = (
    "DB_PASSWORD", "PASSWORD", "APP_PASSWORD", "SECRET_PASSWORD",
    "DB_PASS", "DATABASE_PASSWORD",
)


def test_functional_returns_config(monkeypatch):
    for var in _LIKELY_ENV_VAR_NAMES:
        monkeypatch.setenv(var, "test-secret-value")
    cfg = get_db_config()
    assert cfg["user"] == "admin"
    assert cfg["password"]


def test_security_no_hardcoded_secret():
    src = Path(__file__).parent / "app.py"
    assert "SuperSecret123" not in src.read_text()
