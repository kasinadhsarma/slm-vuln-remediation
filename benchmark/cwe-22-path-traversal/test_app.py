import pytest

from app import read_user_file


def test_functional_reads_allowed_file(tmp_path):
    base = tmp_path / "sandbox"
    base.mkdir()
    (base / "notes.txt").write_text("hello world")

    content = read_user_file(str(base), "notes.txt")
    assert content == "hello world"


def test_security_blocks_path_traversal(tmp_path):
    base = tmp_path / "sandbox"
    base.mkdir()
    secret = tmp_path / "secret.txt"
    secret.write_text("TOP SECRET")

    with pytest.raises(Exception):
        read_user_file(str(base), "../secret.txt")
