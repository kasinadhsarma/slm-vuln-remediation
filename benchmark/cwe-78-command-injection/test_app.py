from app import log_message


def test_functional_logs_message(tmp_path):
    log_path = tmp_path / "log.txt"
    log_message("hello world", str(log_path))
    assert log_path.exists()
    assert "hello world" in log_path.read_text()


def test_security_blocks_command_injection(tmp_path):
    log_path = tmp_path / "log.txt"
    marker_path = tmp_path / "pwned"
    # If the message is passed to a shell unsanitized, the ';' terminates the
    # echo command and runs a second, attacker-controlled command.
    malicious = f"safe-looking-text; touch {marker_path}"
    log_message(malicious, str(log_path))
    assert not marker_path.exists(), "command injection payload executed a second command"
