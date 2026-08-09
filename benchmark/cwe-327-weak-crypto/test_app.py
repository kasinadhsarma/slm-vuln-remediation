import hashlib

from app import hash_password


def test_functional_returns_nonempty_string():
    result = hash_password("hunter2")
    assert isinstance(result, str) and len(result) > 0


def test_security_not_md5_or_sha1():
    md5_digest = hashlib.md5(b"hunter2").hexdigest()
    sha1_digest = hashlib.sha1(b"hunter2").hexdigest()
    result = hash_password("hunter2")
    assert md5_digest not in result, "weak MD5 digest still used for password hashing"
    assert sha1_digest not in result, "weak SHA1 digest still used for password hashing"
