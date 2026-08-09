import sqlite3

from app import get_user


def _make_db():
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE users (username TEXT, role TEXT)")
    cursor.execute("INSERT INTO users VALUES ('alice', 'admin')")
    cursor.execute("INSERT INTO users VALUES ('bob', 'user')")
    conn.commit()
    return conn, cursor


def test_functional_returns_matching_user():
    conn, cursor = _make_db()
    row = get_user(cursor, "alice")
    assert row == ("alice", "admin")
    conn.close()


def test_functional_returns_none_for_unknown_user():
    conn, cursor = _make_db()
    row = get_user(cursor, "nobody")
    assert row is None
    conn.close()


def test_security_blocks_sql_injection():
    conn, cursor = _make_db()
    # A classic tautology-based injection payload. If the query is built by
    # string interpolation, this returns the first row in the table (alice)
    # even though no user is literally named this. A parameterized query
    # treats it as a literal username and correctly finds no match.
    payload = "nonexistent' OR '1'='1"
    row = get_user(cursor, payload)
    assert row is None, "SQL injection payload bypassed the WHERE clause"
    conn.close()
