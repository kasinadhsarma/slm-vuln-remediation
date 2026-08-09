import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

VULNERABLE_SAMPLE = '''import os
import subprocess
import hashlib
import pickle

def get_user(cursor, username):
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)

def run_backup(target_dir):
    os.system("tar -czf backup.tar.gz " + target_dir)

def read_file(base, filename):
    return open(base + filename).read()

password = "SuperSecret123"

def hash_password(pw):
    return hashlib.md5(pw.encode()).hexdigest()

def load_data(data):
    return pickle.loads(data)
'''
