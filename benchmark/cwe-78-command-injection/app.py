import os


def log_message(message, log_path):
    os.system(f"echo {message} >> {log_path}")
