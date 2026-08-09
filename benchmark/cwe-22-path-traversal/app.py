import os


def read_user_file(base_dir, filename):
    return open(os.path.join(base_dir, filename)).read()
