from slm_avr.slicing.slicer import ProgramSlicer

SOURCE_WITH_DISTRACTIONS = '''import os
import logging

def process_request(user_id, action):
    logging.info("processing request")
    timestamp = time.time()
    base_dir = "/var/data/"
    unrelated = compute_something_else(timestamp)
    filename = user_id + ".json"
    full_path = base_dir + filename
    print("about to open file")
    data = open(full_path).read()
    return data
'''


def test_backward_slice_excludes_unrelated_statements():
    result = ProgramSlicer().slice(SOURCE_WITH_DISTRACTIONS, "app.py", target_line=12)

    assert "logging.info" not in result.slice_source
    assert "unrelated = compute_something_else" not in result.slice_source
    assert 'print("about to open file")' not in result.slice_source
    # the actual dependency chain must be preserved
    assert 'base_dir = "/var/data/"' in result.slice_source
    assert 'filename = user_id + ".json"' in result.slice_source
    assert "full_path = base_dir + filename" in result.slice_source
    assert "data = open(full_path).read()" in result.slice_source


def test_full_function_source_is_the_complete_function():
    result = ProgramSlicer().slice(SOURCE_WITH_DISTRACTIONS, "app.py", target_line=12)
    assert result.enclosing_name == "process_request"
    assert "logging.info" in result.full_function_source
    assert "return data" in result.full_function_source


def test_module_level_finding_bounds_to_single_statement():
    source = 'import os\n\npassword = "SuperSecret123"\n\ndef f():\n    pass\n'
    result = ProgramSlicer().slice(source, "app.py", target_line=3)

    assert result.enclosing_name == "<module>"
    assert "def f()" not in result.full_function_source
    assert 'password = "SuperSecret123"' in result.full_function_source
