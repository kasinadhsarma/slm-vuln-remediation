import json
import os
import pickle

from app import load_data


def test_functional_round_trips_data():
    payload = json.dumps({"a": 1, "b": 2}).encode()
    result = load_data(payload)
    assert result == {"a": 1, "b": 2}


class _PickleExploit:
    def __init__(self, marker_path):
        self.marker_path = marker_path

    def __reduce__(self):
        return (os.system, (f"touch {self.marker_path}",))


def test_security_blocks_pickle_exploit(tmp_path):
    marker = tmp_path / "pwned"
    payload = pickle.dumps(_PickleExploit(str(marker)))
    try:
        load_data(payload)
    except Exception:
        pass
    assert not marker.exists(), "pickle deserialization executed arbitrary code"
