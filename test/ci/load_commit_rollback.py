#!/usr/bin/python3

"""End-to-end test of the candidate config workflow: CLI merge, JSON merge,
compare, commit and rollback.

Run via pytest (clean output) or as a plain script (used by `make run-tests`):

    uv run pytest test/ci/load_commit_rollback.py
    uv run test/ci/load_commit_rollback.py
"""

import json
from datetime import datetime

import pytest
from napalm import get_network_driver

HOST = "clab-napalm-ci_cd-srl"


@pytest.fixture(scope="module")
def device():
    dev = get_network_driver("srlinux")(HOST, "admin", "NokiaSrl1!", 10, {"insecure": True})
    dev.open()
    try:
        yield dev
    finally:
        dev.close()


def _running_description(device) -> str:
    parsed = json.loads(device.get_config()["running"])
    return parsed["srl_nokia-interfaces:interface"][0]["description"]


def test_merge_commit_rollback(device):
    # a fresh value each run guarantees the candidate actually differs
    desc = f"Time {datetime.now().strftime('%H:%M:%S')}"

    # CLI format merge
    device.load_merge_candidate(config=f'set / interface ethernet-1/1 description "{desc}"')
    assert desc in device.compare_config()
    device.commit_config()
    assert _running_description(device) == desc

    # JSON format merge on top
    json_desc = f"{desc} using JSON"
    device.load_merge_candidate(
        config=json.dumps({"interface": [{"name": "ethernet-1/1", "description": json_desc}]})
    )
    device.compare_config()
    device.commit_config()
    assert _running_description(device) == json_desc

    # rollback reverts the most recent commit, restoring the CLI description
    device.rollback()
    assert _running_description(device) == desc


def test_is_alive_false_after_close():
    dev = get_network_driver("srlinux")(HOST, "admin", "NokiaSrl1!", 10, {"insecure": True})
    dev.open()
    assert dev.is_alive()["is_alive"]
    dev.close()
    assert not dev.is_alive()["is_alive"]


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__]))
