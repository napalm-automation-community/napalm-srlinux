#!/usr/bin/python3

"""End-to-end test of full config replacement: get_config -> modify ->
load_replace_candidate -> compare -> commit -> verify -> rollback.

Run via pytest (clean output) or as a plain script (used by `make run-tests`):

    uv run pytest test/ci/config_replace.py
    uv run test/ci/config_replace.py
"""

import json

import pytest
from napalm import get_network_driver

HOST = "clab-napalm-ci_cd-srl"
LOCATION = "replaced-by-napalm"


@pytest.fixture(scope="module")
def device():
    dev = get_network_driver("srlinux")(HOST, "admin", "NokiaSrl1!", 30, {"insecure": True})
    dev.open()
    try:
        yield dev
    finally:
        dev.close()


def test_full_replace_round_trip(device):
    # fetch the full running config and use a modified copy as a full replacement
    running = json.loads(device.get_config()["running"])
    information = running.setdefault("srl_nokia-system:system", {}).setdefault(
        "srl_nokia-system-info:information", {}
    )
    location_before = information.get("location")
    information["location"] = LOCATION

    device.load_replace_candidate(config=json.dumps(running))

    # the diff of a full replace must only contain the one modified leaf
    diff = device.compare_config()
    assert LOCATION in diff

    device.commit_config()

    # the replace took effect and the node is still manageable
    after = json.loads(device.get_config()["running"])
    assert (
        after["srl_nokia-system:system"]["srl_nokia-system-info:information"]["location"]
        == LOCATION
    )

    # rollback restores the pre-replace state
    device.rollback()
    restored = json.loads(device.get_config()["running"])
    location_restored = (
        restored.get("srl_nokia-system:system", {})
        .get("srl_nokia-system-info:information", {})
        .get("location")
    )
    assert location_restored == location_before, f"{location_restored} != {location_before}"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__]))
