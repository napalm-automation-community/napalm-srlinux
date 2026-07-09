#!/usr/bin/python3

"""Regression test: get_interfaces_ip() must not fail on subinterfaces without
any IP addresses.

Run via pytest (clean output) or as a plain script (used by `make run-tests`):

    uv run pytest test/ci/get_interfaces_ip.py
    uv run test/ci/get_interfaces_ip.py
"""

import pytest
from napalm import get_network_driver

HOST = "clab-napalm-ci_cd-srl"

# a system0 subinterface with no IP addresses configured
NO_IP_CONFIG = """
set / interface system0
set / interface system0 admin-state enable
set / interface system0 subinterface 0
"""


@pytest.fixture(scope="module")
def device():
    dev = get_network_driver("srlinux")(HOST, "admin", "NokiaSrl1!", 10, {"insecure": True})
    dev.open()
    try:
        yield dev
    finally:
        dev.close()


def test_get_interfaces_ip_without_addresses(device):
    device.load_merge_candidate(config=NO_IP_CONFIG)
    device.commit_config()
    try:
        ip_addresses = device.get_interfaces_ip()
        assert ip_addresses is not None
        assert ip_addresses.get("system0.0") == {}
    finally:
        device.rollback()


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__]))
