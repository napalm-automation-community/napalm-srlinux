#!/usr/bin/python3

"""End-to-end test of get_vlans: configure a mac-vrf with a single-tagged
bridged subinterface, check the reported VLAN and roll the change back.

Run via pytest (clean output) or as a plain script (used by `make run-tests`):

    uv run pytest test/ci/get_vlans.py
    uv run test/ci/get_vlans.py
"""

import pytest
from napalm import get_network_driver

HOST = "clab-napalm-ci_cd-srl"

VLAN_CONFIG = """
set / interface ethernet-1/4 admin-state enable
set / interface ethernet-1/4 vlan-tagging true
set / interface ethernet-1/4 subinterface 100 type bridged
set / interface ethernet-1/4 subinterface 100 admin-state enable
set / interface ethernet-1/4 subinterface 100 vlan encap single-tagged vlan-id 100
set / network-instance vlantest type mac-vrf admin-state enable
set / network-instance vlantest interface ethernet-1/4.100
"""


@pytest.fixture(scope="module")
def device():
    dev = get_network_driver("srlinux")(HOST, "admin", "NokiaSrl1!", 10, {"insecure": True})
    dev.open()
    try:
        yield dev
    finally:
        dev.close()


def test_get_vlans(device):
    device.load_merge_candidate(config=VLAN_CONFIG)
    device.commit_config()

    vlans = device.get_vlans()
    assert 100 in vlans
    assert vlans[100]["name"] == "vlantest"
    assert "ethernet-1/4.100" in vlans[100]["interfaces"]

    # revert and check the VLAN is gone again
    device.rollback()
    assert 100 not in device.get_vlans()


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__]))
