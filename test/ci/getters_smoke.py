#!/usr/bin/python3

"""Smoke test: call every implemented getter against a real node and assert a
sane, non-None result. Cheap full-parity check for the JSON-RPC driver.

Run via pytest (clean output) or as a plain script (used by `make run-tests`):

    uv run pytest test/ci/getters_smoke.py
    uv run test/ci/getters_smoke.py
"""

import pytest
from napalm import get_network_driver

HOST = "clab-napalm-ci_cd-srl"

GETTERS = [
    ("is_alive", {}),
    ("get_facts", {}),
    ("get_interfaces", {}),
    ("get_interfaces_counters", {}),
    ("get_interfaces_ip", {}),
    ("get_arp_table", {}),
    ("get_ipv6_neighbors_table", {}),
    ("get_bgp_neighbors", {}),
    ("get_bgp_neighbors_detail", {}),
    ("get_bgp_config", {}),
    ("get_environment", {}),
    ("get_lldp_neighbors", {}),
    ("get_lldp_neighbors_detail", {}),
    ("get_network_instances", {}),
    ("get_users", {}),
    ("get_snmp_information", {}),
    ("get_config", {}),
    ("get_ntp_servers", {}),
    ("get_ntp_stats", {}),
    ("get_optics", {}),
    ("get_mac_address_table", {}),
    ("get_route_to", {}),
]


@pytest.fixture(scope="module")
def device():
    dev = get_network_driver("srlinux")(HOST, "admin", "NokiaSrl1!", 10, {"insecure": True})
    dev.open()
    try:
        yield dev
    finally:
        dev.close()


@pytest.mark.parametrize("getter,kwargs", GETTERS, ids=[g for g, _ in GETTERS])
def test_getter_returns_non_none(device, getter, kwargs):
    result = getattr(device, getter)(**kwargs)
    assert result is not None


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__]))
