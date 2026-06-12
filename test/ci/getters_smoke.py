#!/usr/bin/python3

# Smoke test: call every implemented getter against a real node and assert a
# sane, non-None result. Cheap full-parity check for the JSON-RPC driver.

import logging
import sys

from napalm import get_network_driver

logging.basicConfig(stream=sys.stdout, level=logging.INFO)

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

driver = get_network_driver("srlinux")
device = driver("clab-napalm-ci_cd-srl", "admin", "NokiaSrl1!", 10, {"insecure": True})
device.open()

failures = []
for getter, kwargs in GETTERS:
    try:
        result = getattr(device, getter)(**kwargs)
        assert result is not None, "returned None"
        print(f"{getter}: OK")
    except Exception as exc:  # noqa: BLE001 - report all failures at once
        failures.append((getter, exc))
        print(f"{getter}: FAILED: {exc}")

device.close()

if failures:
    sys.exit(f"{len(failures)} getter(s) failed: {[g for g, _ in failures]}")

print("all getters OK")
sys.exit(0)
