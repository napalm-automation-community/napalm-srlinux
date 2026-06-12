# Copyright 2024 Nokia
# Licensed under the Apache License 2.0.
# SPDX-License-Identifier: Apache-2.0

"""Record unit-test fixtures from a live SR Linux node.

Deploy the recording lab first:

    cd .clab && sudo clab deploy -t record-topology.yml --reconfigure

Then run (from the repo root):

    uv run tools/record_fixtures.py --prepare   # push the lab config (once)
    uv run tools/record_fixtures.py             # record fixtures + expected results

The script wraps the driver's device so that every JSON-RPC request/response
pair is written into test/unit/mocked_data/<test_name>/normal/ using the same
naming scheme the fake test device uses (test/unit/fixture_names.py). After
recording, each getter's return value is stored as expected_result.json.
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "test" / "unit"))

from fixture_names import fixture_name_for_cli, fixture_name_for_get  # noqa: E402

from napalm_srlinux.srlinux import NokiaSRLinuxDriver  # noqa: E402

SRL1 = os.getenv("NAPALM_HOSTNAME", "172.20.21.11")
SRL2 = os.getenv("NAPALM_SRL2_HOSTNAME", "172.20.21.12")
USERNAME = os.getenv("NAPALM_USERNAME", "admin")
PASSWORD = os.getenv("NAPALM_PASSWORD", "NokiaSrl1!")
OPTIONAL_ARGS = {"insecure": True}

MOCKED_DATA = REPO_ROOT / "test" / "unit" / "mocked_data"

# srl1 is the recorded node: BGP to srl2, an ip-vrf TEST, a mac-vrf, NTP, users
SRL1_CONFIG = """
set / interface ethernet-1/1 admin-state enable
set / interface ethernet-1/1 subinterface 0 admin-state enable
set / interface ethernet-1/1 subinterface 0 ipv4 admin-state enable
set / interface ethernet-1/1 subinterface 0 ipv4 address 10.0.0.1/30
set / interface ethernet-1/1 subinterface 0 ipv6 admin-state enable
set / interface ethernet-1/1 subinterface 0 ipv6 address 2001:db8:0:1::1/64
set / interface ethernet-1/2 admin-state enable
set / interface ethernet-1/2 subinterface 0 admin-state enable
set / interface ethernet-1/2 subinterface 0 ipv4 admin-state enable
set / interface ethernet-1/2 subinterface 0 ipv4 address 10.0.1.1/30
set / interface ethernet-1/2 subinterface 0 ipv6 admin-state enable
set / interface ethernet-1/2 subinterface 0 ipv6 address 2001:db8:0:2::1/64
set / interface ethernet-1/3 admin-state enable
set / interface ethernet-1/3 subinterface 0 type bridged
set / interface ethernet-1/3 subinterface 0 admin-state enable
set / network-instance default type default admin-state enable
set / network-instance default interface ethernet-1/1.0
set / network-instance TEST type ip-vrf admin-state enable
set / network-instance TEST interface ethernet-1/2.0
set / network-instance bridge1 type mac-vrf admin-state enable
set / network-instance bridge1 interface ethernet-1/3.0
set / routing-policy policy all default-action policy-result accept
set / network-instance default protocols bgp autonomous-system 65001
set / network-instance default protocols bgp router-id 1.1.1.1
set / network-instance default protocols bgp afi-safi ipv4-unicast admin-state enable
set / network-instance default protocols bgp afi-safi ipv6-unicast admin-state enable
set / network-instance default protocols bgp group ebgp peer-as 65002
set / network-instance default protocols bgp group ebgp description "eBGP to srl2"
set / network-instance default protocols bgp group ebgp export-policy [ all ]
set / network-instance default protocols bgp group ebgp import-policy [ all ]
set / network-instance default protocols bgp neighbor 10.0.0.2 peer-group ebgp
set / network-instance default protocols bgp neighbor 10.0.0.2 admin-state enable
set / network-instance default protocols bgp neighbor 10.0.0.2 description "srl2"
set / system ntp admin-state enable network-instance mgmt
set / system ntp server 172.20.21.1 prefer true
set / system information location lab
set / system information contact netops
set / system aaa authentication user testuser password NapalmTest1!
"""

# srl2 provides the adjacencies and advertises 1.0.4.0/24 and 8.8.8.8/32
SRL2_CONFIG = """
set / interface ethernet-1/1 admin-state enable
set / interface ethernet-1/1 subinterface 0 admin-state enable
set / interface ethernet-1/1 subinterface 0 ipv4 admin-state enable
set / interface ethernet-1/1 subinterface 0 ipv4 address 10.0.0.2/30
set / interface ethernet-1/1 subinterface 0 ipv6 admin-state enable
set / interface ethernet-1/1 subinterface 0 ipv6 address 2001:db8:0:1::2/64
set / interface ethernet-1/2 admin-state enable
set / interface ethernet-1/2 subinterface 0 admin-state enable
set / interface ethernet-1/2 subinterface 0 ipv4 admin-state enable
set / interface ethernet-1/2 subinterface 0 ipv4 address 10.0.1.2/30
set / interface ethernet-1/2 subinterface 0 ipv6 admin-state enable
set / interface ethernet-1/2 subinterface 0 ipv6 address 2001:db8:0:2::2/64
set / interface ethernet-1/3 admin-state enable
set / interface ethernet-1/3 subinterface 0 admin-state enable
set / interface ethernet-1/3 subinterface 0 ipv4 admin-state enable
set / interface ethernet-1/3 subinterface 0 ipv4 address 10.0.2.2/30
set / interface lo0 admin-state enable
set / interface lo0 subinterface 0 admin-state enable
set / interface lo0 subinterface 0 ipv4 admin-state enable
set / interface lo0 subinterface 0 ipv4 address 8.8.8.8/32
set / network-instance default type default admin-state enable
set / network-instance default interface ethernet-1/1.0
set / network-instance default interface ethernet-1/2.0
set / network-instance default interface ethernet-1/3.0
set / network-instance default interface lo0.0
set / network-instance default next-hop-groups group blackhole blackhole
set / network-instance default static-routes route 1.0.4.0/24 next-hop-group blackhole
set / network-instance default static-routes route 1.0.4.0/24 admin-state enable
set / routing-policy policy all default-action policy-result accept
set / network-instance default protocols bgp autonomous-system 65002
set / network-instance default protocols bgp router-id 2.2.2.2
set / network-instance default protocols bgp afi-safi ipv4-unicast admin-state enable
set / network-instance default protocols bgp afi-safi ipv6-unicast admin-state enable
set / network-instance default protocols bgp group ebgp peer-as 65001
set / network-instance default protocols bgp group ebgp export-policy [ all ]
set / network-instance default protocols bgp group ebgp import-policy [ all ]
set / network-instance default protocols bgp neighbor 10.0.0.1 peer-group ebgp
set / network-instance default protocols bgp neighbor 10.0.0.1 admin-state enable
"""


def make_driver(hostname: str) -> NokiaSRLinuxDriver:
    driver = NokiaSRLinuxDriver(hostname, USERNAME, PASSWORD, optional_args=OPTIONAL_ARGS)
    driver.open()
    return driver


def prepare_lab() -> None:
    """Push the lab config through the driver's own config management."""
    for hostname, config in ((SRL1, SRL1_CONFIG), (SRL2, SRL2_CONFIG)):
        driver = make_driver(hostname)
        print(f"--- configuring {hostname}")
        driver.load_merge_candidate(config=config)
        diff = driver.compare_config()
        print(diff or "(no changes)")
        driver.commit_config()
        driver.close()

    print("--- generating traffic for ARP/MAC/BGP state")
    srl1 = make_driver(SRL1)
    srl2 = make_driver(SRL2)
    # populate ARP (v4) and the IPv6 neighbor cache in the TEST and default vrfs
    print(srl1.ping("10.0.1.2", vrf="TEST", count=2)["success"]["packet_loss"], "lost (TEST)")
    print(srl1.ping("10.0.0.2", vrf="default", count=2)["success"]["packet_loss"], "lost (default)")
    print(
        srl1.ping("2001:db8:0:2::2", vrf="TEST", count=2)["success"]["packet_loss"],
        "lost (TEST v6)",
    )
    print(
        srl1.ping("2001:db8:0:1::2", vrf="default", count=2)["success"]["packet_loss"],
        "lost (default v6)",
    )
    # make srl2 ARP into srl1's mac-vrf so a MAC address is learned
    srl2.ping("10.0.2.1", vrf="default", count=2)
    srl1.close()
    srl2.close()
    print("--- waiting for the BGP session to establish")
    for _ in range(30):
        srl1 = make_driver(SRL1)
        peers = srl1.get_bgp_neighbors()["global"]["peers"]
        srl1.close()
        if peers and all(p["is_up"] for p in peers.values()):
            print("BGP established")
            return
        time.sleep(2)
    raise RuntimeError("BGP session did not establish")


class RecordingDevice:
    """Wraps a real SRLinuxDevice, teeing requests/responses into fixture files."""

    def __init__(self, device):
        self._device = device
        self.target_dir: Path | None = None

    def __getattr__(self, name):
        return getattr(self._device, name)

    def _write(self, filename: str, data) -> None:
        self.target_dir.mkdir(parents=True, exist_ok=True)
        with open(self.target_dir / filename, "w") as f:
            json.dump(data, f, indent=2, sort_keys=False)

    def get_paths(self, paths, datastore):
        result = self._device.get_paths(paths, datastore)
        self._write(fixture_name_for_get(paths, datastore), result)
        return result

    def run_cli_commands(self, commands, output_format="text"):
        result = self._device.run_cli_commands(commands, output_format)
        self._write(fixture_name_for_cli(commands), result)
        return result


# test name -> getter invocation, mirroring napalm.base.test.getters.BaseTestGetters
RECORDINGS = {
    "test_is_alive": lambda d: d.is_alive(),
    "test_get_facts": lambda d: d.get_facts(),
    "test_get_interfaces": lambda d: d.get_interfaces(),
    "test_get_interfaces_counters": lambda d: d.get_interfaces_counters(),
    "test_get_interfaces_ip": lambda d: d.get_interfaces_ip(),
    "test_get_arp_table": lambda d: d.get_arp_table(),
    "test_get_arp_table_with_vrf": lambda d: d.get_arp_table(vrf="TEST"),
    "test_get_ipv6_neighbors_table": lambda d: d.get_ipv6_neighbors_table(),
    "test_get_bgp_neighbors": lambda d: d.get_bgp_neighbors(),
    "test_get_bgp_neighbors_detail": lambda d: d.get_bgp_neighbors_detail(),
    "test_get_bgp_config": lambda d: d.get_bgp_config(),
    "test_get_environment": lambda d: d.get_environment(),
    "test_get_lldp_neighbors": lambda d: d.get_lldp_neighbors(),
    "test_get_lldp_neighbors_detail": lambda d: d.get_lldp_neighbors_detail(),
    "test_get_network_instances": lambda d: d.get_network_instances(),
    "test_get_users": lambda d: d.get_users(),
    "test_get_snmp_information": lambda d: d.get_snmp_information(),
    "test_get_config": lambda d: d.get_config(),
    "test_get_config_sanitized": lambda d: d.get_config(sanitized=True),
    "test_get_ntp_servers": lambda d: d.get_ntp_servers(),
    "test_get_ntp_stats": lambda d: d.get_ntp_stats(),
    "test_get_optics": lambda d: d.get_optics(),
    "test_get_mac_address_table": lambda d: d.get_mac_address_table(),
    "test_get_route_to": lambda d: d.get_route_to(destination="1.0.4.0/24", protocol="bgp"),
    "test_ping": lambda d: d.ping("8.8.8.8"),
    "test_traceroute": lambda d: d.traceroute("8.8.8.8"),
}


def record() -> None:
    driver = make_driver(SRL1)
    recorder = RecordingDevice(driver.device)
    driver.device = recorder

    for test_name, invoke in RECORDINGS.items():
        recorder.target_dir = MOCKED_DATA / test_name / "normal"
        result = invoke(driver)
        # round-trip like the test framework does, so the expected result file
        # matches exactly what the comparison will see
        expected = json.loads(json.dumps(result))
        recorder._write("expected_result.json", expected)
        print(f"recorded {test_name}")

    # test_get_config_filtered reuses the running-config fixture but returns the
    # result of its last loop iteration (retrieve="candidate"), which is empty
    recorder.target_dir = MOCKED_DATA / "test_get_config_filtered" / "normal"
    driver.get_config(retrieve="running")
    recorder._write(
        "expected_result.json", {"running": "", "candidate": "", "startup": ""}
    )
    print("recorded test_get_config_filtered")

    driver.device = recorder._device
    driver.close()


if __name__ == "__main__":
    os.environ["TZ"] = "GMT"
    time.tzset()

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--prepare", action="store_true", help="push the lab config before recording"
    )
    args = parser.parse_args()

    if args.prepare:
        prepare_lab()
    else:
        record()
