# Copyright 2024 Nokia
# Licensed under the Apache License 2.0.
# SPDX-License-Identifier: Apache-2.0
"""
This is a simple example of how to use napalm-srlinux.

First, deploy an SR Linux container using containerlab:

    CLAB_LABDIR_BASE=/tmp \
    sudo -E clab deploy -c -t srlinux.dev/clab-srl

Then uncomment the NAPALM API calls that you want to run and run this script:

    uv run examples/example.py
"""

from napalm import get_network_driver

# using rich to pretty print the output;
# feel free to remove it if you don't want to install it
from rich import print_json

driver = get_network_driver("srlinux")
optional_args = {
    # "jsonrpc_port": 443,
    # "skip_verify": True,  # https without certificate verification
    # "tls_ca": "/path/to/ca.pem",  # https verified against a CA
    "insecure": True,  # plain http on port 80
}
with driver("srl", "admin", "NokiaSrl1!", optional_args=optional_args) as device:
    print(device.is_alive())
    print_json(data=device.get_facts())
    # print_json(data=device.get_interfaces())
    # print_json(data=device.get_interfaces_counters())
    # print_json(data=device.get_interfaces_ip())
    # print_json(data=device.get_arp_table())
    # print_json(data=device.get_arp_table(vrf="mgmt"))
    # print_json(data=device.get_ipv6_neighbors_table())
    # print_json(data=device.get_bgp_neighbors())
    # print_json(data=device.get_bgp_neighbors_detail())
    # print_json(data=device.get_bgp_config())
    # print_json(data=device.get_environment())
    # print_json(data=device.get_lldp_neighbors())
    # print_json(data=device.get_lldp_neighbors_detail())
    # print_json(data=device.get_network_instances())
    # print_json(data=device.get_users())
    # print_json(data=device.get_snmp_information())
    # print_json(data=device.get_config(retrieve="running"))
    # print_json(data=device.get_config(retrieve="running", sanitized=True))
    # print_json(data=device.get_ntp_servers())
    # print_json(data=device.get_ntp_stats())
    # print_json(data=device.get_optics())
    # print_json(data=device.get_mac_address_table())
    # print_json(data=device.get_route_to())
    # print_json(data=device.get_route_to(destination="172.20.20.0/24"))
    # print_json(data=device.ping(destination="172.20.20.1", vrf="mgmt"))
    # print_json(data=device.traceroute(destination="172.20.20.1", vrf="mgmt"))
    # print(device.cli(["show version", "date"]))

    # candidate config workflow (CLI or JSON config):
    # device.load_merge_candidate(config='set / system information location "lab"')
    # print(device.compare_config())
    # device.commit_config()
    # device.rollback()
