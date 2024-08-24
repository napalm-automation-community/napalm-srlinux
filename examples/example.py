# Copyright 2020 Nokia
# Licensed under the Apache License 2.0.
# SPDX-License-Identifier: Apache-2.0
"""
This is a simple example of how to use napalm-srlinux.
First, deploy the SR Linux container using containerlab:

```
CLAB_LABDIR_BASE=/tmp \
sudo -E clab deploy -c -t srlinux.dev/clab-srl
```

Then uncomment the NAPALM API calls that you want to run and run this script:

python examples/example.py
"""

from napalm import get_network_driver

# using rich to pretty print the output
# feel free to remove it if you don't want to install it
from rich import print_json

driver = get_network_driver("srlinux")
optional_args = {
    # "jsonrpc_port": 80,
    # "skip_verify": True,
    "insecure": True
}
with driver("srl", "admin", "NokiaSrl1!", optional_args=optional_args) as device:
    # print_json(data=device.get_bgp_config(neighbor="", group="")) #Done
    # print_json(data=device.get_bgp_config(neighbor="", group="ebgp")) #Done
    # print_json(data=device.get_bgp_config(neighbor="10.1.1.2", group="")) #Done
    # print_json(data=device.get_config(retrieve="all", full=False, sanitized=False))
    # print_json(data=device.get_config(retrieve="running", full=False, sanitized=False))
    # print_json(data=device.get_config(retrieve="candidate", full=False, sanitized=False))
    # print_json(data=device.get_config(retrieve="state", full=False, sanitized=False))
    # print_json(data=device.get_ntp_stats())
    # print_json(data=device.get_optics())
    # print_json(data=device.get_route_to())
    # print_json(data=device.get_route_to("1.0.4.0/24"))
    # print_json(data=device.get_route_to("100.100.100.100"))
    # print_json(data=device.get_route_to(destination="172.20.20.0/24"))
    # print_json(data=device.get_route_to(protocol="bgp"))
    # print_json(data=device.get_route_to(protocol="host"))
    # print_json(data=device.get_mac_address_table()) #Done
    # print_json(data=device.get_snmp_information())
    # print(device.is_alive())
    # print_json(data=device.cli(["date","info system information","show network-instance default protocols bgp neighbor"]))
    # print(device.load_merge_candidate(filename="/root/syed/backup/napalm-srl-dev/demo_merge.json"))
    # print(device.load_replace_candidate(filename="/home/nuage/json_compare/srl2_2000_Ori_WithBGP.json"))
    # print_json(data=device.commit_config("test commit"))
    # print_json(data=device.compare_config())
    # print_json(data=device.discard_config())
    # print_json(data=device.rollback())
    # print_json(data=device.ping(destination="11.1.1.2"))
    # print_json(data=device.ping(destination="11.1.1.2",source="10.1.1.1",ttl=2, timeout=2, size=64, count=2, vrf="default"))
    # print_json(data=device.traceroute(destination="11.1.1.2",vrf = ""))
    # print_json(data=device.traceroute(destination="21.1.1.2",ttl=5, vrf = "ip_vrf1"))
    # print_json(data=device.get_arp_table())
    # print_json(data=device.get_arp_table("ip_vrf1"))
    # print_json(data=device.get_bgp_neighbors())
    # print_json(data=device.get_bgp_neighbors_detail())
    # print_json(data=device.get_bgp_neighbors_detail("10.1.1.2"))
    # print_json(data=device.get_environment())
    # print_json(data=device.get_facts())
    # print_json(data=device.get_interfaces())
    # print_json(data=device.get_interfaces_counters())
    # print_json(data=device.get_interfaces_ip())
    # print_json(data=device.get_ipv6_neighbors_table())#----------TBD
    # print_json(data=device.get_lldp_neighbors())
    # print_json(data=device.get_lldp_neighbors_detail())
    # print_json(data=device.get_lldp_neighbors_detail("ethernet-1/3"))
    # print_json(data=device.get_network_instances())
    # print_json(data=device.get_network_instances())
    print_json(data=device.get_users())
    # print_json(data=device.test())
