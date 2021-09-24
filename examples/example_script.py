# Copyright 2020 Nokia
# Licensed under the Apache License 2.0.
# SPDX-License-Identifier: Apache-2.0

from napalm import get_network_driver
import json

driver = get_network_driver("srl")
optional_args = {
    "gnmi_port": 57400,
    "jsonrpc_port": 80,
    "target_name": "172.20.20.2",
    "tls_cert":"/root/gnmic_certs/srl_certs/clientCert.crt",
    "tls_ca": "/root/gnmic_certs/srl_certs/RootCA.crt",
    "tls_key": "/root/gnmic_certs/srl_certs/clientKey.pem",
     #"skip_verify": True,
     #"insecure": False
    "encoding": "JSON_IETF"
} 
device = driver("172.20.20.2", "admin", "admin", 60, optional_args)
device.open()
#print(json.dumps(device.get_bgp_config(neighbor="", group=""))) #Done
#print(json.dumps(device.get_bgp_config(neighbor="", group="ebgp"))) #Done
#print(json.dumps(device.get_bgp_config(neighbor="10.1.1.2", group=""))) #Done
#print(json.dumps(device.get_config(retrieve="all", full=False, sanitized=False)))
#print(json.dumps(device.get_config(retrieve="running", full=False, sanitized=False)))
#print(json.dumps(device.get_config(retrieve="candidate", full=False, sanitized=False))) 
#print(json.dumps(device.get_config(retrieve="state", full=False, sanitized=False)))
#print(json.dumps(device.get_ntp_stats()))
#print(json.dumps(device.get_optics()))
#print(json.dumps(device.get_route_to()))
#print(json.dumps(device.get_route_to("1.0.4.0/24")))
#print(json.dumps(device.get_route_to("100.100.100.100")))
#print(json.dumps(device.get_route_to(destination="172.20.20.0/24")))
#print(json.dumps(device.get_route_to(protocol="bgp")))
#print(json.dumps(device.get_route_to(protocol="host")))
#print(json.dumps(device.get_mac_address_table())) #Done
#print(json.dumps(device.get_snmp_information())) 
#print(device.is_alive())
#print(json.dumps(device.cli(["date","info system information","show network-instance default protocols bgp neighbor"])))
#print(device.load_merge_candidate(filename="/root/syed/backup/napalm-srl-dev/demo_merge.json"))
#print(device.load_replace_candidate(filename="/home/nuage/json_compare/srl2_2000_Ori_WithBGP.json"))
#print(json.dumps(device.commit_config("test commit")))
#print(json.dumps(device.compare_config()))
#print(json.dumps(device.discard_config()))
#print(json.dumps(device.rollback()))
#print(json.dumps(device.ping(destination="11.1.1.2")))
#print(json.dumps(device.ping(destination="11.1.1.2",source="10.1.1.1",ttl=2, timeout=2, size=64, count=2, vrf="default")))
#print(json.dumps(device.traceroute(destination="11.1.1.2",vrf = "")))
#print(json.dumps(device.traceroute(destination="21.1.1.2",ttl=5, vrf = "ip_vrf1")))
#print(json.dumps(device.get_arp_table()))
#print(json.dumps(device.get_arp_table("ip_vrf1")))
#print(json.dumps(device.get_bgp_neighbors()))
#print(json.dumps(device.get_bgp_neighbors_detail()))
#print(json.dumps(device.get_bgp_neighbors_detail("10.1.1.2")))
#print(json.dumps(device.get_environment()))
#print(json.dumps(device.get_facts())) 
#print(json.dumps(device.get_interfaces()))
#print(json.dumps(device.get_interfaces_counters()))
#print(json.dumps(device.get_interfaces_ip()))
#print(json.dumps(device.get_ipv6_neighbors_table()))#----------TBD
#print(json.dumps(device.get_lldp_neighbors()))
#print(json.dumps(device.get_lldp_neighbors_detail()))
#print(json.dumps(device.get_lldp_neighbors_detail("ethernet-1/3")))
#print(json.dumps(device.get_network_instances()))
#print(json.dumps(device.get_network_instances()))
#print(json.dumps(device.get_users()))
#print(json.dumps(device.test())) 

device.close()
