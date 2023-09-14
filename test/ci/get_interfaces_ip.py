#!/usr/bin/python3

import sys
from napalm import get_network_driver

import logging
logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

driver = get_network_driver("srl")
optional_args = {
    "gnmi_port": 57400,
    "jsonrpc_port": 443,
    "insecure": True,
    "encoding": "JSON_IETF"
}

device = driver("clab-napalm-ci_cd-srl", "admin", "NokiaSrl1!", 10, optional_args)

device.open()

# Add system0 interface with subinterface 0 and no ip addresses
cfg = """
set / interface system0
set / interface system0 admin-state enable
set / interface system0 subinterface 0
"""

device.load_merge_candidate(config=cfg)
device.commit_config()

# get_interfaces_ip() should not fail when no ip addresses are present
ip_addresses = device.get_interfaces_ip()

assert(ip_addresses.get("system0.0") == {})
assert(ip_addresses is not None)
