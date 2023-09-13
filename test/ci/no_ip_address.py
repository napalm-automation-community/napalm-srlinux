#!/usr/bin/python3

# Tests what happens if no IP address is enabled on an interface

import json
import sys
from napalm import get_network_driver

driver = get_network_driver("srl")
optional_args = {
    "gnmi_port": 57400,
    "jsonrpc_port": 443,
    "insecure": False,
    "encoding": "JSON_IETF"
}
device = driver("clab-napalm-ci_cd-srl", "admin", "NokiaSrl1!", 10, optional_args)
device.open()
#print(device.get_facts())
#print(device.get_optics())
cfg = """
set /interface system0 admin-state enable subinterface 0
"""
device.load_merge_candidate(config=cfg) # CLI format
device.commit_config()

ips = device.get_interfaces_ip()
print( json.dumps(ips,indent=2) )

device.close()

sys.exit(0) # Success
