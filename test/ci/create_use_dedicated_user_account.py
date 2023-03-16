#!/usr/bin/python3

# Creates a dedicated 'napalm' user account and accesses it

import json
import sys
from napalm import get_network_driver

driver = get_network_driver("srl")
optional_args = {
    "gnmi_port": 57400,
    "jsonrpc_port": 443,
    "insecure": True,
    "encoding": "JSON_IETF"
}
device = driver("clab-napalm-ci_cd-srl", "admin", "NokiaSrl1!", 10, optional_args)
device.open()
#print(device.get_facts())
#print(device.get_optics())
cfg = """
set /system configuration role napalm rule / action write
set /system aaa authorization role napalm services [ gnmi json-rpc ]
set /system aaa authentication user napalm password "NAPALM" role [ napalm ]
"""
device.load_merge_candidate(config=cfg) # CLI format
device.commit_config()

# get config -> check that AAA is set
config = device.get_config()
parsed = json.loads(config["running"])
print( json.dumps(parsed["srl_nokia-system:system"],indent=2) )
device.close()

# Use the newly created user account
device2 = driver("clab-napalm-ci_cd-srl", "napalm", "NAPALM", 10, optional_args)
device2.open()
config = device2.get_config()
parsed2 = json.loads(config["running"])
print( json.dumps(parsed2["srl_nokia-system:system"],indent=2) )
device2.close()

sys.exit(0) # Success
