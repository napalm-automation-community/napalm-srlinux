#!/usr/bin/python3

import json
import sys
from napalm import get_network_driver
from datetime import datetime

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
now = datetime.now().strftime("%H:%M:%S")
DESC = f"Time {now}"
cfg = f"""
set /interface ethernet-1/1 description "{DESC}"
"""
device.load_merge_candidate(config=cfg) # CLI format
device.commit_config()

# get config -> check that description is set
config = device.get_config()
parsed = json.loads(config["running"])
print( json.dumps(parsed["srl_nokia-interfaces:interface"],indent=2) )
assert( parsed["srl_nokia-interfaces:interface"][0]["description"] == DESC )

cfg2 = {
 "interface": [
  { "name": "ethernet-1/1", "description": f"{DESC} using JSON" }
 ]
}
device.load_merge_candidate(config=json.dumps(cfg2)) # JSON format
device.commit_config()

# get config -> check that description is set
config2 = device.get_config()
parsed2 = json.loads(config2["running"])
print( json.dumps(parsed2["srl_nokia-interfaces:interface"],indent=2) )
assert( parsed2["srl_nokia-interfaces:interface"][0]["description"] == cfg2["interface"][0]["description"] )

# Revert changes in most recent commit_config
reply = device.rollback()
print( reply )

config3 = device.get_config()
parsed3 = json.loads(config3["running"])
assert( parsed3["srl_nokia-interfaces:interface"][0]["description"] == DESC )

device.close()

# Regression: check that is_alive returns false
assert( not device.is_alive() )

sys.exit(0) # Success
