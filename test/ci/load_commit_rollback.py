#!/usr/bin/python3

from napalm import get_network_driver
import json, time, sys
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

reply = device.rollback()
print( reply )

config2 = device.get_config()
parsed2 = json.loads(config2["running"])
assert( parsed2["srl_nokia-interfaces:interface"][0]["description"] != DESC )

device.close()

sys.exit(0) # Success
