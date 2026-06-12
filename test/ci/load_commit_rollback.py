#!/usr/bin/python3

# End-to-end test of the candidate config workflow: CLI merge, JSON merge,
# compare, commit and rollback.

import json
import logging
import sys
from datetime import datetime

from napalm import get_network_driver

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

driver = get_network_driver("srlinux")
optional_args = {"insecure": True}
device = driver("clab-napalm-ci_cd-srl", "admin", "NokiaSrl1!", 10, optional_args)
device.open()

now = datetime.now().strftime("%H:%M:%S")
DESC = f"Time {now}"
cfg = f"""
set / interface ethernet-1/1 description "{DESC}"
"""

device.load_merge_candidate(config=cfg)  # CLI format
diff = device.compare_config()
print(f"CLI diff:\n{diff}")
assert DESC in diff
device.commit_config()

# get config -> check that description is set
config = device.get_config()
parsed = json.loads(config["running"])
print(json.dumps(parsed["srl_nokia-interfaces:interface"], indent=2))
assert parsed["srl_nokia-interfaces:interface"][0]["description"] == DESC

cfg2 = {"interface": [{"name": "ethernet-1/1", "description": f"{DESC} using JSON"}]}
device.load_merge_candidate(config=json.dumps(cfg2))  # JSON format
diff2 = device.compare_config()
print(f"JSON diff:\n{diff2}")
device.commit_config()

# get config -> check that description is set
config2 = device.get_config()
parsed2 = json.loads(config2["running"])
print(json.dumps(parsed2["srl_nokia-interfaces:interface"], indent=2))
assert (
    parsed2["srl_nokia-interfaces:interface"][0]["description"]
    == cfg2["interface"][0]["description"]
)

# Revert changes in most recent commit_config
device.rollback()

config3 = device.get_config()
parsed3 = json.loads(config3["running"])
assert parsed3["srl_nokia-interfaces:interface"][0]["description"] == DESC

device.close()

# Regression: check that is_alive returns false after close
assert not device.is_alive()["is_alive"]

sys.exit(0)  # Success
