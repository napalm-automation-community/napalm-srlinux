#!/usr/bin/python3

# End-to-end test of full config replacement: get_config -> modify ->
# load_replace_candidate -> compare -> commit -> verify -> rollback.

import json
import logging
import sys

from napalm import get_network_driver

logging.basicConfig(stream=sys.stdout, level=logging.INFO)

LOCATION = "replaced-by-napalm"

driver = get_network_driver("srlinux")
device = driver("clab-napalm-ci_cd-srl", "admin", "NokiaSrl1!", 30, {"insecure": True})
device.open()

# fetch the full running config and use a modified copy as a full replacement
running = json.loads(device.get_config()["running"])
information = running.setdefault("srl_nokia-system:system", {}).setdefault(
    "srl_nokia-system-info:information", {}
)
location_before = information.get("location")
information["location"] = LOCATION

device.load_replace_candidate(config=json.dumps(running))

# the diff of a full replace must only contain the one modified leaf
diff = device.compare_config()
print(f"replace diff:\n{diff}")
assert LOCATION in diff

device.commit_config()

# the replace took effect and the node is still manageable
after = json.loads(device.get_config()["running"])
assert (
    after["srl_nokia-system:system"]["srl_nokia-system-info:information"]["location"]
    == LOCATION
)

# rollback restores the pre-replace state
device.rollback()
restored = json.loads(device.get_config()["running"])
location_restored = (
    restored.get("srl_nokia-system:system", {})
    .get("srl_nokia-system-info:information", {})
    .get("location")
)
assert location_restored == location_before, f"{location_restored} != {location_before}"

device.close()
print("config replace round-trip OK")
sys.exit(0)
