#!/usr/bin/python3

# End-to-end test of get_vlans: configure a mac-vrf with a single-tagged
# bridged subinterface, check the reported VLAN and roll the change back.

import logging
import sys

from napalm import get_network_driver

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

driver = get_network_driver("srlinux")
optional_args = {"insecure": True}
device = driver("clab-napalm-ci_cd-srl", "admin", "NokiaSrl1!", 10, optional_args)
device.open()

cfg = """
set / interface ethernet-1/4 admin-state enable
set / interface ethernet-1/4 vlan-tagging true
set / interface ethernet-1/4 subinterface 100 type bridged
set / interface ethernet-1/4 subinterface 100 admin-state enable
set / interface ethernet-1/4 subinterface 100 vlan encap single-tagged vlan-id 100
set / network-instance vlantest type mac-vrf admin-state enable
set / network-instance vlantest interface ethernet-1/4.100
"""

device.load_merge_candidate(config=cfg)
device.commit_config()

vlans = device.get_vlans()
print(vlans)
assert 100 in vlans
assert vlans[100]["name"] == "vlantest"
assert "ethernet-1/4.100" in vlans[100]["interfaces"]

# revert and check the VLAN is gone again
device.rollback()
assert 100 not in device.get_vlans()

device.close()
sys.exit(0)  # Success
