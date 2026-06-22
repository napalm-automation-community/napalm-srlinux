#!/usr/bin/python3

# End-to-end test of the commit-confirm workflow: commit_config(revert_in=...),
# has_pending_commit, confirm_commit, rollback-while-pending and the automatic
# revert when the timer expires. Exercises both the JSON candidate mode
# (JSON-RPC confirm-timeout) and the CLI candidate mode (commit confirmed).

import json
import logging
import sys
import time

from napalm import get_network_driver
from napalm.base.exceptions import CommitError

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

driver = get_network_driver("srlinux")
optional_args = {"insecure": True}
device = driver("clab-napalm-ci_cd-srl", "admin", "NokiaSrl1!", 10, optional_args)
device.open()


def running_description() -> str:
    config = device.get_config(retrieve="running")
    parsed = json.loads(config["running"])
    return parsed["srl_nokia-interfaces:interface"][0].get("description", "")


def merge_description(desc: str) -> None:
    cfg = {"interface": [{"name": "ethernet-1/1", "description": desc}]}
    device.load_merge_candidate(config=json.dumps(cfg))


# --- baseline: a plain commit, no confirm pending
merge_description("commit-confirm baseline")
device.commit_config()
assert not device.has_pending_commit()
assert running_description() == "commit-confirm baseline"

# --- confirm_commit without a pending confirm raises
try:
    device.confirm_commit()
    raise AssertionError("confirm_commit without pending confirm did not raise")
except CommitError:
    pass

# --- JSON mode: commit with revert timer, then confirm
merge_description("confirmed change")
device.commit_config(revert_in=120)
assert device.has_pending_commit()
assert running_description() == "confirmed change"

# a second commit while the confirm is pending must be refused
merge_description("should be refused")
try:
    device.commit_config()
    raise AssertionError("commit_config during pending confirm did not raise")
except CommitError:
    device.discard_config()

device.confirm_commit()
assert not device.has_pending_commit()
assert running_description() == "confirmed change"

# --- JSON mode: commit with revert timer, then reject via rollback()
merge_description("rejected change")
device.commit_config(revert_in=120)
assert device.has_pending_commit()
device.rollback()
assert not device.has_pending_commit()
assert running_description() == "confirmed change"

# --- CLI mode: verifies the 'commit confirmed timeout <s>' syntax per release
device.load_merge_candidate(
    config='set / interface ethernet-1/1 description "cli confirmed change"'
)
device.commit_config(revert_in=120)
assert device.has_pending_commit()
device.confirm_commit()
assert not device.has_pending_commit()
assert running_description() == "cli confirmed change"

# --- auto-revert: let the timer expire
merge_description("auto-reverted change")
device.commit_config(revert_in=20)
assert running_description() == "auto-reverted change"
deadline = time.time() + 90
while device.has_pending_commit():
    assert time.time() < deadline, "confirm timer did not expire in time"
    time.sleep(5)
# the revert itself can take a moment after the pending state clears
for _ in range(12):
    if running_description() == "cli confirmed change":
        break
    time.sleep(5)
assert running_description() == "cli confirmed change"

# regression: none of the above may leave the shared per-user candidate open —
# a later 'enter candidate private' would silently reuse its stale baseline
(candidates,) = device.device.get_paths(
    ["/system/configuration/candidate[name=*]"], device.device.Datastore.STATE
)
names = [c.get("name") for c in candidates.get("candidate", [])]
assert "private-admin" not in names, f"stale shared candidate left open: {names}"

device.close()
sys.exit(0)  # Success
