#!/usr/bin/python3

"""End-to-end test of the commit-confirm workflow: commit_config(revert_in=...),
has_pending_commit, confirm_commit, rollback-while-pending and the automatic
revert when the timer expires. Exercises both the JSON candidate mode
(JSON-RPC confirm-timeout) and the CLI candidate mode (commit confirmed).

Run via pytest (clean output) or as a plain script (used by `make run-tests`):

    uv run pytest test/ci/commit_confirm.py
    uv run test/ci/commit_confirm.py
"""

import json
import time

import pytest
from napalm import get_network_driver
from napalm.base.exceptions import CommitError

HOST = "clab-napalm-ci_cd-srl"


@pytest.fixture(scope="module")
def device():
    dev = get_network_driver("srlinux")(HOST, "admin", "NokiaSrl1!", 10, {"insecure": True})
    dev.open()
    try:
        yield dev
    finally:
        dev.close()


def test_commit_confirm_workflow(device):
    def running_description() -> str:
        parsed = json.loads(device.get_config(retrieve="running")["running"])
        return parsed["srl_nokia-interfaces:interface"][0].get("description", "")

    def merge_description(desc: str) -> None:
        device.load_merge_candidate(
            config=json.dumps({"interface": [{"name": "ethernet-1/1", "description": desc}]})
        )

    # --- baseline: a plain commit, no confirm pending
    merge_description("commit-confirm baseline")
    device.commit_config()
    assert not device.has_pending_commit()
    assert running_description() == "commit-confirm baseline"

    # --- confirm_commit without a pending confirm raises
    with pytest.raises(CommitError):
        device.confirm_commit()

    # --- JSON mode: commit with revert timer, then confirm
    merge_description("confirmed change")
    device.commit_config(revert_in=120)
    assert device.has_pending_commit()
    assert running_description() == "confirmed change"

    # a second commit while the confirm is pending must be refused
    merge_description("should be refused")
    with pytest.raises(CommitError):
        device.commit_config()
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


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__]))
