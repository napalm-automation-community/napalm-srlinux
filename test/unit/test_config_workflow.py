# Copyright 2024 Nokia
# Licensed under the Apache License 2.0.
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the client-side candidate config workflow.

These tests assert the request shapes sent to the device for the
load -> compare -> commit -> rollback lifecycle, using a recording stub.
"""

import json

import pytest
from napalm.base.exceptions import (
    CommandErrorException,
    CommitConfirmException,
    CommitError,
    MergeConfigException,
    ReplaceConfigException,
)

from napalm_srlinux.srlinux import NokiaSRLinuxDriver

JSON_CONFIG = json.dumps({"system": {"information": {"location": "lab"}}})
GNMI_STYLE_CONFIG = json.dumps(
    {
        "updates": [{"path": "/system/information", "value": {"location": "lab"}}],
        "deletes": [{"path": "/system/banner"}],
    }
)
CLI_CONFIG = "set / system information location lab\nset / system information contact ops"
JSON_CONFIG_2 = json.dumps({"system": {"information": {"contact": "ops"}}})
CLI_CONFIG_2 = "set / system information contact ops2"


class RecordingDevice:
    """Stub device recording every RPC the driver makes."""

    def __init__(self):
        self.calls = []
        self.validate_error = None
        # device-side pending confirmed commit, reflected in the commit list
        self.pending = False

    def open(self):
        pass

    def close(self):
        pass

    def get_paths(self, paths, datastore):
        self.calls.append(("get", paths, datastore))
        results = []
        for path in paths:
            if path.startswith("/system/configuration/commit"):
                status = "unconfirmed" if self.pending else "complete"
                results.append({"srl_nokia-configuration:commit": [{"id": 1, "status": status}]})
            else:
                results.append({})
        return results

    def run_cli_commands(self, commands, output_format="text"):
        self.calls.append(("cli", commands))
        return [{"text": f"output of {c}"} for c in commands]

    def set_paths(self, commands, datastore=None, confirm_timeout=None):
        self.calls.append(("set", commands, datastore, confirm_timeout))
        return {}

    def validate_paths(self, commands):
        self.calls.append(("validate", commands))
        if self.validate_error:
            raise self.validate_error
        return {}

    def diff_paths(self, commands, output_format="text"):
        self.calls.append(("diff", commands))
        return [{"text": "+ location lab"}]


@pytest.fixture
def driver():
    drv = NokiaSRLinuxDriver("srl", "admin", "admin")
    drv.device = RecordingDevice()
    return drv


class TestLoadCandidate:
    def test_load_merge_json_validates_on_load(self, driver):
        driver.load_merge_candidate(config=JSON_CONFIG)
        kinds = [c[0] for c in driver.device.calls]
        assert kinds == ["validate"]
        commands = driver.device.calls[0][1]
        assert commands == [{"action": "update", "path": "/", "value": json.loads(JSON_CONFIG)}]

    def test_load_replace_json_uses_replace_action(self, driver):
        driver.load_replace_candidate(config=JSON_CONFIG)
        commands = driver.device.calls[0][1]
        assert commands[0]["action"] == "replace"
        assert commands[0]["path"] == "/"

    def test_load_gnmi_style_envelope(self, driver):
        driver.load_merge_candidate(config=GNMI_STYLE_CONFIG)
        commands = driver.device.calls[0][1]
        assert {"action": "delete", "path": "/system/banner"} in commands
        assert {
            "action": "update",
            "path": "/system/information",
            "value": {"location": "lab"},
        } in commands

    def test_load_replace_rejects_updates_and_deletes(self, driver):
        with pytest.raises(ReplaceConfigException):
            driver.load_replace_candidate(config=GNMI_STYLE_CONFIG)

    def test_validation_failure_raises_merge_exception(self, driver):
        driver.device.validate_error = CommandErrorException("invalid path")
        with pytest.raises(MergeConfigException, match="invalid path"):
            driver.load_merge_candidate(config=JSON_CONFIG)
        assert driver._candidate is None

    def test_load_cli_config_does_not_touch_device(self, driver):
        driver.load_merge_candidate(config=CLI_CONFIG)
        assert driver.device.calls == []
        assert driver._candidate["mode"] == "cli"
        assert len(driver._candidate["lines"]) == 2

    def test_load_without_config_or_filename_raises(self, driver):
        with pytest.raises(MergeConfigException):
            driver.load_merge_candidate()

    def test_merge_then_merge_json_accumulates(self, driver):
        driver.load_merge_candidate(config=JSON_CONFIG)
        driver.load_merge_candidate(config=JSON_CONFIG_2)
        assert driver._candidate["mode"] == "json"
        assert driver._candidate["commands"] == [
            {"action": "update", "path": "/", "value": json.loads(JSON_CONFIG)},
            {"action": "update", "path": "/", "value": json.loads(JSON_CONFIG_2)},
        ]
        # the second load re-validates the full accumulated candidate, i.e.
        # exactly what commit_config would send
        assert [c[0] for c in driver.device.calls] == ["validate", "validate"]
        assert driver.device.calls[1][1] == driver._candidate["commands"]

    def test_merge_then_merge_cli_accumulates(self, driver):
        driver.load_merge_candidate(config=CLI_CONFIG)
        driver.load_merge_candidate(config=CLI_CONFIG_2)
        assert driver._candidate["mode"] == "cli"
        assert driver._candidate["lines"] == (CLI_CONFIG.splitlines() + CLI_CONFIG_2.splitlines())
        # CLI candidates never touch the device on load
        assert driver.device.calls == []

    def test_merge_validates_combined_candidate(self, driver):
        # a merge may depend on config staged by the replace baseline, so the
        # merge-time validation must carry the baseline as well
        driver.load_replace_candidate(config=JSON_CONFIG)
        driver.load_merge_candidate(config=JSON_CONFIG_2)
        validates = [c for c in driver.device.calls if c[0] == "validate"]
        assert validates[-1][1] == [
            {"action": "replace", "path": "/", "value": json.loads(JSON_CONFIG)},
            {"action": "update", "path": "/", "value": json.loads(JSON_CONFIG_2)},
        ]

    def test_replace_after_merge_resets(self, driver):
        driver.load_merge_candidate(config=JSON_CONFIG)
        driver.load_replace_candidate(config=JSON_CONFIG_2)
        assert driver._candidate["commands"] == [
            {"action": "replace", "path": "/", "value": json.loads(JSON_CONFIG_2)}
        ]
        assert driver._candidate["replace"] is True

    def test_replace_resets_across_formats(self, driver):
        # a replace may use a different format than the pending candidate,
        # since it discards it and starts fresh
        driver.load_merge_candidate(config=CLI_CONFIG)
        driver.load_replace_candidate(config=JSON_CONFIG)
        assert driver._candidate["mode"] == "json"
        assert driver._candidate["replace"] is True

    def test_merge_cli_into_json_candidate_raises(self, driver):
        driver.load_merge_candidate(config=JSON_CONFIG)
        with pytest.raises(MergeConfigException, match="discard"):
            driver.load_merge_candidate(config=CLI_CONFIG)
        # the pending JSON candidate is left intact
        assert driver._candidate["mode"] == "json"

    def test_merge_json_into_cli_candidate_raises(self, driver):
        driver.load_merge_candidate(config=CLI_CONFIG)
        with pytest.raises(MergeConfigException, match="discard"):
            driver.load_merge_candidate(config=JSON_CONFIG)
        assert driver._candidate["mode"] == "cli"
        # the format mismatch is detected before the fragment is validated,
        # so the failed load makes no device call
        assert driver.device.calls == []

    def test_failed_validation_on_second_load_keeps_first(self, driver):
        driver.load_merge_candidate(config=JSON_CONFIG)
        driver.device.validate_error = CommandErrorException("invalid path")
        with pytest.raises(MergeConfigException, match="invalid path"):
            driver.load_merge_candidate(config=JSON_CONFIG_2)
        # the first candidate survives a failed second load unchanged
        assert driver._candidate["commands"] == [
            {"action": "update", "path": "/", "value": json.loads(JSON_CONFIG)}
        ]


class TestIssue66:
    """Regression for issue #66: consecutive loads must accumulate, not raise.

    https://github.com/napalm-automation-community/napalm-srlinux/issues/66

    The reported sequence ``load_replace -> compare_config -> load_merge`` with
    no ``discard_config()`` in between used to fail with "A candidate config is
    already loaded; discard it first".
    """

    def test_replace_compare_merge_json(self, driver):
        driver.load_replace_candidate(config=JSON_CONFIG)
        driver.compare_config()
        driver.load_merge_candidate(config=JSON_CONFIG_2)  # no discard: used to raise

        commands = driver._candidate["commands"]
        assert commands[0] == {
            "action": "replace",
            "path": "/",
            "value": json.loads(JSON_CONFIG),
        }
        assert commands[-1] == {
            "action": "update",
            "path": "/",
            "value": json.loads(JSON_CONFIG_2),
        }
        assert driver._candidate["replace"] is True

        driver.commit_config()
        # the final set request carries the replace baseline plus the merge
        set_call = [c for c in driver.device.calls if c[0] == "set"][-1]
        assert set_call[1] == commands
        assert driver._candidate is None

    def test_replace_compare_merge_cli(self, driver):
        driver.load_replace_candidate(config=CLI_CONFIG)
        driver.compare_config()
        driver.load_merge_candidate(config=CLI_CONFIG_2)  # no discard: used to raise

        assert driver._candidate["replace"] is True
        assert driver._candidate["lines"] == (CLI_CONFIG.splitlines() + CLI_CONFIG_2.splitlines())

        driver.commit_config()
        commit_cmds = driver.device.calls[-1][1]
        first_set = CLI_CONFIG.splitlines()[0]
        last_set = CLI_CONFIG_2.splitlines()[0]
        # delete / (replace baseline) applied before both loads' set commands
        assert commit_cmds.index("delete /") < commit_cmds.index(first_set)
        assert commit_cmds.index(first_set) < commit_cmds.index(last_set)


class TestCompareConfig:
    def test_no_candidate_returns_empty_string(self, driver):
        assert driver.compare_config() == ""
        assert driver.device.calls == []

    def test_json_mode_uses_diff_method(self, driver):
        driver.load_merge_candidate(config=JSON_CONFIG)
        diff = driver.compare_config()
        assert diff == "+ location lab"
        assert driver.device.calls[-1][0] == "diff"

    def test_cli_mode_uses_named_candidate_with_cleanup(self, driver):
        driver.load_merge_candidate(config=CLI_CONFIG)
        result = driver.compare_config()
        kinds = [c[0] for c in driver.device.calls]
        assert kinds == ["cli", "cli", "cli"]  # reset, diff, cleanup
        reset, diff, cleanup = (c[1] for c in driver.device.calls)
        enter = f"enter candidate private name {driver._candidate_name}-diff"
        assert reset == [enter, "discard now"]
        assert diff[0] == enter
        assert diff[-1] == "diff"
        assert CLI_CONFIG.splitlines()[0] in diff
        assert cleanup == [enter, "discard now"]
        # the returned diff is the "diff" command's own result, not the
        # "enter candidate ..." command's (which is always first and empty)
        assert result == "output of diff"

    def test_cli_replace_mode_deletes_first(self, driver):
        driver.load_replace_candidate(config=CLI_CONFIG)
        driver.compare_config()
        commands = driver.device.calls[1][1]
        assert "delete /" in commands
        assert commands.index("delete /") < commands.index(CLI_CONFIG.splitlines()[0])


class TestCommitConfig:
    def test_commit_without_candidate_raises(self, driver):
        with pytest.raises(CommitError, match="No candidate"):
            driver.commit_config()

    def test_json_commit_checkpoints_then_sets(self, driver):
        driver.load_merge_candidate(config=JSON_CONFIG)
        driver.commit_config()
        kinds = [c[0] for c in driver.device.calls]
        assert kinds == ["validate", "get", "cli", "set"]
        checkpoint_cmds = driver.device.calls[2][1]
        assert f"generate-checkpoint name {driver._last_checkpoint}" in checkpoint_cmds[0]
        assert driver._candidate is None
        # unique per driver instance so concurrent/sequential sessions never
        # overwrite each other's rollback anchors on the device
        assert driver._last_checkpoint == f"{driver._checkpoint_prefix}-1"

    def test_cli_commit_single_request_with_message(self, driver):
        driver.load_merge_candidate(config=CLI_CONFIG)
        driver.commit_config(message="maintenance")
        kind, commands = driver.device.calls[-1]
        assert kind == "cli"
        assert commands[0] == f"enter candidate private name {driver._candidate_name}"
        assert commands[-1] == 'commit now comment "maintenance"'
        # a stale candidate with the same name is discarded beforehand
        discard = driver.device.calls[-2][1]
        assert discard == [commands[0], "discard now"]

    def test_cli_replace_commit_deletes_first(self, driver):
        driver.load_replace_candidate(config=CLI_CONFIG)
        driver.commit_config()
        commands = driver.device.calls[-1][1]
        assert "delete /" in commands

    def test_commit_save_mode(self, driver):
        driver.commit_mode = "save"
        driver.load_merge_candidate(config=JSON_CONFIG)
        driver.commit_config()
        assert ("cli", ["save startup"]) == driver.device.calls[-1]

    def test_checkpoint_names_increment(self, driver):
        driver.load_merge_candidate(config=JSON_CONFIG)
        driver.commit_config()
        driver.load_merge_candidate(config=JSON_CONFIG)
        driver.commit_config()
        assert driver._last_checkpoint == f"{driver._checkpoint_prefix}-2"


class TestDiscardAndRollback:
    def test_discard_clears_candidate_without_device_calls(self, driver):
        driver.load_merge_candidate(config=CLI_CONFIG)
        driver.discard_config()
        assert driver._candidate is None
        assert driver.device.calls == []

    def test_rollback_without_checkpoint_raises(self, driver):
        with pytest.raises(CommitError, match="No checkpoint"):
            driver.rollback()

    def test_rollback_loads_recorded_checkpoint(self, driver):
        driver.load_merge_candidate(config=JSON_CONFIG)
        driver.commit_config()
        driver.rollback()
        kind, commands = driver.device.calls[-1]
        assert kind == "cli"
        assert commands == [
            f"enter candidate private name {driver._candidate_name}",
            f"load checkpoint name {driver._last_checkpoint}",
            "commit now",
        ]


class TestCommitConfirm:
    def test_revert_in_passes_confirm_timeout(self, driver):
        driver.load_merge_candidate(config=JSON_CONFIG)
        driver.commit_config(revert_in=60)
        kinds = [c[0] for c in driver.device.calls]
        assert kinds == ["validate", "get", "cli", "set"]
        checkpoint_cmds = driver.device.calls[2][1]
        assert f"generate-checkpoint name {driver._last_checkpoint}" in checkpoint_cmds[0]
        assert driver.device.calls[-1][3] == 60  # confirm_timeout
        assert driver._pending_confirm is True

    def test_revert_in_defers_save(self, driver):
        driver.commit_mode = "save"
        driver.load_merge_candidate(config=JSON_CONFIG)
        driver.commit_config(revert_in=60)
        assert ["save startup"] not in [c[1] for c in driver.device.calls if c[0] == "cli"]

    def test_cli_mode_uses_commit_confirmed(self, driver):
        driver.load_merge_candidate(config=CLI_CONFIG)
        driver.commit_config(message="maintenance", revert_in=60)
        kind, commands = driver.device.calls[-1]
        assert kind == "cli"
        assert commands[-1] == "commit confirmed timeout 60"
        # 'commit confirmed' keeps the candidate session open on the device
        assert driver._pending_cli_candidate == commands[0]

    def test_confirm_after_cli_commit_closes_candidate(self, driver):
        driver.load_merge_candidate(config=CLI_CONFIG)
        driver.commit_config(revert_in=60)
        driver.device.pending = True
        driver.confirm_commit()
        assert driver._pending_cli_candidate is None
        assert driver.device.calls[-1][1] == [
            f"enter candidate private name {driver._candidate_name}",
            "discard now",
        ]

    def test_reject_after_cli_commit_closes_candidate(self, driver):
        driver.load_merge_candidate(config=CLI_CONFIG)
        driver.commit_config(revert_in=60)
        driver.device.pending = True
        driver.rollback()
        assert driver._pending_cli_candidate is None
        assert driver.device.calls[-1][1] == [
            f"enter candidate private name {driver._candidate_name}",
            "discard now",
        ]

    def test_commit_while_pending_raises(self, driver):
        driver.device.pending = True
        driver.load_merge_candidate(config=JSON_CONFIG)
        with pytest.raises(CommitError, match="already in process"):
            driver.commit_config()

    @pytest.mark.parametrize("revert_in", [0, -5, "60", 60.5])
    def test_invalid_revert_in_raises(self, driver, revert_in):
        driver.load_merge_candidate(config=JSON_CONFIG)
        with pytest.raises(CommitConfirmException):
            driver.commit_config(revert_in=revert_in)

    def test_has_pending_commit(self, driver):
        assert driver.has_pending_commit() is False
        driver.device.pending = True
        assert driver.has_pending_commit() is True

    def test_has_pending_commit_defensive_shapes(self, driver):
        for data in [{}, {"commit": {"id": 1, "status": "unconfirmed"}}, {"commit": None}]:
            driver.device.get_paths = lambda paths, datastore, d=data: [d]
            expected = data.get("commit") is not None
            assert driver.has_pending_commit() is expected

    def test_confirm_commit_accepts(self, driver):
        driver.device.pending = True
        driver.confirm_commit()
        kind, commands = driver.device.calls[-1]
        assert kind == "cli"
        assert commands == ["/tools system configuration confirmed-accept"]
        assert driver._pending_confirm is False

    def test_confirm_commit_saves_startup_in_save_mode(self, driver):
        driver.commit_mode = "save"
        driver.device.pending = True
        driver.confirm_commit()
        assert driver.device.calls[-1] == ("cli", ["save startup"])
        assert driver.device.calls[-2][1] == ["/tools system configuration confirmed-accept"]

    def test_confirm_commit_without_pending_raises(self, driver):
        with pytest.raises(CommitError, match="No pending"):
            driver.confirm_commit()

    def test_rollback_while_pending_rejects(self, driver):
        driver.load_merge_candidate(config=JSON_CONFIG)
        driver.commit_config(revert_in=60)
        driver.device.pending = True
        driver.rollback()
        kind, commands = driver.device.calls[-1]
        assert kind == "cli"
        assert commands == ["/tools system configuration confirmed-reject"]
        assert driver._pending_confirm is False
        # the checkpoint anchor is untouched and remains usable
        assert driver._last_checkpoint == f"{driver._checkpoint_prefix}-1"
