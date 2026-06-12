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


class RecordingDevice:
    """Stub device recording every RPC the driver makes."""

    def __init__(self):
        self.calls = []
        self.validate_error = None

    def open(self):
        pass

    def close(self):
        pass

    def get_paths(self, paths, datastore):
        self.calls.append(("get", paths, datastore))
        return [{} for _ in paths]

    def run_cli_commands(self, commands, output_format="text"):
        self.calls.append(("cli", commands))
        return [{"text": f"output of {c}"} for c in commands]

    def set_paths(self, commands, datastore=None, confirm_timeout=None):
        self.calls.append(("set", commands, datastore))
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
        assert commands == [
            {"action": "update", "path": "/", "value": json.loads(JSON_CONFIG)}
        ]

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

    def test_second_load_without_discard_raises(self, driver):
        driver.load_merge_candidate(config=CLI_CONFIG)
        with pytest.raises(MergeConfigException, match="already loaded"):
            driver.load_merge_candidate(config=CLI_CONFIG)

    def test_load_without_config_or_filename_raises(self, driver):
        with pytest.raises(MergeConfigException):
            driver.load_merge_candidate()


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
        driver.compare_config()
        kinds = [c[0] for c in driver.device.calls]
        assert kinds == ["cli", "cli", "cli"]  # reset, diff, cleanup
        reset, diff, cleanup = (c[1] for c in driver.device.calls)
        assert reset == ["enter candidate private name napalm-diff", "discard now"]
        assert diff[0] == "enter candidate private name napalm-diff"
        assert diff[-1] == "diff"
        assert CLI_CONFIG.splitlines()[0] in diff
        assert cleanup == ["enter candidate private name napalm-diff", "discard now"]

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

    def test_revert_in_not_supported(self, driver):
        driver.load_merge_candidate(config=JSON_CONFIG)
        with pytest.raises(NotImplementedError):
            driver.commit_config(revert_in=60)

    def test_json_commit_checkpoints_then_sets(self, driver):
        driver.load_merge_candidate(config=JSON_CONFIG)
        driver.commit_config()
        kinds = [c[0] for c in driver.device.calls]
        assert kinds == ["validate", "cli", "set"]
        checkpoint_cmds = driver.device.calls[1][1]
        assert "generate-checkpoint name NAPALM-1" in checkpoint_cmds[0]
        assert driver._candidate is None
        assert driver._last_checkpoint == "NAPALM-1"

    def test_cli_commit_single_request_with_message(self, driver):
        driver.load_merge_candidate(config=CLI_CONFIG)
        driver.commit_config(message="maintenance")
        kind, commands = driver.device.calls[-1]
        assert kind == "cli"
        assert commands[0] == "enter candidate private"
        assert commands[-1] == 'commit now comment "maintenance"'

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
        assert driver._last_checkpoint == "NAPALM-2"


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
            "enter candidate private",
            "load checkpoint name NAPALM-1",
            "commit now",
        ]
