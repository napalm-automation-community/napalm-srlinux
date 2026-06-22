# Copyright 2024 Nokia
# Licensed under the Apache License 2.0.
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the cli() method's text and json encodings."""

import pytest

from napalm_srlinux.srlinux import NokiaSRLinuxDriver

JSON_RESULT = {"basic system info": {"Hostname": "srl", "Software Version": "v25.10.1"}}


class StubDevice:
    """Stub device returning canned per-command results."""

    def __init__(self):
        self.requests = []

    def run_cli_commands(self, commands, output_format="text"):
        self.requests.append((commands, output_format))
        if output_format == "json":
            return [JSON_RESULT for _ in commands]
        return [{"text": f"output of {c}"} for c in commands]


@pytest.fixture
def driver():
    drv = NokiaSRLinuxDriver("srl", "admin", "admin")
    drv.device = StubDevice()
    return drv


def test_text_encoding_returns_per_command_text(driver):
    output = driver.cli(["show version", "show platform"])
    assert output == {
        "show version": "output of show version",
        "show platform": "output of show platform",
    }
    # one request per command to preserve the per-command mapping
    assert driver.device.requests == [
        (["show version"], "text"),
        (["show platform"], "text"),
    ]


def test_json_encoding_returns_structured_result(driver):
    output = driver.cli(["show version"], encoding="json")
    assert output == {"show version": JSON_RESULT}
    assert driver.device.requests == [(["show version"], "json")]


def test_unsupported_encoding_raises(driver):
    with pytest.raises(NotImplementedError):
        driver.cli(["show version"], encoding="xml")
    assert driver.device.requests == []
