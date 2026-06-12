# Copyright 2024 Nokia
# Licensed under the Apache License 2.0.
# SPDX-License-Identifier: Apache-2.0

"""Test fixtures."""

import os
import sys

import pytest
from napalm.base.test import conftest as parent_conftest
from napalm.base.test.double import BaseTestDouble

from napalm_srlinux import srlinux

sys.path.insert(0, os.path.dirname(__file__))
from fixture_names import fixture_name_for_cli, fixture_name_for_get  # noqa: E402


@pytest.fixture(scope="session", autouse=True)
def setenv():
    # Set timezone such that timestamps are generated/parsed correctly
    os.environ["TZ"] = "GMT"


@pytest.fixture(scope="class")
def set_device_parameters(request):
    """Set up the class."""

    def fin():
        request.cls.device.close()

    request.addfinalizer(fin)

    request.cls.driver = srlinux.NokiaSRLinuxDriver
    request.cls.patched_driver = PatchedNokiaSRLinuxDriver
    request.cls.vendor = "srlinux"
    parent_conftest.set_device_parameters(request)


def pytest_generate_tests(metafunc):
    """Generate test cases dynamically."""
    parent_conftest.pytest_generate_tests(metafunc, __file__)


class PatchedNokiaSRLinuxDriver(srlinux.NokiaSRLinuxDriver):
    """NokiaSRLinuxDriver with a fake JSON-RPC device."""

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        super().__init__(hostname, username, password, timeout, optional_args)

        self.patched_attrs = ["device"]
        self.device = FakeSRLinuxDevice()


class FakeSRLinuxDevice(BaseTestDouble):
    """Fake SRLinuxDevice that serves JSON-RPC results from fixture files.

    Fixture files contain the verbatim "result" array of the corresponding
    JSON-RPC response, named after the request (see fixture_names.py).
    """

    def open(self):
        pass

    def close(self):
        pass

    def is_alive(self):
        return True

    def get_paths(self, paths, datastore):
        full_path = self.find_file(fixture_name_for_get(paths, datastore))
        return self.read_json_file(full_path)

    def run_cli_commands(self, commands, output_format="text"):
        full_path = self.find_file(fixture_name_for_cli(commands))
        return self.read_json_file(full_path)

    def set_paths(self, commands, datastore=None, confirm_timeout=None):
        return {}

    def validate_paths(self, commands):
        return {}

    def diff_paths(self, commands, output_format="text"):
        full_path = self.find_file("diff.json")
        return self.read_json_file(full_path)
