# Copyright 2020 Nokia
# Licensed under the Apache License 2.0.
# SPDX-License-Identifier: Apache-2.0

"""Test fixtures."""
from builtins import super

import pytest
from napalm.base.test import conftest as parent_conftest

from napalm.base.test.double import BaseTestDouble

from napalm_srl import srl
import json

@pytest.fixture(scope='class')
def set_device_parameters(request):
    """Set up the class."""
    def fin():
        request.cls.device.close()
    request.addfinalizer(fin)

    request.cls.driver = srl.NokiaSRLDriver
    request.cls.patched_driver = PatchedsrlDriver
    request.cls.vendor = 'srl'
    parent_conftest.set_device_parameters(request)


def pytest_generate_tests(metafunc):
    """Generate test cases dynamically."""
    parent_conftest.pytest_generate_tests(metafunc, __file__)


class PatchedsrlDriver(srl.NokiaSRLDriver):
    """Patched Skeleton Driver."""

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        """Patched Skeleton Driver constructor."""
        super().__init__(hostname, username, password, timeout, optional_args)

        self.patched_attrs = ['device']
        self.device = FakesrlDevice()


class FakesrlDevice(BaseTestDouble):

    def _jsonrpcRunCli(self, command_list):
        """Fake run_commands."""
        #
        out = []
        for command in command_list:
            filename = command.split(" ")[0] + ".txt"
            full_path = self.find_file(filename)
            with open(full_path) as f:
                out.append(json.load(f))
        result = {
            "result":out
        }
        print(result)
        return result

    def _gnmiGet(self, prefix, path, pathType):
        path = str(sorted(path)).strip("{}'")
        filename = "{}.txt".format(self.sanitize_text(path))
        full_path = self.find_file(filename)
        with open(full_path) as f:
            output = json.load(f)
        return output

    def open(self):
        pass
    def close(self):
        pass


    def _jsonrpcGet(self,cmds, other_params=None):
        filename = "{}.txt".format(self.sanitize_text(str(sorted(cmds)).strip("{}' ")))
        full_path = self.find_file(filename)
        with open(full_path) as f:
            output = json.load(f)
        return output

