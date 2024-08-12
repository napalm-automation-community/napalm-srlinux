# Copyright 2021 Nokia. All rights reserved.
# Copyright 2015 Spotify AB. All rights reserved.
#
# The contents of this file are licensed under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with the
# License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.

import unittest
import pytest
from napalm_srlinux import srlinux
from napalm.base.test.base import TestConfigNetworkDriver
from napalm.base.exceptions import (
    MergeConfigException,
)
class TestConfigSRLDriver(unittest.TestCase, TestConfigNetworkDriver):
    @classmethod
    def setUpClass(cls):
        hostname = "172.20.20.10"
        username = "admin"
        password = "admin"
        cls.vendor = "test/unit/" + "srl" #to facilitate executing test without errors prepended path

        optional_args = {
            "port": 57400,
            "target_name": "srl",
            "tls_cert":"/root/gnmic_certs/srl_certs/clientCert.crt",
            "tls_ca": "/etc/containerlab/lab-examples/srlceos01/clab-srlceos01/ca/root/root-ca.pem",
            "tls_key": "/root/gnmic_certs/srl_certs/clientKey.pem",
            # "skip_verify": True,
            # "insecure": False
            "encoding": "JSON_IETF"
        }
        cls.device = srl.NokiaSRLinuxDriver(
            hostname, username, password, timeout=60, optional_args=optional_args
        )
        cls.device.open()

        cls.device.load_replace_candidate(filename="%s/initial.conf" % cls.vendor)
        #auto commit for load replace
        #cls.device.commit_config()

    def test_merge_configuration(self):
        intended_diff = self.read_file("%s/merge_good.diff" % self.vendor)

        self.device.load_merge_candidate(filename="%s/merge_good.conf" % self.vendor)
        #self.device.commit_config()

        # Reverting changes

        diff = self.device.compare_config()
        print(diff)

        self.device.load_replace_candidate(filename="%s/initial.conf" % self.vendor)
        # auto commit for load_replace

        self.assertEqual(str(diff).strip(), intended_diff)

    def test_merge_configuration_typo_and_rollback(self):
        #because of autocommit in load_replace_candidate -  this requires a discard_config before test begins
        result = False
        try:
            self.device.discard_config()
            self.device.load_merge_candidate(
                filename="%s/merge_typo.conf" % self.vendor
            )
            self.device.compare_config()
            self.device.commit_config()
            raise Exception("We shouldn't be here")
        except MergeConfigException:
            # We load the original config as candidate. If the commit failed cleanly the
            # compare_config should be empty
            self.device.load_replace_candidate(filename="%s/initial.conf" % self.vendor)
            result = self.device.compare_config() == ""
            self.device.discard_config()

        self.assertTrue(result)

    def test_load_template(self):
        pytest.skip("Method not implemented")

    def test_replacing_config_and_diff_and_discard(self):
        # because of autocommit in load_replace_candidate -  this test case cannot be passed
        pytest.skip("Constraint due to auto commit in load_replace_candidate")

		