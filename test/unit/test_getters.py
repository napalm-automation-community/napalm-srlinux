# Copyright 2024 Nokia
# Licensed under the Apache License 2.0.
# SPDX-License-Identifier: Apache-2.0

"""Tests for getters.

Methods that SR Linux does not support (probes, vlans, firewall policies,
route_to with longer=True, ...) raise NotImplementedError and are skipped
automatically by the napalm test framework.
"""

import pytest
from napalm.base.test.getters import BaseTestGetters


@pytest.mark.usefixtures("set_device_parameters")
class TestGetter(BaseTestGetters):
    """Test get_* methods."""
