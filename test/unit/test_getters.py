# Copyright 2020 Nokia
# Licensed under the Apache License 2.0.
# SPDX-License-Identifier: Apache-2.0

"""Tests for getters."""

from napalm.base.test.getters import BaseTestGetters


import pytest


@pytest.mark.usefixtures("set_device_parameters")
class TestGetter(BaseTestGetters):
    """Test get_* methods."""
    def test_get_route_to_longer(self):
        pytest.skip("Longer option not Supported")
        return

