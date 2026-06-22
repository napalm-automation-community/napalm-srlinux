# Copyright 2024 Nokia
# Licensed under the Apache License 2.0.
# SPDX-License-Identifier: Apache-2.0

"""Deterministic mapping from JSON-RPC requests to mocked-data fixture filenames.

Shared between the fake test device (test/unit/conftest.py) and the fixture
recorder (tools/record_fixtures.py) so that recorded fixtures land exactly where
the tests look for them.
"""

import re


def _sanitize(text: str) -> str:
    """Same sanitization as napalm.base.test.double.BaseTestDouble.sanitize_text."""
    return re.sub("[^a-zA-Z0-9]", "_", text)[0:150]


def fixture_name_for_get(paths: list[str], datastore) -> str:
    """Fixture filename for a get_paths(paths, datastore) request."""
    datastore_value = getattr(datastore, "value", datastore)
    return f"{_sanitize('_'.join(paths))}__{datastore_value}.json"


def fixture_name_for_cli(commands: list[str]) -> str:
    """Fixture filename for a run_cli_commands(commands) request."""
    return f"{_sanitize('_'.join(commands))}__cli.json"
