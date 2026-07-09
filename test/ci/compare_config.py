#!/usr/bin/python3

"""End-to-end test of compare_config() against a real SR Linux node.

Asserts the diff returned by the device matches a golden diff text word-by-word
for both the CLI and JSON candidate modes. Run it either way:

    uv run pytest test/ci/compare_config.py                         # clean output
    uv run pytest test/ci/compare_config.py --log-cli-level=DEBUG   # verbose
    uv run test/ci/compare_config.py                               # used by `make run-tests`
"""

import json

import pytest
from napalm import get_network_driver

HOST = "clab-napalm-ci_cd-srl"
BASE_DESC = "napalm-base"
CLI_DESC = "napalm-cli"
JSON_DESC = "napalm-json"

# Golden diffs recorded from a real SR Linux container. Compared word-by-word
# (whitespace-insensitive), so indentation is irrelevant, but the token
# sequence - including the '-'/'+' markers and the changed leaves - must match.
# SR Linux does not quote single-token description values in its diff output.
CLI_GOLDEN = f"""
      interface ethernet-1/1 {{
-         description {BASE_DESC}
+         description {CLI_DESC}
      }}
"""

JSON_GOLDEN = f"""
      interface ethernet-1/1 {{
-         description {BASE_DESC}
+         description {JSON_DESC}
      }}
"""


def assert_golden_diff(actual: str, golden: str) -> None:
    """Assert a device diff equals the golden text, compared word by word."""
    assert actual.split() == golden.split(), (
        f"diff mismatch\n--- actual ---\n{actual}\n--- golden ---\n{golden}"
    )


@pytest.fixture(scope="module")
def device():
    """Open the driver, commit a deterministic baseline, roll back on teardown."""
    dev = get_network_driver("srlinux")(HOST, "admin", "NokiaSrl1!", 30, {"insecure": True})
    dev.open()
    # commit_config checkpoints the pre-change state, so rollback() restores it.
    dev.load_merge_candidate(config=f'set / interface ethernet-1/1 description "{BASE_DESC}"')
    dev.commit_config()
    try:
        yield dev
    finally:
        dev.rollback()
        dev.close()


def test_cli_candidate_diff(device):
    """CLI candidate mode: the diff is the trailing "diff" command's own result."""
    device.load_merge_candidate(config=f'set / interface ethernet-1/1 description "{CLI_DESC}"')
    try:
        assert_golden_diff(device.compare_config(), CLI_GOLDEN)
    finally:
        device.discard_config()


def test_json_candidate_diff(device):
    """JSON candidate mode: the diff comes from the JSON-RPC "diff" method."""
    device.load_merge_candidate(
        config=json.dumps({"interface": [{"name": "ethernet-1/1", "description": JSON_DESC}]})
    )
    try:
        assert_golden_diff(device.compare_config(), JSON_GOLDEN)
    finally:
        device.discard_config()


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__]))
