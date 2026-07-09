#!/usr/bin/python3

"""Creates a dedicated 'napalm' user account and connects with it.

Run via pytest (clean output) or as a plain script (used by `make run-tests`):

    uv run pytest test/ci/create_use_dedicated_user_account.py
    uv run test/ci/create_use_dedicated_user_account.py
"""

import pytest
from napalm import get_network_driver

HOST = "clab-napalm-ci_cd-srl"

USER_CONFIG = """
set / system configuration role napalm rule / action write
set / system aaa authorization role napalm services [ json-rpc ]
set / system aaa authentication user napalm password "NapalmTest1!" role [ napalm ]
"""


@pytest.fixture(scope="module")
def device():
    dev = get_network_driver("srlinux")(HOST, "admin", "NokiaSrl1!", 10, {"insecure": True})
    dev.open()
    try:
        yield dev
    finally:
        dev.close()


def test_create_and_use_dedicated_user(device):
    device.load_merge_candidate(config=USER_CONFIG)
    device.commit_config()
    try:
        # connect and read the config as the newly created user
        napalm_user = get_network_driver("srlinux")(
            HOST, "napalm", "NapalmTest1!", 10, {"insecure": True}
        )
        napalm_user.open()
        try:
            assert napalm_user.get_config()["running"]
        finally:
            napalm_user.close()
    finally:
        # remove the dedicated account again
        device.rollback()


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__]))
