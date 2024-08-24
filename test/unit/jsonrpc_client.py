"""
Determines the JSON-RPC port to use based on the provided configuration.

Args:
    config (dict): A dictionary containing the configuration options.

Returns:
    int: The JSON-RPC port to use.
"""

import pytest

from napalm_srlinux.srlinux import NokiaSRLinuxDriver


@pytest.fixture
def driver():
    return NokiaSRLinuxDriver("hostname", "username", "password")


def test_determine_jsonrpc_port(driver):
    # Test default case
    assert driver._determine_jsonrpc_port({}) == 443

    # Test when jsonrpc_port is specified
    assert driver._determine_jsonrpc_port({"jsonrpc_port": 8080}) == 8080

    # Test when insecure is set and jsonrpc_port is not specified
    assert driver._determine_jsonrpc_port({"insecure": True}) == 80

    # Test when both jsonrpc_port and insecure are set
    assert (
        driver._determine_jsonrpc_port({"jsonrpc_port": 9000, "insecure": True}) == 9000
    )
