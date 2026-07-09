#!/usr/bin/python3

"""Tests JSON-RPC connections with certificates and combinations of
insecure/skip_verify flags.

Run via pytest (clean output) or as a plain script (used by `make run-tests`):

    uv run pytest test/ci/json_rpc_certificates.py
    uv run test/ci/json_rpc_certificates.py
"""

import os

import pytest
from napalm import get_network_driver

HOST = "clab-napalm-ci_cd-srl"

# the lab CA is written by containerlab under the lab directory at the repo root
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CA_CERT = os.path.join(REPO_ROOT, ".clab", "clab-napalm-ci_cd", ".tls", "ca", "ca.pem")


@pytest.mark.parametrize(
    "optional_args",
    [
        pytest.param({"tls_ca": CA_CERT}, id="https-verified-against-lab-ca"),
        pytest.param({"skip_verify": True}, id="https-certificate-not-verified"),
        pytest.param({"insecure": True}, id="plain-http-port-80"),
        pytest.param({"insecure": True, "jsonrpc_port": 80}, id="plain-http-explicit-port"),
    ],
)
def test_jsonrpc_connection(optional_args):
    device = get_network_driver("srlinux")(HOST, "admin", "NokiaSrl1!", 10, optional_args)
    device.open()
    try:
        assert device.get_facts()
    finally:
        device.close()


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__]))
