#!/usr/bin/python3

# Tests JSON-RPC connections with certificates and combinations of
# insecure/skip_verify flags.

import logging
import os
import sys

from napalm import get_network_driver

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)


def test(jsonrpc_port=None, tls_ca="", skip_verify=False, insecure=False):
    driver = get_network_driver("srlinux")
    optional_args = {
        "tls_ca": tls_ca,
        "skip_verify": skip_verify,
        "insecure": insecure,
    }
    if jsonrpc_port:
        optional_args["jsonrpc_port"] = jsonrpc_port
    device = driver("clab-napalm-ci_cd-srl", "admin", "NokiaSrl1!", 10, optional_args)
    device.open()
    facts = device.get_facts()
    assert facts
    print(
        f"jsonrpc_port={jsonrpc_port} tls_ca={tls_ca} "
        f"skip_verify={skip_verify} insecure={insecure} -> test OK"
    )
    device.close()


cwd = os.getcwd() + "/.clab/clab-napalm-ci_cd/.tls/"

test(tls_ca=cwd + "ca/ca.pem")  # https, verified against the lab CA
test(skip_verify=True)  # https, certificate not verified
test(insecure=True)  # plain http on port 80
test(insecure=True, jsonrpc_port=80)  # plain http, explicit port

sys.exit(0)  # Success
