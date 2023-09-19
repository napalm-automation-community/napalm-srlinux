#!/usr/bin/python3

# Tests JSON RPC call with certificates and combinations of insecure/skip_verify flags

from napalm import get_network_driver
import sys
import os

import logging
logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

def test(jsonrpc_port=443,tls_ca=None,skip_verify=False,insecure=False):
    driver = get_network_driver("srl")
    optional_args = {
        "gnmi_port": 57400,
        "jsonrpc_port": jsonrpc_port,
        "target_name": "clab-napalm-ci_cd-srl",
        # "tls_cert": cwd + "srl/client.pem",
        "tls_ca": tls_ca,
        # "tls_key": cwd + "srl/client.key",
        "skip_verify": skip_verify,
        "insecure": insecure,
        "encoding": "JSON_IETF"
    }
    device = driver("clab-napalm-ci_cd-srl", "admin", "NokiaSrl1!", 10, optional_args)
    device.open()
    facts = device.get_facts()
    assert( facts )
    print( f"jsonrpc_port={jsonrpc_port} tls_ca={tls_ca} skip_verify={skip_verify} insecure={insecure} -> test OK" )
    device.close()

cwd = os.getcwd() + "/.clab/clab-napalm-ci_cd/.tls/"

test( tls_ca=cwd+"ca/ca.pem" )
test( insecure=True )
test( insecure=True, skip_verify=True )
test( insecure=True, jsonrpc_port=80 )

sys.exit(0) # Success
