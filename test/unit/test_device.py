# Copyright 2024 Nokia
# Licensed under the Apache License 2.0.
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the JSON-RPC transport layer, using httpx.MockTransport."""

import json
import ssl

import httpx
import pytest
from napalm.base.exceptions import CommandErrorException, ConnectionException

from napalm_srlinux.device import SRLinuxDevice


def make_device(optional_args=None, handler=None, **kwargs):
    """Create a device whose client routes requests to a MockTransport handler."""
    device = SRLinuxDevice("srl", "admin", "admin", optional_args=optional_args, **kwargs)
    if handler is not None:
        device.jsonrpc_client = httpx.Client(transport=httpx.MockTransport(handler))
    return device


def json_response(payload, status_code=200):
    return httpx.Response(status_code, json=payload)


class TestConstruction:
    def test_no_io_at_init(self):
        """Constructing the device must not create the HTTP client or connect."""
        device = SRLinuxDevice("srl", "admin", "admin")
        assert device.jsonrpc_client is None

    def test_default_url(self):
        device = SRLinuxDevice("srl", "admin", "admin")
        assert device.jsonrpc_url == "https://srl:443/jsonrpc"

    def test_insecure_url(self):
        device = SRLinuxDevice("srl", "admin", "admin", optional_args={"insecure": True})
        assert device.jsonrpc_url == "http://srl:80/jsonrpc"

    def test_request_before_open_raises(self):
        device = SRLinuxDevice("srl", "admin", "admin")
        with pytest.raises(ConnectionException):
            device.get_paths(["/system/information"], SRLinuxDevice.Datastore.STATE)


class TestClientConstruction:
    def test_plain_credentials_without_certs(self):
        """Plain user/password must work without any TLS cert files configured."""
        device = SRLinuxDevice("srl", "admin", "admin", optional_args={"skip_verify": True})
        client = device._new_jsonrpc_client()
        assert client is not None
        client.close()

    def test_skip_verify_disables_verification(self):
        device = SRLinuxDevice("srl", "admin", "admin", optional_args={"skip_verify": True})
        context = device._build_verify()
        assert isinstance(context, ssl.SSLContext)
        assert context.verify_mode == ssl.CERT_NONE
        assert context.check_hostname is False

    def test_default_uses_system_trust(self):
        device = SRLinuxDevice("srl", "admin", "admin")
        assert device._build_verify() is True

    def test_insecure_skips_verification(self):
        device = SRLinuxDevice("srl", "admin", "admin", optional_args={"insecure": True})
        assert device._build_verify() is False

    def test_no_partial_cert_tuple(self):
        """A client cert is only configured when both cert and key are provided."""
        device = SRLinuxDevice(
            "srl", "admin", "admin", optional_args={"tls_cert_path": "/tmp/cert.pem"}
        )
        assert device._build_cert() is None

    def test_cert_tuple_with_password(self):
        device = SRLinuxDevice(
            "srl",
            "admin",
            "admin",
            optional_args={
                "tls_cert_path": "/tmp/cert.pem",
                "tls_key_path": "/tmp/key.pem",
                "tls_key_password": "secret",
            },
        )
        assert device._build_cert() == ("/tmp/cert.pem", "/tmp/key.pem", "secret")


class TestJsonRpcRequests:
    def test_request_shape_and_id_increments(self):
        requests = []

        def handler(request):
            requests.append(json.loads(request.content))
            return json_response({"jsonrpc": "2.0", "id": 1, "result": [{}]})

        device = make_device(handler=handler)
        device.get_paths(["/system/information"], SRLinuxDevice.Datastore.STATE)
        device.get_paths(["/platform"], SRLinuxDevice.Datastore.STATE)

        first, second = requests
        assert first["jsonrpc"] == "2.0"
        assert first["method"] == "get"
        assert first["params"]["commands"] == [
            {"path": "/system/information", "datastore": "state"}
        ]
        assert second["id"] == first["id"] + 1

    def test_cli_request(self):
        requests = []

        def handler(request):
            requests.append(json.loads(request.content))
            return json_response({"jsonrpc": "2.0", "id": 1, "result": [{"text": "ok"}]})

        device = make_device(handler=handler)
        result = device.run_cli_commands(["show version"])
        assert result == [{"text": "ok"}]
        assert requests[0]["method"] == "cli"
        assert requests[0]["params"]["commands"] == ["show version"]

    def test_set_request(self):
        requests = []

        def handler(request):
            requests.append(json.loads(request.content))
            return json_response({"jsonrpc": "2.0", "id": 1, "result": [{}]})

        device = make_device(handler=handler)
        commands = [{"action": "update", "path": "/", "value": {}}]
        device.set_paths(commands)
        assert requests[0]["method"] == "set"
        assert requests[0]["params"]["datastore"] == "candidate"
        assert requests[0]["params"]["commands"] == commands

    def test_jsonrpc_error_raises_command_error(self):
        def handler(request):
            return json_response(
                {"jsonrpc": "2.0", "id": 1, "error": {"code": -32602, "message": "bad path"}}
            )

        device = make_device(handler=handler)
        with pytest.raises(CommandErrorException, match="bad path"):
            device.get_paths(["/bogus"], SRLinuxDevice.Datastore.STATE)

    def test_http_401_raises_connection_exception(self):
        def handler(request):
            return httpx.Response(401, text="Unauthorized")

        device = make_device(handler=handler)
        with pytest.raises(ConnectionException, match="401"):
            device.get_paths(["/system/information"], SRLinuxDevice.Datastore.STATE)

    def test_http_400_raises_command_error(self):
        def handler(request):
            return httpx.Response(400, text="Bad Request")

        device = make_device(handler=handler)
        with pytest.raises(CommandErrorException, match="400"):
            device.get_paths(["/system/information"], SRLinuxDevice.Datastore.STATE)

    def test_transport_error_raises_connection_exception(self):
        def handler(request):
            raise httpx.ConnectError("connection refused")

        device = make_device(handler=handler)
        with pytest.raises(ConnectionException):
            device.get_paths(["/system/information"], SRLinuxDevice.Datastore.STATE)


class TestLifecycle:
    def test_is_alive_true(self):
        device = make_device(handler=lambda request: httpx.Response(200))
        assert device.is_alive() is True

    def test_is_alive_false_when_unreachable(self):
        def handler(request):
            raise httpx.ConnectError("connection refused")

        device = make_device(handler=handler)
        assert device.is_alive() is False

    def test_is_alive_false_when_closed(self):
        device = SRLinuxDevice("srl", "admin", "admin")
        assert device.is_alive() is False

    def test_open_raises_connection_exception_when_unreachable(self):
        device = SRLinuxDevice("srl", "admin", "admin")

        def handler(request):
            raise httpx.ConnectError("connection refused")

        device.jsonrpc_client = httpx.Client(transport=httpx.MockTransport(handler))
        with pytest.raises(ConnectionException):
            device.open()

    def test_close_clears_client(self):
        device = make_device(handler=lambda request: httpx.Response(200))
        device.close()
        assert device.jsonrpc_client is None
