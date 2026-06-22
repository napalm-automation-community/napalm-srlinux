# Copyright 2024 Nokia. All rights reserved.
#
# The contents of this file are licensed under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with the
# License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.
# SPDX-License-Identifier: Apache-2.0

"""JSON-RPC transport for Nokia SR Linux."""

import enum
import itertools
import logging
import ssl
from typing import Any

import httpx
from napalm.base.exceptions import CommandErrorException, ConnectionException

from napalm_srlinux.helpers import compose_jsonrpc_url, determine_jsonrpc_port

logger = logging.getLogger(__name__)


class SRLinuxDevice:
    """Represents a Nokia SR Linux device, abstracting the JSON-RPC transport.

    Constructing the object performs no I/O; the HTTP client is created by
    :meth:`open`.
    """

    class RPCMethod(str, enum.Enum):
        """JSON-RPC methods supported by the SR Linux management server."""

        GET = "get"
        SET = "set"
        VALIDATE = "validate"
        CLI = "cli"
        DIFF = "diff"

    class RPCAction(str, enum.Enum):
        """Actions for set/validate/diff commands."""

        REPLACE = "replace"
        UPDATE = "update"
        DELETE = "delete"

    class Datastore(str, enum.Enum):
        """SR Linux configuration/state datastores."""

        CANDIDATE = "candidate"
        RUNNING = "running"
        STATE = "state"
        TOOLS = "tools"

    def __init__(
        self,
        hostname: str,
        username: str,
        password: str,
        timeout: int = 60,
        optional_args: dict | None = None,
    ):
        optional_args = optional_args or {}

        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout

        self.insecure: bool = optional_args.get("insecure", False)
        self.skip_verify: bool = optional_args.get("skip_verify", False)
        self.tls_ca: str = optional_args.get("tls_ca", "")
        self.tls_cert_path: str = optional_args.get("tls_cert_path", "")
        self.tls_key_path: str = optional_args.get("tls_key_path", "")
        self.tls_key_password: str = optional_args.get("tls_key_password", "")

        self.jsonrpc_port = determine_jsonrpc_port(optional_args)
        self.jsonrpc_url = compose_jsonrpc_url(self.hostname, self.jsonrpc_port, self.insecure)

        self.jsonrpc_client: httpx.Client | None = None
        self._request_id = itertools.count(1)

        if self.insecure and self.jsonrpc_port == 443:
            logger.warning(
                "insecure=True (plain http) with port 443 configured; "
                "the JSON-RPC server normally serves https on 443"
            )
        if not self.insecure and self.jsonrpc_port == 80:
            logger.warning(
                "Port 80 configured without insecure=True; "
                "the JSON-RPC server normally serves plain http on 80"
            )

    # ----------------------------------------------------------------- lifecycle

    def open(self) -> None:
        """Create the HTTP client and verify the JSON-RPC endpoint is reachable."""
        if self.jsonrpc_client is None:
            self.jsonrpc_client = self._new_jsonrpc_client()
        try:
            self.jsonrpc_client.head(self.jsonrpc_url)
        except httpx.HTTPError as exc:
            raise ConnectionException(
                f"Error opening http(s) connection to {self.jsonrpc_url}: {exc}"
            ) from exc

    def close(self) -> None:
        """Close the HTTP client."""
        if self.jsonrpc_client is not None:
            self.jsonrpc_client.close()
            self.jsonrpc_client = None

    def is_alive(self) -> bool:
        """Return True when the JSON-RPC endpoint answers an HTTP HEAD request."""
        if self.jsonrpc_client is None:
            return False
        try:
            self.jsonrpc_client.head(self.jsonrpc_url)
            return True
        except httpx.HTTPError:
            return False

    # ----------------------------------------------------------------- RPC surface

    def get_paths(self, paths: list[str], datastore: Datastore) -> list:
        """Get the subtrees for a list of YANG paths from a datastore.

        Returns a list of results aligned with the requested paths.
        """
        commands = [{"path": p, "datastore": datastore.value} for p in paths]
        response = self._jsonrpc_request(self.RPCMethod.GET, {"commands": commands})
        return response["result"]

    def run_cli_commands(self, commands: list[str], output_format: str = "text") -> list:
        """Run CLI commands; returns a list of results aligned with the commands."""
        response = self._jsonrpc_request(
            self.RPCMethod.CLI,
            {"commands": commands, "output-format": output_format},
        )
        return response["result"]

    def set_paths(
        self,
        commands: list[dict],
        datastore: Datastore = Datastore.CANDIDATE,
        confirm_timeout: int | None = None,
    ) -> dict:
        """Apply configuration commands ({action, path, value}) via the set method.

        A set request against the candidate datastore is transactional and
        commits on success.
        """
        params: dict[str, Any] = {"commands": commands, "datastore": datastore.value}
        if confirm_timeout is not None:
            params["confirm-timeout"] = confirm_timeout
        return self._jsonrpc_request(self.RPCMethod.SET, params)

    def validate_paths(self, commands: list[dict]) -> dict:
        """Validate configuration commands without applying them."""
        return self._jsonrpc_request(self.RPCMethod.VALIDATE, {"commands": commands})

    def diff_paths(self, commands: list[dict], output_format: str = "text") -> list:
        """Diff configuration commands against the running config."""
        response = self._jsonrpc_request(
            self.RPCMethod.DIFF,
            {"commands": commands, "output-format": output_format},
        )
        return response.get("result", [])

    # ----------------------------------------------------------------- internals

    def _jsonrpc_request(self, method: RPCMethod, params: dict) -> dict:
        """POST a JSON-RPC request and return the response body.

        Raises ConnectionException for authentication/transport problems and
        CommandErrorException when the server reports a JSON-RPC error.
        """
        if self.jsonrpc_client is None:
            raise ConnectionException("Device connection is not open; call open() first")

        request_data = {
            "jsonrpc": "2.0",
            "id": next(self._request_id),
            "method": method.value,
            "params": params,
        }

        try:
            response = self.jsonrpc_client.post(
                self.jsonrpc_url,
                json=request_data,
                timeout=self.timeout,
            )
        except httpx.HTTPError as exc:
            raise ConnectionException(f"JSON-RPC request failed: {exc}") from exc

        if response.status_code in (401, 403):
            raise ConnectionException(
                f"Authentication failed (HTTP {response.status_code})"
            )
        if not response.is_success:
            raise CommandErrorException(
                f"JSON-RPC request returned HTTP {response.status_code}: {response.text}"
            )

        body = response.json()
        if body.get("error"):
            error = body["error"]
            raise CommandErrorException(
                f"JSON-RPC error {error.get('code')}: {error.get('message')}"
            )
        return body

    def _build_verify(self) -> bool | ssl.SSLContext:
        """Determine the TLS verification setting for the HTTP client."""
        if self.insecure:
            # plain http; verify is irrelevant but must not block anything
            return False
        if self.skip_verify:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            return ctx
        if self.tls_ca:
            return ssl.create_default_context(cafile=self.tls_ca)
        return True

    def _build_cert(self) -> tuple | None:
        """Build the client certificate tuple; None unless both cert and key are set."""
        if not (self.tls_cert_path and self.tls_key_path):
            return None
        if self.tls_key_password:
            return (self.tls_cert_path, self.tls_key_path, self.tls_key_password)
        return (self.tls_cert_path, self.tls_key_path)

    def _new_jsonrpc_client(self) -> httpx.Client:
        """Create the HTTP client, configured for the requested TLS mode."""
        opts: dict[str, Any] = {
            "verify": self._build_verify(),
            "auth": httpx.BasicAuth(self.username, self.password),
            "headers": {
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        }

        cert = self._build_cert()
        if cert:
            opts["cert"] = cert

        return httpx.Client(**opts)
