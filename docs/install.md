# Installation

## Install the driver

Install `napalm-srlinux` from PyPI into the environment where you run NAPALM:

/// tab | pip

```bash
pip install napalm-srlinux
```

///
/// tab | uv

```bash
uv add napalm-srlinux
```

///
The driver requires:

- Python ≥ 3.10
- napalm ≥ 5 (installed automatically as a dependency)

That's the whole footprint - besides NAPALM itself, the only dependency is [`httpx`](https://www.python-httpx.org/). There is no gNMI/protobuf stack to build.

## Enable the JSON-RPC server on SR Linux

The driver talks to the JSON-RPC server of SR Linux, so it must be enabled on the node:

```srl
set / system json-rpc-server admin-state enable
set / system json-rpc-server network-instance mgmt http admin-state enable
set / system json-rpc-server network-instance mgmt https admin-state enable
set / system json-rpc-server network-instance mgmt https tls-profile <profile>
```

/// note | containerlab has you covered
In [containerlab](https://containerlab.dev) labs the JSON-RPC server is enabled by default, with both HTTP and HTTPS endpoints up - no extra configuration needed. Deploy a node and connect.
///

Only enable the endpoints you intend to use: `https` for [verified TLS or mTLS](guide/connection.md), `http` if you plan to connect with `insecure: True` in a lab.

## Verify

Check that the JSON-RPC server answers - for a containerlab node named `srl`:

```bash
curl -k -u admin:NokiaSrl1! https://srl/jsonrpc -d '{
  "jsonrpc": "2.0", "id": 1, "method": "get",
  "params": {"commands": [{"path": "/system/name/host-name", "datastore": "state"}]}
}'
```

If you get a JSON response with your hostname back, you're ready for the [quickstart](quickstart.md).
