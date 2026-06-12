# Connection & TLS

The driver connects to the SR Linux JSON-RPC server over HTTP(S). Everything about the connection is controlled through NAPALM's `optional_args`.

## TLS modes

Pick exactly one of the four modes below.

=== "Plain HTTP (labs)"

    No TLS at all — the JSON-RPC server's `http` endpoint on port 80. Use this in containerlab and other throwaway labs, never in production.

    ```python
    optional_args = {
        "insecure": True,
    }
    ```

=== "HTTPS, unverified"

    TLS encryption without certificate verification. The traffic is encrypted, but you are not protected against a man-in-the-middle.

    ```python
    optional_args = {
        "skip_verify": True,
    }
    ```

=== "HTTPS, CA-verified"

    The recommended production mode: the server certificate is verified against the CA bundle you provide.

    ```python
    optional_args = {
        "tls_ca": "/path/to/ca.pem",
    }
    ```

=== "Mutual TLS"

    On top of server verification, the driver presents a client certificate. Both `tls_cert_path` and `tls_key_path` are required; add `tls_key_password` if the key is encrypted.

    ```python
    optional_args = {
        "tls_ca": "/path/to/ca.pem",
        "tls_cert_path": "/path/to/client.pem",
        "tls_key_path": "/path/to/client.key",
        "tls_key_password": "s3cr3t",  # only for encrypted keys
    }
    ```

With no TLS-related arguments at all, the driver uses HTTPS and verifies the server certificate against the system CA store.

## All optional arguments

| argument | default | description |
|---|---|---|
| `jsonrpc_port` | `443` (or `80` with `insecure`) | TCP port of the JSON-RPC server |
| `insecure` | `False` | use plain HTTP instead of HTTPS |
| `skip_verify` | `False` | HTTPS without certificate verification |
| `tls_ca` | `""` | CA bundle used to verify the server certificate |
| `tls_cert_path` / `tls_key_path` | `""` | client certificate and key (both required for mTLS) |
| `tls_key_password` | `""` | passphrase of the client key |
| `running_format` | `"json"` | [`get_config()`](../reference/tools.md#get_config) running-config format: `json` or `cli` (`info flat`) |
| `commit_save` | `False` | commits use `commit save` / `save startup` so the config persists — see [configuration management](config-management.md) |

/// warning | Mismatched port and mode
`insecure: True` together with port 443, or HTTPS against port 80, almost certainly points at the wrong endpoint. The driver logs a warning when it sees either combination.
///

## Connection lifecycle

The driver is a regular NAPALM driver: call `open()`/`close()` yourself, or let the context manager do it:

```python
from napalm import get_network_driver

driver = get_network_driver("srlinux")
device = driver(
    hostname="192.0.2.1",
    username="admin",
    password="NokiaSrl1!",
    timeout=60,  # (1)!
    optional_args={"tls_ca": "/path/to/ca.pem"},
)

with device:
    print(device.get_facts())
```

1. `timeout` (seconds) applies to every JSON-RPC request the driver makes.

`open()` creates the HTTP client and verifies the endpoint is reachable; `is_alive()` re-checks reachability at any time. Because JSON-RPC is stateless, there is no long-lived session on the device — each NAPALM call maps to one or more independent HTTP requests.
