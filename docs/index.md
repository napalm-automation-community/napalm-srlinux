# NAPALM driver for Nokia SR Linux

`napalm-srlinux` is the community [NAPALM](https://napalm.readthedocs.io) driver for the [Nokia SR Linux](https://learn.srlinux.dev) network OS. It speaks to SR Linux over its **JSON-RPC** management interface — no gNMI stack, no protobuf toolchain, no platform-specific wheels. The only runtime dependencies are `napalm` and `httpx`.

If you already automate with NAPALM — directly, through Nornir, Ansible, or Salt — SR Linux becomes just another platform string:

```python
from napalm import get_network_driver

driver = get_network_driver("srlinux")
with driver("192.0.2.1", "admin", "NokiaSrl1!",
            optional_args={"insecure": True}) as device:  # (1)!
    print(device.get_facts())
```

1. `insecure: True` uses plain HTTP — perfect for [containerlab](https://containerlab.dev) labs, not for production. See [Connection & TLS](guide/connection.md) for the HTTPS modes.

<div class="grid cards" markdown>

-   :material-database-search:{ .lg .middle } **26 getters**

    ---

    Every standard NAPALM getter with an SR Linux equivalent is implemented — facts, interfaces, BGP, LLDP, routes, MAC tables, optics and more.

    [:octicons-arrow-right-24: Capabilities](reference/index.md)

-   :material-file-replace-outline:{ .lg .middle } **Full config workflow**

    ---

    Merge or replace candidates from native JSON, gNMI-style payloads, or plain SR Linux CLI — with diff, commit, checkpoint-based rollback.

    [:octicons-arrow-right-24: Configuration management](guide/config-management.md)

-   :material-timer-check-outline:{ .lg .middle } **Commit confirm**

    ---

    Push risky changes with an automatic revert timer. Confirm them when you still have access, or let the device roll itself back.

    [:octicons-arrow-right-24: Commit confirm](guide/commit-confirm.md)

-   :material-certificate-outline:{ .lg .middle } **TLS done right**

    ---

    Plain HTTP for the lab, CA-verified HTTPS and mutual TLS with client certificates for everything else.

    [:octicons-arrow-right-24: Connection & TLS](guide/connection.md)

</div>

## Install

```bash
pip install napalm-srlinux
```

Requires Python ≥ 3.10 and napalm ≥ 5. Head over to the [installation guide](install.md) to enable the JSON-RPC server on your node, then run through the [quickstart](quickstart.md) — it takes you from zero to `get_facts()` against a containerlab node in about two minutes.

Coming from the older gNMI-based 1.x driver? The [migration guide](migration.md) covers everything that changed.
