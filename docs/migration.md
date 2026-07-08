# Migrating from 1.x

The 1.x driver spoke gNMI; the current driver speaks JSON-RPC. For most users migration is a package swap and a driver-name change, but a few details differ.

## Checklist

- [ ] Switch the driver name: `get_network_driver("srlinux")` - it was `"srl"`
- [ ] Update imports if you used the package directly: `napalm_srlinux` (was `napalm_srl`)
- [ ] Enable the [JSON-RPC server](install.md#enable-the-json-rpc-server-on-sr-linux) on your nodes (gNMI alone is no longer enough)
- [ ] Replace the removed gNMI optional arguments (table below)
- [ ] Review code that consumes interface speeds, `get_users()` output, or uptimes (behavior fixes below)

## Optional arguments

The gNMI transport and its options are gone:

| 1.x argument | now |
|---|---|
| `gnmi_port` | `jsonrpc_port` (default 443, or 80 with `insecure`) |
| `target_name` | removed - use `skip_verify` or a proper `tls_ca` |
| `encoding` | removed - JSON-RPC is always JSON |
| `tls_cert` | `tls_cert_path` |
| `tls_key` | `tls_key_path` (+ optional `tls_key_password`) |
| `insecure` | kept, but now means plain HTTP instead of an unverified gNMI channel |
| `skip_verify` | unchanged - HTTPS without certificate verification |

See [Connection & TLS](guide/connection.md) for the full current list.

## Behavior fixes

These were bugs in 1.x that your code may have worked around:

- **Interface speeds** are now correctly reported in Mbit/s - a 1G port returns `1000.0` (1.x returned `1.0`).
- **`get_users()`** returns SSH keys under the standard NAPALM key `sshkeys` (was the non-standard `ssh-keys`).
- **BGP and interface uptimes** are no longer truncated to less than a day.

## New since 1.x

While you're migrating, you also gain:

- [Commit confirm](guide/commit-confirm.md): `commit_config(revert_in=...)`, `confirm_commit()`, `has_pending_commit()`
- [`get_vlans()`](reference/interfaces.md#get_vlans)
- [`cli(encoding="json")`](reference/tools.md#cli) for structured command output
- CLI-format running config via [`running_format`](guide/connection.md#all-optional-arguments) or `get_config(format="cli")`
