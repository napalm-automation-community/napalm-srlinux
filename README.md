# napalm-srlinux

Community [NAPALM](https://napalm.readthedocs.io) driver for the [Nokia SR Linux](https://learn.srlinux.dev) network OS, built on the **JSON-RPC** management interface; the only runtime dependencies are `napalm` and `httpx`.

**Documentation: https://napalm-automation-community.github.io/napalm-srlinux/**

## Installation

```bash
pip install napalm-srlinux
```

Requires Python ≥ 3.10 and napalm ≥ 5.

On the SR Linux node the JSON-RPC server must be enabled (it is by default in [containerlab](https://containerlab.dev) labs):

```
set / system json-rpc-server admin-state enable
set / system json-rpc-server network-instance mgmt http admin-state enable
set / system json-rpc-server network-instance mgmt https admin-state enable
set / system json-rpc-server network-instance mgmt https tls-profile <profile>
```

## Quick start

```python
from napalm import get_network_driver

driver = get_network_driver("srlinux")
optional_args = {
    # pick one of the TLS modes below:
    "insecure": True,        # plain http on port 80 — labs only
    # "skip_verify": True,   # https, certificate not verified
    # "tls_ca": "ca.pem",    # https, verified against this CA
}
with driver("192.0.2.1", "admin", "NokiaSrl1!", optional_args=optional_args) as device:
    print(device.get_facts())
```

A runnable example against a containerlab node is in [examples/example.py](examples/example.py).

## Optional arguments

| argument | default | description |
|---|---|---|
| `jsonrpc_port` | `443` (or `80` with `insecure`) | TCP port of the JSON-RPC server |
| `insecure` | `False` | use plain http instead of https |
| `skip_verify` | `False` | https without certificate verification |
| `tls_ca` | `""` | CA bundle used to verify the server certificate |
| `tls_cert_path` / `tls_key_path` | `""` | client certificate and key (both required for mTLS) |
| `tls_key_password` | `""` | passphrase of the client key |
| `running_format` | `"json"` | `get_config()` running-config format: `json` or `cli` (`info flat`) |
| `commit_save` | `False` | when set, commits use `commit save` / `save startup` so the config persists |

## Supported methods

All standard NAPALM getters that have an SR Linux equivalent are implemented:
`get_facts`, `get_interfaces`, `get_interfaces_counters`*, `get_interfaces_ip`*, `get_arp_table`, `get_ipv6_neighbors_table`, `get_bgp_neighbors`, `get_bgp_neighbors_detail`, `get_bgp_config`, `get_environment`, `get_lldp_neighbors`, `get_lldp_neighbors_detail`, `get_network_instances`, `get_users`, `get_snmp_information`, `get_config`, `get_ntp_servers`, `get_ntp_stats`, `get_optics`, `get_mac_address_table`, `get_route_to`, `get_vlans`**, `is_alive`, `ping`, `traceroute`, `cli` (`text` and `json` encodings), plus the full candidate-config workflow (`load_merge_candidate`, `load_replace_candidate`, `compare_config`, `commit_config` — including commit-confirm via `revert_in` —, `confirm_commit`, `has_pending_commit`, `discard_config`, `rollback`).

\* keyed by subinterface name (e.g. `ethernet-1/1.0`), since IP/counter state lives on subinterfaces in SR Linux.

\** SR Linux has no global VLAN table; `get_vlans` reports the single-tagged encapsulations of bridged subinterfaces attached to mac-vrf network instances, named after the mac-vrf. Untagged subinterfaces and `vlan-id any` are not reported.

Not supported by SR Linux (raise `NotImplementedError`): `get_probes_config/results`, `get_firewall_policies`, `get_ntp_peers`, `get_route_to(longer=True)`.

### Candidate-config semantics

The JSON-RPC interface has no persistent candidate datastore across requests — a `set` request against the candidate datastore is transactional and commits on success. The NAPALM candidate workflow is therefore emulated client-side:

- `load_merge_candidate()` / `load_replace_candidate()` store the intended change **in the driver** and (for JSON configs) validate it on the device via the `validate` method. Accepted formats: native SR Linux JSON, a gNMI-style envelope (`updates`/`replaces`/`deletes`), or SR Linux CLI commands.
- `compare_config()` uses the JSON-RPC `diff` method (JSON configs) or a throwaway named candidate on the device (CLI configs).
- `commit_config()` first creates a named checkpoint (`NAPALM-<session>-<n>`, unique per driver instance) as the rollback anchor, then applies everything in one transactional request.
- `discard_config()` only clears the client-side state; it never touches the device.
- `rollback()` restores the checkpoint created by the last `commit_config()`. Checkpoints contain the **entire** configuration tree — any change made after the checkpoint is reverted too.
- `get_config(retrieve="candidate")` returns `""` — the candidate only exists client-side.

#### Commit confirm

`commit_config(revert_in=<seconds>)` starts a confirmed commit: the change is applied, but the device reverts it automatically unless it is confirmed in time (JSON configs use the JSON-RPC `confirm-timeout` parameter, available since SR Linux 23.3.2; CLI configs use `commit confirmed timeout <seconds>`).

- `has_pending_commit()` reports whether a confirmed commit is awaiting confirmation — device-side state, visible to every session.
- `confirm_commit()` accepts the pending commit and cancels the revert timer. With `commit_save`, the `save startup` is deferred until this point, so the startup config never holds a change that may still auto-revert.
- `rollback()` called while a confirm is pending rejects it immediately (`confirmed-reject`) instead of loading a checkpoint.
- `commit_config()` refuses to run while another confirmed commit is pending.

Because the candidate is client-side, no lock is held on the device; concurrent clients are not blocked (and not protected) against each other.

## Migrating from 1.x

- The driver name changed: `get_network_driver("srlinux")` instead of `"srl"`; the package is `napalm_srlinux` (was `napalm_srl`).
- gNMI is gone — the optional arguments `gnmi_port`, `target_name`, `encoding`, `tls_cert`, and `tls_key` no longer exist. Client certificates are configured with `tls_cert_path`/`tls_key_path`.
- `get_interfaces()` speeds are now correctly reported in Mbit/s (e.g. `1G` → `1000.0`).
- `get_users()` returns the standard `sshkeys` key (was `ssh-keys`).
- BGP/interface uptimes are no longer truncated to less than a day.

## Development

The project is managed with [uv](https://docs.astral.sh/uv/):

```bash
uv sync                  # create the venv and install all dependencies
uv run pytest test/unit  # unit tests (mocked JSON-RPC fixtures)
uv run ruff check napalm_srlinux test tools examples
```

### Testing against a real node

```bash
make deploy-clab-ci      # single-node containerlab topology
make run-tests           # runs all test/ci scripts against it
make destroy-clab-ci
```

### Re-recording the unit-test fixtures

The mocked-data fixtures under `test/unit/mocked_data/` are verbatim JSON-RPC responses recorded from a real two-node lab (BGP, LLDP, ARP, mac-vrf, NTP, ...):

```bash
make deploy-clab-record  # two-node recording topology
make record-fixtures     # configure the lab + record all fixtures
make destroy-clab-record
```

Review the resulting `git diff` before committing re-recorded fixtures.

## License

Apache 2.0 — see [LICENSE](LICENSE).
