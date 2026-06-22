# Quickstart

This walkthrough takes you from nothing to live NAPALM data against an SR Linux node. All you need is [containerlab](https://containerlab.dev) and the [driver installed](install.md).

## 1. Deploy a lab

Use the ready-made single-node topology hosted at srlinux.dev:

```bash
clab deploy -c -t srlinux.dev/clab-srl
```

Or write your own minimal topology:

```yaml title="srl.clab.yml"
name: srl
topology:
  nodes:
    srl:
      kind: nokia_srlinux
      image: ghcr.io/nokia/srlinux
```

```bash
clab deploy -c -t srl.clab.yml
```

Either way you end up with a node reachable by name (`srl`) with the default credentials `admin` / `NokiaSrl1!` and the JSON-RPC server already enabled.

## 2. Connect and get facts

```python title="quickstart.py"
from napalm import get_network_driver

driver = get_network_driver("srlinux")

optional_args = {
    "insecure": True,  # plain http — labs only (1)
}

with driver("srl", "admin", "NokiaSrl1!", optional_args=optional_args) as device:
    print(device.get_facts())
```

1. For HTTPS with or without certificate verification, see [Connection & TLS](guide/connection.md).

Run it:

```bash
python quickstart.py
```

```python
{
    'hostname': 'srl',
    'fqdn': 'srl',
    'vendor': 'Nokia',
    'model': '7220 IXR-D2L',
    'serial_number': 'Sim Serial No.',
    'os_version': 'v25.10.1',
    'uptime': 1042.5,
    'interface_list': ['ethernet-1/1', 'ethernet-1/2', '...', 'mgmt0']
}
```

## 3. Explore the API

Everything NAPALM offers works the same way — a few to try:

```python
device.get_interfaces()                # admin/oper state, speed, MAC, MTU
device.get_bgp_neighbors()             # per-VRF BGP sessions
device.get_route_to("192.0.2.0/24")    # RIB lookup
device.cli(["show version"])           # raw CLI, text or json encoding
```

And the configuration workflow — load, diff, commit, roll back:

```python
device.load_merge_candidate(config='set / system information location "lab"')
print(device.compare_config())
device.commit_config()
device.rollback()
```

A runnable example covering every getter ships with the repository: [`examples/example.py`](https://github.com/napalm-automation-community/napalm-srlinux/blob/main/examples/example.py).

## 4. Clean up

```bash
clab destroy -c -t srlinux.dev/clab-srl
```

## Where to next

- [Connection & TLS](guide/connection.md) — HTTPS, certificate verification, mTLS, ports
- [Capabilities](reference/index.md) — every supported method, with real example output
- [Configuration management](guide/config-management.md) — how the candidate workflow maps onto JSON-RPC
