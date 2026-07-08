# Config & tools

Reading the configuration, raw CLI access, and on-device reachability tools.

## `get_config`

```python
device.get_config(retrieve="all", sanitized=False, format="text")
```

Returns the running configuration - by default as a JSON document, straight from the `running` datastore:

```python
device.get_config(retrieve="running")                  # JSON string
device.get_config(retrieve="running", sanitized=True)  # aaa/tls subtrees removed
```

Prefer flat CLI commands? Pass `format="cli"` per call, or set the [`running_format`](../guide/connection.md#all-optional-arguments) optional argument to make it the default - the output is then equivalent to `info flat`:

```python
device.get_config(retrieve="running", format="cli")
```

```text
set / interface ethernet-1/1 admin-state enable
set / interface ethernet-1/1 subinterface 0 ipv4 admin-state enable
set / interface ethernet-1/1 subinterface 0 ipv4 address 10.0.0.1/30
...
```

Two notes:

- `sanitized=True` (strips `aaa` and `tls` secrets) is only available with the JSON format.
- `retrieve="candidate"` and `retrieve="startup"` return `""` - the candidate exists only [client-side](../guide/config-management.md), and the startup config is not exposed via JSON-RPC.

## `cli`

```python
device.cli(commands, encoding="text")
```

Runs arbitrary CLI commands through the JSON-RPC `cli` method and returns the output per command:

/// tab | text

```python
>>> device.cli(["show version"])
{"show version": "--------------------------------------\nHostname  : srl1\nChassis Type : 7220 IXR-D2L\n..."}
```

///
/// tab | json

```python
>>> device.cli(["show version"], encoding="json")
{"show version": {"basic system info": {"Hostname": "srl1", "Chassis Type": "7220 IXR-D2L", ...}}}
```

///
With `encoding="json"` you get SR Linux's structured output instead of rendered text - usually much nicer to post-process than parsing CLI screens. Each command is sent as its own request, so the per-command mapping in the result is always exact.

## `ping`

```python
device.ping(destination, source="", ttl=255, timeout=2,
            size=100, count=5, vrf="", source_interface="")
```

Pings from the device. `vrf` selects the network-instance the ping runs in - for management-network targets that's typically `vrf="mgmt"`.

```python
device.ping("172.20.20.1", vrf="mgmt")
```

/// details | Example output
    type: example

```python
{
    "success": {
        "probes_sent": 5,
        "packet_loss": 0,
        "rtt_min": 2.923,
        "rtt_avg": 3.326,
        "rtt_max": 3.477,
        "rtt_stddev": 0.203,
        "results": [
            {"ip_address": "8.8.8.8", "rtt": 3.48},
            {"ip_address": "8.8.8.8", "rtt": 3.43},
            {"ip_address": "8.8.8.8", "rtt": 2.92},
            {"ip_address": "8.8.8.8", "rtt": 3.41},
            {"ip_address": "8.8.8.8", "rtt": 3.39}
        ]
    }
}
```

///

## `traceroute`

```python
device.traceroute(destination, ttl=255, vrf="")
```

Traceroute from the device, per network-instance via `vrf`. SR Linux's traceroute does not support the `source` and `timeout` options; they are accepted for API compatibility but ignored.

/// details | Example output
    type: example

```python
{
    "success": {
        1: {
            "probes": {
                1: {"rtt": 3.029, "ip_address": "8.8.8.8", "host_name": "8.8.8.8"},
                2: {"rtt": 3.001, "ip_address": "8.8.8.8", "host_name": "8.8.8.8"},
                3: {"rtt": 2.988, "ip_address": "8.8.8.8", "host_name": "8.8.8.8"}
            }
        }
    }
}
```

///

## Changing configuration

Everything about writing config - the candidate workflow, accepted formats, commit, rollback, and confirmed commits - lives in the user guide:

- [Configuration management](../guide/config-management.md)
- [Commit confirm](../guide/commit-confirm.md)
