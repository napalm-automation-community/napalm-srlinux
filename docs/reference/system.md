# Facts & system

System-level getters: identity, hardware health, users, and management services.

All example outputs on this page are real driver output, recorded against SR Linux nodes in a containerlab topology.

## `get_facts`

```python
device.get_facts()
```

Identity and inventory of the node: model, serial number, OS version, uptime in seconds, and the list of physical interfaces.

/// details | Example output
    type: example

```python
{
    "hostname": "srl1",
    "fqdn": "srl1",
    "vendor": "Nokia",
    "model": "7220 IXR-D2L",
    "serial_number": "Sim Serial No.",
    "os_version": "v25.3.2-312-ga0c5002f15",
    "uptime": 6394.816,
    "interface_list": ["ethernet-1/1", "ethernet-1/2", ..., "mgmt0"]
}
```
///

## `get_environment`

```python
device.get_environment()
```

Hardware health: fan and power-supply status, temperature sensors, memory and CPU usage. Values the platform doesn't report (e.g. PSU capacity on virtual nodes) follow the NAPALM convention of `-1`.

/// details | Example output
    type: example

```python
{
    "fans": {"1": {"status": false}, "2": {"status": false}, ...},
    "power": {
        "1": {"status": false, "capacity": -1.0, "output": -1.0},
        "2": {"status": false, "capacity": -1.0, "output": -1.0}
    },
    "temperature": {
        "A": {"temperature": 50.0, "is_alert": false, "is_critical": false}
    },
    "memory": {"available_ram": 49270095872, "used_ram": 20123807744},
    "cpu": {"all": {"%usage": 9.0}}
}
```
///

## `get_users`

```python
device.get_users()
```

Locally configured users with their hashed passwords and SSH public keys. The admin role maps to privilege level 15, all other users to 0. SSH keys live under the standard NAPALM key `sshkeys`.

/// details | Example output
    type: example

```python
{
    "admin": {
        "level": 15,
        "password": "$y$j9T$pNVjOgcNNGIWjBcdDfK/7.$Ir4uYxszxtqzVj5...",
        "sshkeys": ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKUhBr4Bmuy..."]
    },
    "linuxadmin": {
        "level": 0,
        "password": "$y$j9T$0dhyedqIhXCKxo03TPudQ0$a8o6k88JXKdBKHp7...",
        "sshkeys": ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKUhBr4Bmuy..."]
    },
    "testuser": {
        "level": 0,
        "password": "$y$j9T$4416195d85c38e2c$0MJ2QlwoB0JfrzJsrz5/SAT...",
        "sshkeys": []
    }
}
```
///

## `get_snmp_information`

```python
device.get_snmp_information()
```

SNMP contact and location from the system configuration. SR Linux's SNMP framework has no classic chassis-ID or v2c community configuration, so `chassis_id` is empty and `community` is an empty dict.

/// details | Example output
    type: example

```python
{
    "chassis_id": "",
    "community": {},
    "contact": "netops",
    "location": "lab"
}
```
///

## `get_ntp_servers`

```python
device.get_ntp_servers()
```

The configured NTP servers, as a dict keyed by server address (the values are empty dicts, per the NAPALM model).

/// details | Example output
    type: example

```python
{"172.20.21.1": {}}
```
///

## `get_ntp_stats`

```python
device.get_ntp_stats()
```

Synchronization state per configured NTP server. SR Linux exposes whether the clock is synchronized and to which server; protocol internals like stratum, poll interval, and jitter are not available via the management API and are reported as `-1` / empty.

/// details | Example output
    type: example

```python
[
    {
        "remote": "172.20.21.1",
        "referenceid": "",
        "synchronized": false,
        "stratum": -1,
        "type": "",
        "when": "",
        "hostpoll": -1,
        "reachability": -1,
        "delay": -1.0,
        "offset": -1.0,
        "jitter": -1.0
    }
]
```
///

## `is_alive`

```python
device.is_alive()
```

Checks that the JSON-RPC endpoint still answers (an HTTP `HEAD` request). Because JSON-RPC is stateless there is no session that could "die" — this genuinely re-tests reachability on every call.

/// details | Example output
    type: example

```python
{"is_alive": true}
```
///
