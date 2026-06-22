# Interfaces & L2

Interface state, counters, addressing, optics, LLDP, and the bridged-domain getters.

/// note | Interfaces vs. subinterfaces
In SR Linux, IP addresses and traffic counters live on **subinterfaces** (`ethernet-1/1.0`), not on the physical interface (`ethernet-1/1`). `get_interfaces()` and the LLDP getters are keyed by interface; `get_interfaces_ip()` and `get_interfaces_counters()` are keyed by subinterface. If you post-process those results, match on `ethernet-1/1.0`, not `ethernet-1/1`.
///

## `get_interfaces`

```python
device.get_interfaces()
```

Admin/oper state, description, last flap, speed, MTU and MAC address for every physical interface. Speeds are reported in Mbit/s — a 25G port returns `25000.0`.

/// details | Example output
    type: example

```python
{
    "ethernet-1/1": {
        "is_up": true,
        "is_enabled": true,
        "description": "",
        "last_flapped": 6385.051,
        "speed": 25000.0,
        "mtu": 9232,
        "mac_address": "1A:9A:00:FF:00:01"
    },
    ...
    "mgmt0": {
        "is_up": true,
        "is_enabled": true,
        "description": "",
        "last_flapped": 6394.581,
        "speed": 1000.0,
        "mtu": 1514,
        "mac_address": "22:A3:E3:5A:A6:1E"
    }
}
```
///

## `get_interfaces_counters`

```python
device.get_interfaces_counters()
```

Octet, unicast/multicast/broadcast packet, and discard counters — keyed by **subinterface**. SR Linux does not break errors out per direction, so `tx_errors`/`rx_errors` are `-1`.

/// details | Example output
    type: example

```python
{
    "ethernet-1/1.0": {
        "tx_errors": -1,
        "rx_errors": -1,
        "tx_discards": 0,
        "rx_discards": 322,
        "tx_octets": 27679,
        "rx_octets": 27441,
        "tx_unicast_packets": 327,
        "rx_unicast_packets": 306,
        "tx_multicast_packets": 123,
        "rx_multicast_packets": 125,
        "tx_broadcast_packets": 8,
        "rx_broadcast_packets": 6
    },
    "mgmt0.0": {...}
}
```
///

## `get_interfaces_ip`

```python
device.get_interfaces_ip()
```

All IPv4 and IPv6 addresses with prefix lengths — keyed by **subinterface**. Link-local addresses are included.

/// details | Example output
    type: example

```python
{
    "ethernet-1/1.0": {
        "ipv4": {"10.0.0.1": {"prefix_length": 30}},
        "ipv6": {
            "2001:db8:0:1::1": {"prefix_length": 64},
            "fe80::189a:ff:feff:1": {"prefix_length": 64}
        }
    },
    "ethernet-1/3.0": {},
    "mgmt0.0": {
        "ipv4": {"172.20.21.11": {"prefix_length": 24}},
        "ipv6": {"fe80::20a3:e3ff:fe5a:a61e": {"prefix_length": 64}}
    }
}
```
///

## `get_optics`

```python
device.get_optics()
```

Per-channel transceiver diagnostics from `/interface/transceiver`: instant RX/TX power and laser bias current. Ports without a transceiver (including all ports on virtual nodes) are omitted, and SR Linux only exposes instant values — `avg`/`min`/`max` are `-1.0`.

/// details | Example output
    type: example

```python
{
    "ethernet-1/1": {
        "physical_channels": {
            "channel": [
                {
                    "index": 1,
                    "state": {
                        "input_power":  {"instant": -2.51, "avg": -1.0, "min": -1.0, "max": -1.0},
                        "output_power": {"instant": -1.95, "avg": -1.0, "min": -1.0, "max": -1.0},
                        "laser_bias_current": {"instant": 35.1, "avg": -1.0, "min": -1.0, "max": -1.0}
                    }
                }
            ]
        }
    }
}
```
///

## `get_lldp_neighbors`

```python
device.get_lldp_neighbors()
```

LLDP neighbors per local interface — hostname and remote port only. Use [`get_lldp_neighbors_detail()`](#get_lldp_neighbors_detail) for the full TLV set.

/// details | Example output
    type: example

```python
{
    "ethernet-1/1": [{"hostname": "srl2", "port": "ethernet-1/1"}],
    "ethernet-1/2": [{"hostname": "srl2", "port": "ethernet-1/2"}],
    "ethernet-1/3": [{"hostname": "srl2", "port": "ethernet-1/3"}]
}
```
///

## `get_lldp_neighbors_detail`

```python
device.get_lldp_neighbors_detail(interface="")
```

Everything LLDP knows about each neighbor: chassis ID, system description, capabilities. Pass `interface` to restrict the result to one local port.

/// details | Example output
    type: example

```python
{
    "ethernet-1/1": [
        {
            "parent_interface": "ethernet-1/1",
            "remote_port": "ethernet-1/1",
            "remote_port_description": "",
            "remote_chassis_id": "1A:35:01:FF:00:00",
            "remote_system_name": "srl2",
            "remote_system_description": "SRLinux-v25.3.2-312-ga0c5002f15 srl2 ...",
            "remote_system_capab": ["router"],
            "remote_system_enable_capab": ["router"]
        }
    ],
    ...
}
```
///

## `get_vlans`

```python
device.get_vlans()
```

SR Linux has no global VLAN table — bridging happens in **mac-vrf** network instances. `get_vlans()` therefore reports the single-tagged encapsulations of bridged subinterfaces attached to mac-vrfs:

- the VLAN ID is the subinterface's `vlan encap single-tagged vlan-id`
- the VLAN name is the mac-vrf's name
- untagged subinterfaces and `vlan-id any` are **not** reported

/// details | Example output
    type: example

```python
{
    100: {
        "name": "bridge1",
        "interfaces": ["ethernet-1/3.100", "ethernet-1/4.100"]
    }
}
```
///

## `get_mac_address_table`

```python
device.get_mac_address_table()
```

Learned and static MAC addresses from all mac-vrf network instances. SR Linux does not track per-MAC move counters, and the VLAN association lives on the subinterface — so `vlan`, `moves` and `last_move` are reported as `-1`.

/// details | Example output
    type: example

```python
[
    {
        "mac": "1A:35:01:FF:00:03",
        "interface": "ethernet-1/3.0",
        "vlan": -1,
        "active": true,
        "static": false,
        "moves": -1,
        "last_move": -1.0
    }
]
```
///
