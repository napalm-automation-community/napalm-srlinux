# Routing

BGP, RIB lookups, neighbor tables, and network-instances.

## `get_bgp_neighbors`

```python
device.get_bgp_neighbors()
```

BGP sessions grouped per network-instance (VRF) - the `default` network-instance is reported as `global`, per the NAPALM convention. For each peer: session state, AS numbers, and received/accepted/sent prefix counts per address family.

/// details | Example output
    type: example

```python
{
    "global": {
        "router_id": "1.1.1.1",
        "peers": {
            "10.0.0.2": {
                "local_as": 65001,
                "remote_as": 65002,
                "remote_id": "10.0.0.2",
                "is_up": true,
                "is_enabled": true,
                "description": "srl2",
                "uptime": 21,
                "address_family": {
                    "ipv4": {
                        "received_prefixes": 5,
                        "accepted_prefixes": 4,
                        "sent_prefixes": 1
                    },
                    "ipv6": {
                        "received_prefixes": 2,
                        "accepted_prefixes": 1,
                        "sent_prefixes": 1
                    }
                }
            }
        }
    }
}
```

///

## `get_bgp_neighbors_detail`

```python
device.get_bgp_neighbors_detail(neighbor_address="")
```

The full session view: addresses and ports, timers (configured and negotiated), message and update counters, connection-state history. Results are grouped by network-instance, then by remote AS. Pass `neighbor_address` to fetch a single peer.

/// details | Example output
    type: example

```python
{
    "default": {
        65002: [
            {
                "up": true,
                "local_as": 65001,
                "remote_as": 65002,
                "router_id": "1.1.1.1",
                "local_address": "10.0.0.1",
                "routing_table": "ebgp",
                "local_address_configured": false,
                "local_port": 179,
                "remote_address": "10.0.0.2",
                "remote_port": 43835,
                "multihop": false,
                "multipath": false,
                "remove_private_as": false,
                "import_policy": "['all']",
                "export_policy": "['all']",
                "input_messages": 8,
                "output_messages": 9,
                "input_updates": 5,
                "output_updates": 4,
                "messages_queued_out": 0,
                "connection_state": "established",
                "previous_connection_state": "active",
                "last_event": "recvOpen",
                "suppress_4byte_as": false,
                "local_as_prepend": true,
                "holdtime": 90,
                "configured_holdtime": 90,
                "keepalive": 30,
                "configured_keepalive": 30,
                "active_prefix_count": -1,
                "received_prefix_count": -1,
                "accepted_prefix_count": -1,
                "suppressed_prefix_count": -1,
                "advertised_prefix_count": -1,
                "flap_count": -1
            }
        ]
    }
}
```

///

## `get_bgp_config`

```python
device.get_bgp_config(group="", neighbor="")
```

The BGP **configuration** (as opposed to the session state above): peer groups with their neighbors, policies, and prefix limits. Filter by `group` or `neighbor` to get a subset.

/// details | Example output
    type: example

```python
{
    "ebgp": {
        "type": "external",
        "description": "eBGP to srl2",
        "apply_groups": [],
        "multihop_ttl": -1,
        "multipath": false,
        "local_address": "",
        "local_as": 65001,
        "remote_as": 65002,
        "import_policy": "['all']",
        "export_policy": "['all']",
        "remove_private_as": false,
        "prefix_limit": {...},
        "neighbors": {
            "10.0.0.2": {
                "description": "srl2",
                "import_policy": "['all']",
                "export_policy": "['all']",
                "local_address": "10.0.0.1",
                "local_as": 65001,
                "remote_as": 65002,
                "authentication_key": "",
                "prefix_limit": {...},
                "route_reflector_client": false,
                "nhs": false
            }
        }
    }
}
```

///

## `get_route_to`

```python
device.get_route_to(destination="", protocol="")
```

RIB lookup across all network-instances. Filter by `destination` (a prefix or host address) and/or `protocol`. BGP routes carry full protocol attributes - AS path, communities, local preference - resolved from the BGP RIB.

`longer=True` (prefix-tree expansion) is not supported and raises `NotImplementedError`.

/// details | Example output
    type: example

```python
{
    "1.0.4.0/24": [
        {
            "protocol": "bgp",
            "current_active": true,
            "last_active": false,
            "age": 18,
            "next_hop": "10.0.0.2",
            "outgoing_interface": "",
            "selected_next_hop": true,
            "preference": 170,
            "inactive_reason": "",
            "routing_table": "default",
            "protocol_attributes": {
                "local_as": 65001,
                "remote_as": 65002,
                "peer_id": "10.0.0.2",
                "as_path": "65002",
                "communities": [],
                "local_preference": -1,
                "preference2": -1,
                "metric": 0,
                "metric2": -1
            }
        }
    ]
}
```

///

## `get_arp_table`

```python
device.get_arp_table(vrf="")
```

IPv4 ARP entries from all subinterfaces - and, despite the name, the IPv6 neighbor entries too, so dual-stack neighbors show up with all their addresses. Pass `vrf` to restrict to one network-instance. `age` reflects the subinterface's configured ARP timeout (IPv4) or ND reachable-time (IPv6).

/// details | Example output
    type: example

```python
[
    {
        "interface": "ethernet-1/1.0",
        "mac": "1A:35:01:FF:00:01",
        "ip": "10.0.0.2",
        "age": 14400.0
    },
    {
        "interface": "ethernet-1/1.0",
        "mac": "1A:35:01:FF:00:01",
        "ip": "2001:db8:0:1::2",
        "age": 30.0
    },
    {
        "interface": "mgmt0.0",
        "mac": "3E:78:AD:72:1F:05",
        "ip": "172.20.21.1",
        "age": 14400.0
    }
]
```

///

## `get_ipv6_neighbors_table`

```python
device.get_ipv6_neighbors_table()
```

The IPv6 neighbor-discovery table, including the neighbor state (`reachable`, `stale`, ...).

/// details | Example output
    type: example

```python
[
    {
        "interface": "ethernet-1/1.0",
        "mac": "1A:35:01:FF:00:01",
        "ip": "2001:db8:0:1::2",
        "age": 1781281814.225,
        "state": "reachable"
    },
    {
        "interface": "ethernet-1/2.0",
        "mac": "1A:35:01:FF:00:02",
        "ip": "2001:db8:0:2::2",
        "age": 1781296195.599,
        "state": "stale"
    }
]
```

///

## `get_network_instances`

```python
device.get_network_instances(name="")
```

All network-instances (SR Linux's VRFs) with their type - `default`, `ip-vrf`, or `mac-vrf` - and attached subinterfaces. Pass `name` to fetch a single instance.

/// details | Example output
    type: example

```python
{
    "default": {
        "name": "default",
        "type": "default",
        "state": {"route_distinguisher": ""},
        "interfaces": {"interface": {"ethernet-1/1.0": {}}}
    },
    "TEST": {
        "name": "TEST",
        "type": "ip-vrf",
        "state": {"route_distinguisher": ""},
        "interfaces": {"interface": {"ethernet-1/2.0": {}}}
    },
    "bridge1": {
        "name": "bridge1",
        "type": "mac-vrf",
        "state": {"route_distinguisher": ""},
        "interfaces": {"interface": {"ethernet-1/3.0": {}}}
    },
    "mgmt": {
        "name": "mgmt",
        "type": "ip-vrf",
        "state": {"route_distinguisher": ""},
        "interfaces": {"interface": {"mgmt0.0": {}}}
    }
}
```

///
