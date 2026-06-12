# Capabilities

Every NAPALM method the driver supports, at a glance. All state getters read from the SR Linux `state` datastore over JSON-RPC — structured data straight from the device, no screen scraping. Click through for per-method details and real example output.

## State getters

| method | returns |
|---|---|
| [`get_facts()`](system.md#get_facts) | hostname, model, serial, OS version, uptime, interface list |
| [`get_environment()`](system.md#get_environment) | fans, power supplies, temperature, CPU, memory |
| [`get_users()`](system.md#get_users) | local users with hashed passwords and SSH keys |
| [`get_snmp_information()`](system.md#get_snmp_information) | SNMP contact/location |
| [`get_ntp_servers()`](system.md#get_ntp_servers) | configured NTP servers |
| [`get_ntp_stats()`](system.md#get_ntp_stats) | NTP synchronization state |
| [`is_alive()`](system.md#is_alive) | JSON-RPC endpoint reachability |
| [`get_interfaces()`](interfaces.md#get_interfaces) | state, speed, MTU, MAC per interface |
| [`get_interfaces_counters()`](interfaces.md#get_interfaces_counters) | octet/packet/error counters per subinterface |
| [`get_interfaces_ip()`](interfaces.md#get_interfaces_ip) | IPv4/IPv6 addresses per subinterface |
| [`get_optics()`](interfaces.md#get_optics) | transceiver TX/RX power, laser bias |
| [`get_lldp_neighbors()`](interfaces.md#get_lldp_neighbors) | LLDP neighbor summary |
| [`get_lldp_neighbors_detail()`](interfaces.md#get_lldp_neighbors_detail) | full LLDP TLVs per neighbor |
| [`get_vlans()`](interfaces.md#get_vlans) | VLANs derived from mac-vrf bridged subinterfaces |
| [`get_mac_address_table()`](interfaces.md#get_mac_address_table) | learned MAC addresses in mac-vrfs |
| [`get_bgp_neighbors()`](routing.md#get_bgp_neighbors) | BGP sessions per network-instance |
| [`get_bgp_neighbors_detail()`](routing.md#get_bgp_neighbors_detail) | timers, message counters, session details |
| [`get_bgp_config()`](routing.md#get_bgp_config) | BGP groups and neighbors as configured |
| [`get_route_to()`](routing.md#get_route_to) | RIB lookup with protocol attributes |
| [`get_arp_table()`](routing.md#get_arp_table) | IPv4 ARP entries |
| [`get_ipv6_neighbors_table()`](routing.md#get_ipv6_neighbors_table) | IPv6 neighbor discovery entries |
| [`get_network_instances()`](routing.md#get_network_instances) | network-instances (VRFs) and their interfaces |

## Configuration

| method | does |
|---|---|
| [`get_config()`](tools.md#get_config) | running config as JSON or flat CLI |
| [`load_merge_candidate()`](../guide/config-management.md) | stage a merge — native JSON, gNMI-style, or CLI |
| [`load_replace_candidate()`](../guide/config-management.md) | stage a full replace |
| [`compare_config()`](../guide/config-management.md) | diff the staged change against running |
| [`commit_config()`](../guide/config-management.md#committing) | checkpoint, then apply in one transaction |
| [`commit_config(revert_in=...)`](../guide/commit-confirm.md) | confirmed commit with auto-revert timer |
| [`confirm_commit()`](../guide/commit-confirm.md) | accept a pending confirmed commit |
| [`has_pending_commit()`](../guide/commit-confirm.md) | check for a pending confirmed commit |
| [`discard_config()`](../guide/config-management.md) | drop the staged change (client-side only) |
| [`rollback()`](../guide/config-management.md) | restore the pre-commit checkpoint, or reject a pending confirm |

The candidate workflow is emulated client-side on top of SR Linux's transactional JSON-RPC `set` — the [configuration management guide](../guide/config-management.md) explains exactly how.

## Tools

| method | does |
|---|---|
| [`cli()`](tools.md#cli) | run CLI commands, text or structured JSON output |
| [`ping()`](tools.md#ping) | ping from the device, per network-instance |
| [`traceroute()`](tools.md#traceroute) | traceroute from the device, per network-instance |

## Not supported

SR Linux has no equivalent for these; they raise `NotImplementedError`:

- `get_probes_config()` / `get_probes_results()` — no RPM/SLA probe infrastructure
- `get_firewall_policies()` — no zone-based firewall
- `get_ntp_peers()` — SR Linux only supports NTP servers, not symmetric peers
- `get_route_to(longer=True)`

Two `get_config()` targets always return empty strings rather than raising:

- `retrieve="candidate"` — the candidate exists only [client-side](../guide/config-management.md)
- `retrieve="startup"` — the startup config is not retrievable via JSON-RPC
