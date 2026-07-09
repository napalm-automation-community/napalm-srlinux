# Copyright 2024 Nokia. All rights reserved.
#
# The contents of this file are licensed under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with the
# License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.
# SPDX-License-Identifier: Apache-2.0

"""NAPALM driver for Nokia SR Linux, using the JSON-RPC management interface.

Read https://napalm.readthedocs.io and https://napalm.srlinux.dev for more information.
"""

# annotations must stay lazy: some napalm.base.models names differ across the
# supported napalm range (e.g. BGPConfigGroupDict arrived in 5.1.0)
from __future__ import annotations

import json
import logging
import uuid

from napalm.base import NetworkDriver, models
from napalm.base.exceptions import (
    CommandErrorException,
    CommitConfirmException,
    CommitError,
    ConnectionException,
    MergeConfigException,
    ReplaceConfigException,
)
from napalm.base.helpers import as_number, convert

from napalm_srlinux import helpers
from napalm_srlinux.device import SRLinuxDevice

logger = logging.getLogger(__name__)

Datastore = SRLinuxDevice.Datastore
RPCAction = SRLinuxDevice.RPCAction


class NokiaSRLinuxDriver(NetworkDriver):
    """NAPALM driver for Nokia SR Linux."""

    platform = "srlinux"

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        """Constructor."""
        optional_args = optional_args or {}

        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout

        # 'json' (default) or 'cli' formatted running config in get_config()
        self.running_format = optional_args.get("running_format", "json")
        # commit with 'save' persists the config to startup
        self.commit_mode = "save" if optional_args.get("commit_save") else "now"

        # client-side candidate configuration, see load_*_candidate()
        self._candidate: dict | None = None
        # checkpoints and named candidates persist on the device across driver
        # instances, so both need a per-instance component: otherwise instances
        # overwrite each other's rollback anchors, and a candidate left open by
        # one session (e.g. by 'commit confirmed') is silently reused by the
        # next, which then commits against a stale baseline
        session = uuid.uuid4().hex[:8]
        self._checkpoint_prefix = f"NAPALM-{session}"
        self._candidate_name = f"napalm-{session}"
        self._checkpoint_id = 0
        self._last_checkpoint: str | None = None
        # the named candidate held open by an unconfirmed CLI-mode commit
        self._pending_cli_candidate: str | None = None
        # informational only: pending confirms live device-side and survive
        # across (stateless) JSON-RPC sessions, so behavior always consults
        # has_pending_commit() rather than this flag
        self._pending_confirm = False

        self.device = SRLinuxDevice(
            hostname, username, password, timeout=timeout, optional_args=optional_args
        )

    # ------------------------------------------------------------------ lifecycle

    def open(self) -> None:
        self.device.open()

    def close(self) -> None:
        self.device.close()

    def is_alive(self) -> models.AliveDict:
        """Tests if the JSON-RPC endpoint of the device is reachable."""
        return {"is_alive": self.device.is_alive()}

    # ------------------------------------------------------------------ getters

    def get_facts(self) -> models.FactsDict:
        """
        Returns a dictionary containing the following information:
            uptime - Uptime of the device in seconds.
            vendor - Manufacturer of the device.
            model - Device model.
            hostname - Hostname of the device
            fqdn - Fqdn of the device
            os_version - String with the OS version running on the device.
            serial_number - Serial number of the device
            interface_list - List of the interfaces of the device
        """
        chassis, information, hostname_data, interfaces = self.device.get_paths(
            [
                "/platform/chassis",
                "/system/information",
                "/system/name/host-name",
                "/interface[name=*]",
            ],
            Datastore.STATE,
        )

        # /system/information exposes the boot time as a timestamp
        uptime = -1.0
        current_time = information.get("current-datetime")
        boot_time = information.get("last-booted") or information.get("uptime")
        if current_time and boot_time:
            uptime = helpers.seconds_between(current_time, boot_time)

        hostname = hostname_data if isinstance(hostname_data, str) else ""
        interface_list = [i["name"] for i in helpers.value_at(interfaces, "interface", default=[])]

        return {
            "uptime": uptime,
            "vendor": "Nokia",
            "model": chassis.get("type", ""),
            "hostname": hostname,
            "fqdn": hostname,
            "os_version": information.get("version", ""),
            "serial_number": chassis.get("serial-number", ""),
            "interface_list": interface_list,
        }

    def get_interfaces(self) -> dict[str, models.InterfaceDict]:
        """
        Returns a dictionary of dictionaries.
        The keys for the first dictionary will be the interfaces in the devices.
        """
        interfaces_data, information = self.device.get_paths(
            ["/interface[name=*]", "/system/information"],
            Datastore.STATE,
        )

        current_time = information.get("current-datetime")

        interfaces = {}
        for interface in helpers.value_at(interfaces_data, "interface", default=[]):
            last_flapped = -1.0
            if current_time and interface.get("last-change"):
                last_flapped = helpers.seconds_between(current_time, interface["last-change"])

            interfaces[interface["name"]] = {
                "is_up": interface.get("oper-state") == "up",
                "is_enabled": interface.get("admin-state") == "enable",
                "description": interface.get("description", ""),
                "last_flapped": last_flapped,
                "speed": helpers.port_speed_to_mbits(
                    helpers.value_at(interface, "ethernet", "port-speed")
                ),
                "mtu": interface.get("mtu", -1),
                "mac_address": helpers.value_at(
                    interface, "ethernet", "hw-mac-address", default=""
                ),
            }
        return interfaces

    def get_interfaces_counters(self) -> dict[str, models.InterfaceCounterDict]:
        """
        Returns a dictionary of dictionaries keyed by subinterface name with the
        standard NAPALM counters. Octet/error/discard counters are taken per
        subinterface; unicast/multicast/broadcast packet counters are only
        available at the parent interface level.
        """
        (interfaces_data,) = self.device.get_paths(["/interface[name=*]"], Datastore.STATE)

        counters = {}
        for interface in helpers.value_at(interfaces_data, "interface", default=[]):
            if_stats = interface.get("statistics", {})
            for subinterface in interface.get("subinterface", []):
                sub_stats = subinterface.get("statistics", {})
                counters[subinterface["name"]] = {
                    "tx_errors": convert(int, sub_stats.get("out-error-packets"), default=-1),
                    "rx_errors": convert(int, sub_stats.get("in-error-packets"), default=-1),
                    "tx_discards": convert(int, sub_stats.get("out-discarded-packets"), default=-1),
                    "rx_discards": convert(int, sub_stats.get("in-discarded-packets"), default=-1),
                    "tx_octets": convert(int, sub_stats.get("out-octets"), default=-1),
                    "rx_octets": convert(int, sub_stats.get("in-octets"), default=-1),
                    "tx_unicast_packets": convert(
                        int, if_stats.get("out-unicast-packets"), default=-1
                    ),
                    "rx_unicast_packets": convert(
                        int, if_stats.get("in-unicast-packets"), default=-1
                    ),
                    "tx_multicast_packets": convert(
                        int, if_stats.get("out-multicast-packets"), default=-1
                    ),
                    "rx_multicast_packets": convert(
                        int, if_stats.get("in-multicast-packets"), default=-1
                    ),
                    "tx_broadcast_packets": convert(
                        int, if_stats.get("out-broadcast-packets"), default=-1
                    ),
                    "rx_broadcast_packets": convert(
                        int, if_stats.get("in-broadcast-packets"), default=-1
                    ),
                }
        return counters

    def get_interfaces_ip(self) -> dict[str, models.InterfacesIPDict]:
        """
        Returns all configured IP addresses on all subinterfaces as a dictionary
        of dictionaries keyed by subinterface name.
        """
        (interfaces_data,) = self.device.get_paths(
            ["/interface[name=*]/subinterface"], Datastore.STATE
        )

        interfaces_ip = {}
        for interface in helpers.value_at(interfaces_data, "interface", default=[]):
            for subinterface in interface.get("subinterface", []):
                addresses: dict = {}
                for version in ("ipv4", "ipv6"):
                    for address in helpers.value_at(subinterface, version, "address", default=[]):
                        ip, prefix_length = address["ip-prefix"].split("/")
                        addresses.setdefault(version, {})[ip] = {
                            "prefix_length": int(prefix_length)
                        }
                interfaces_ip[subinterface["name"]] = addresses
        return interfaces_ip

    def get_arp_table(self, vrf: str = "") -> list[models.ARPTableDict]:
        """
        Returns a list of dictionaries having the following set of keys:
            interface (string)
            mac (string)
            ip (string)
            age (float)
        'vrf' of null-string will default to all VRFs.
        """
        ni_path = f"/network-instance[name={vrf or '*'}]"
        ni_data, interfaces_data = self.device.get_paths(
            [ni_path, "/interface[name=*]/subinterface"], Datastore.STATE
        )

        # subinterfaces that are members of the selected network instance(s)
        member_subinterfaces = {
            member["name"]
            for instance in self._network_instance_list(ni_data, vrf)
            for member in instance.get("interface", [])
        }

        arp_table = []
        for interface in helpers.value_at(interfaces_data, "interface", default=[]):
            for subinterface in interface.get("subinterface", []):
                name = subinterface.get("name")
                if name not in member_subinterfaces:
                    continue

                arp = helpers.value_at(subinterface, "ipv4", "arp", default={})
                timeout = convert(float, arp.get("timeout"), default=-1.0)
                for neighbor in arp.get("neighbor", []):
                    arp_table.append(
                        {
                            "interface": name,
                            "mac": neighbor.get("link-layer-address", ""),
                            "ip": neighbor.get("ipv4-address", ""),
                            "age": timeout,
                        }
                    )

                nd = helpers.value_at(subinterface, "ipv6", "neighbor-discovery", default={})
                reachable_time = convert(float, nd.get("reachable-time"), default=-1.0)
                for neighbor in nd.get("neighbor", []):
                    arp_table.append(
                        {
                            "interface": name,
                            "mac": neighbor.get("link-layer-address", ""),
                            "ip": neighbor.get("ipv6-address", ""),
                            "age": reachable_time,
                        }
                    )
        return arp_table

    def get_ipv6_neighbors_table(self) -> list[models.IPV6NeighborDict]:
        """
        Get IPv6 neighbors table information.

        Return a list of dictionaries having the following set of keys:
            interface (string)
            mac (string)
            ip (string)
            age (float) in seconds
            state (string)
        """
        (interfaces_data,) = self.device.get_paths(
            ["/interface[name=*]/subinterface"], Datastore.STATE
        )

        neighbors = []
        for interface in helpers.value_at(interfaces_data, "interface", default=[]):
            for subinterface in interface.get("subinterface", []):
                nd = helpers.value_at(subinterface, "ipv6", "neighbor-discovery", default={})
                for neighbor in nd.get("neighbor", []):
                    # SR Linux does not expose the entry age; like v1, report the
                    # next-state-time as an epoch timestamp instead.
                    age = -1.0
                    if neighbor.get("next-state-time"):
                        age = helpers.parse_srl_time(neighbor["next-state-time"]).timestamp()
                    neighbors.append(
                        {
                            "interface": subinterface.get("name", ""),
                            "mac": neighbor.get("link-layer-address", ""),
                            "ip": neighbor.get("ipv6-address", ""),
                            "age": age,
                            "state": neighbor.get("current-state", ""),
                        }
                    )
        return neighbors

    def get_bgp_neighbors(self) -> dict[str, models.BGPStateNeighborsPerVRFDict]:
        """
        Returns a dictionary of dictionaries. The keys for the first dictionary
        will be the vrf (global if no vrf).
        """
        bgp_data, information = self.device.get_paths(
            ["/network-instance[name=*]/protocols/bgp", "/system/information"],
            Datastore.STATE,
        )

        current_time = information.get("current-datetime")
        return_data: dict = {"global": {"router_id": "", "peers": {}}}

        for instance in helpers.value_at(bgp_data, "network-instance", default=[]):
            bgp = helpers.value_at(instance, "protocols", "bgp")
            if not bgp:
                continue

            # the SR Linux global routing table is called "default"
            instance_name = instance.get("name")
            if instance_name == "default":
                instance_name = "global"

            global_asn = bgp.get("autonomous-system")
            return_data[instance_name] = {
                "router_id": bgp.get("router-id", ""),
                "peers": {},
            }

            for neighbor in bgp.get("neighbor", []):
                is_up = neighbor.get("session-state") == "established"

                uptime = -1
                if is_up and current_time and neighbor.get("last-established"):
                    uptime = int(
                        helpers.seconds_between(current_time, neighbor["last-established"])
                    )

                address_family = {}
                for afi_safi in neighbor.get("afi-safi", []):
                    afi_name = helpers.strip_module_prefix(afi_safi.get("afi-safi-name", ""))
                    if afi_name == "ipv4-unicast":
                        family = "ipv4"
                    elif afi_name == "ipv6-unicast":
                        family = "ipv6"
                    else:
                        continue
                    address_family[family] = {
                        "received_prefixes": convert(
                            int, afi_safi.get("received-routes"), default=-1
                        ),
                        "accepted_prefixes": convert(
                            int, afi_safi.get("active-routes"), default=-1
                        ),
                        "sent_prefixes": convert(int, afi_safi.get("sent-routes"), default=-1),
                    }

                local_as = helpers.value_at(neighbor, "local-as", "as-number", default=global_asn)
                return_data[instance_name]["peers"][neighbor.get("peer-address")] = {
                    "local_as": as_number(local_as) if local_as else -1,
                    "remote_as": as_number(neighbor.get("peer-as", global_asn or -1)),
                    "remote_id": neighbor.get("peer-remote-id", neighbor.get("peer-address", "")),
                    "is_up": is_up,
                    "is_enabled": neighbor.get("admin-state") == "enable",
                    "description": neighbor.get("description", ""),
                    "uptime": uptime,
                    "address_family": address_family,
                }
        return return_data

    def get_bgp_neighbors_detail(
        self, neighbor_address: str = ""
    ) -> dict[str, dict[int, list[models.PeerDetailsDict]]]:
        """
        Returns a detailed view of the BGP neighbors as a dictionary of lists,
        keyed by network instance and remote AS number.
        """
        (bgp_data,) = self.device.get_paths(
            ["/network-instance[name=*]/protocols/bgp"], Datastore.STATE
        )

        details: dict = {}
        for instance in helpers.value_at(bgp_data, "network-instance", default=[]):
            bgp = helpers.value_at(instance, "protocols", "bgp")
            if not bgp:
                continue

            instance_name = instance.get("name")
            global_asn = bgp.get("autonomous-system")
            router_id = bgp.get("router-id", "")
            details[instance_name] = {}

            for neighbor in bgp.get("neighbor", []):
                peer_ip = neighbor.get("peer-address")
                if not peer_ip or (neighbor_address and neighbor_address != peer_ip):
                    continue

                local_as = helpers.value_at(neighbor, "local-as", "as-number", default=global_asn)
                peer_as = neighbor.get("peer-as", global_asn)

                transport = neighbor.get("transport", {})
                timers = neighbor.get("timers", {})
                sent = neighbor.get("sent-messages", {})
                received = neighbor.get("received-messages", {})
                local_address = transport.get("local-address", "")

                # prefix counts: prefer ipv4-unicast, fall back to ipv6-unicast
                ipv4 = helpers.value_at(neighbor, "ipv4-unicast", default={})
                ipv6 = helpers.value_at(neighbor, "ipv6-unicast", default={})
                afi = ipv4 if ipv4.get("received-routes") is not None else ipv6

                peer_data = {
                    "up": neighbor.get("session-state") == "established",
                    "local_as": as_number(local_as) if local_as else -1,
                    "remote_as": as_number(peer_as) if peer_as else -1,
                    "router_id": router_id,
                    "local_address": local_address,
                    "routing_table": neighbor.get("peer-group", ""),
                    "local_address_configured": not local_address,
                    "local_port": convert(int, transport.get("local-port"), default=-1),
                    "remote_address": peer_ip,
                    "remote_port": convert(int, transport.get("remote-port"), default=-1),
                    "multihop": False,  # not supported in SR Linux
                    "multipath": False,  # not supported in SR Linux
                    "remove_private_as": False,  # not supported in SR Linux
                    "import_policy": str(neighbor.get("import-policy", "")),
                    "export_policy": str(neighbor.get("export-policy", "")),
                    "input_messages": convert(int, received.get("total-messages"), default=-1),
                    "output_messages": convert(int, sent.get("total-messages"), default=-1),
                    "input_updates": convert(int, received.get("total-updates"), default=-1),
                    "output_updates": convert(int, sent.get("total-updates"), default=-1),
                    "messages_queued_out": convert(int, sent.get("queue-depth"), default=-1),
                    "connection_state": neighbor.get("session-state", ""),
                    "previous_connection_state": neighbor.get("last-state", ""),
                    "last_event": neighbor.get("last-event", ""),
                    "suppress_4byte_as": False,  # not supported in SR Linux
                    "local_as_prepend": convert(
                        bool,
                        helpers.value_at(neighbor, "local-as", "prepend-local-as"),
                        default=False,
                    ),
                    "holdtime": convert(int, timers.get("hold-time"), default=-1),
                    "configured_holdtime": convert(
                        int, timers.get("negotiated-hold-time"), default=-1
                    ),
                    "keepalive": convert(int, timers.get("keepalive-interval"), default=-1),
                    "configured_keepalive": convert(
                        int, timers.get("negotiated-keepalive-interval"), default=-1
                    ),
                    "active_prefix_count": convert(int, afi.get("active-routes"), default=-1),
                    "received_prefix_count": convert(int, afi.get("received-routes"), default=-1),
                    "accepted_prefix_count": convert(int, afi.get("active-routes"), default=-1),
                    "suppressed_prefix_count": convert(int, afi.get("rejected-routes"), default=-1),
                    "advertised_prefix_count": convert(int, afi.get("sent-routes"), default=-1),
                    "flap_count": -1,  # not supported in SR Linux
                }

                remote_as = peer_data["remote_as"]
                details[instance_name].setdefault(remote_as, []).append(peer_data)
        return details

    def get_bgp_config(
        self, group: str = "", neighbor: str = ""
    ) -> dict[str, models.BGPConfigGroupDict]:
        """
        Returns a dictionary containing the BGP configuration. Can return either
        the whole config, either the config only for a group or neighbor.
        """

        def prefix_limit(afi: dict) -> dict:
            return {
                "limit": helpers.value_at(afi, "prefix-limit", "max-received-routes", default=-1),
                "teardown": {
                    "threshold": helpers.value_at(
                        afi, "prefix-limit", "warning-threshold-pct", default=-1
                    ),
                    "timeout": -1,
                },
            }

        (bgp_data,) = self.device.get_paths(
            ["/network-instance[name=*]/protocols/bgp"], Datastore.STATE
        )

        groups_data: dict = {}
        for instance in helpers.value_at(bgp_data, "network-instance", default=[]):
            bgp = helpers.value_at(instance, "protocols", "bgp")
            if not bgp:
                continue

            neighbors = bgp.get("neighbor", [])
            multipath = bool(
                helpers.value_at(bgp, "ipv4-unicast", "multipath", "allow-multiple-as")
            )

            for grp in bgp.get("group", []):
                group_name = grp.get("group-name", "")
                group_local_as = helpers.value_at(grp, "local-as", "as-number", default=-1)
                group_remote_as = grp.get("peer-as", -1)

                neighbors_data = {}
                for nbr in (n for n in neighbors if n.get("peer-group") == group_name):
                    nbr_ipv4 = helpers.value_at(nbr, "ipv4-unicast", default={})
                    nbr_ipv6 = helpers.value_at(nbr, "ipv6-unicast", default={})
                    neighbors_data[nbr.get("peer-address", "")] = {
                        "description": nbr.get("description", ""),
                        "import_policy": str(nbr.get("import-policy", "")),
                        "export_policy": str(nbr.get("export-policy", "")),
                        "local_address": helpers.value_at(
                            nbr, "transport", "local-address", default=""
                        ),
                        "local_as": as_number(
                            helpers.value_at(nbr, "local-as", "as-number", default=-1)
                        ),
                        "remote_as": as_number(nbr.get("peer-as", -1)),
                        "authentication_key": "",
                        "prefix_limit": {
                            "inet": {"unicast": prefix_limit(nbr_ipv4)},
                            "inet6": {"unicast": prefix_limit(nbr_ipv6)},
                        },
                        "route_reflector_client": bool(
                            helpers.value_at(nbr, "route-reflector", "client", default=False)
                        ),
                        "nhs": bool(nbr.get("next-hop-self", False)),
                    }

                group_data = {
                    group_name: {
                        "type": "internal" if group_local_as == group_remote_as else "external",
                        "description": grp.get("description", ""),
                        "apply_groups": [],  # not supported
                        "multihop_ttl": -1,  # not supported
                        "multipath": multipath,
                        "local_address": helpers.value_at(
                            grp, "transport", "local-address", default=""
                        ),
                        "local_as": as_number(group_local_as),
                        "remote_as": as_number(group_remote_as),
                        "import_policy": str(grp.get("import-policy", "")),
                        "export_policy": str(grp.get("export-policy", "")),
                        "remove_private_as": False,  # not supported
                        "prefix_limit": {
                            "inet": {
                                "unicast": prefix_limit(
                                    helpers.value_at(grp, "ipv4-unicast", default={})
                                )
                            },
                            "inet6": {
                                "unicast": prefix_limit(
                                    helpers.value_at(grp, "ipv6-unicast", default={})
                                )
                            },
                        },
                        "neighbors": neighbors_data,
                    }
                }

                if group and group == group_name:
                    return group_data
                if neighbor and neighbor in neighbors_data:
                    group_data[group_name]["neighbors"] = {neighbor: neighbors_data[neighbor]}
                    return group_data
                groups_data.update(group_data)

        return {} if group or neighbor else groups_data

    def get_environment(self) -> models.EnvironmentDict:
        """
        Returns a dictionary with fans, temperature, power, cpu and memory data.
        """
        (platform,) = self.device.get_paths(["/platform"], Datastore.STATE)

        environment: dict = {
            "fans": {},
            "power": {},
            "temperature": {},
            "memory": {"available_ram": -1, "used_ram": -1},
            "cpu": {},
        }

        for control in helpers.value_at(platform, "control", default=[]):
            slot = str(control.get("slot", ""))
            if not slot:
                continue

            temperature = control.get("temperature")
            if temperature:
                environment["temperature"][slot] = {
                    "temperature": convert(float, temperature.get("instant"), default=-1.0),
                    "is_alert": convert(bool, temperature.get("alarm-status"), default=False),
                    "is_critical": False,  # not supported in SR Linux
                }

            memory = helpers.value_at(control, "memory", default={})
            if memory:
                physical = convert(int, memory.get("physical"), default=-1)
                free = convert(int, memory.get("free"), default=-1)
                environment["memory"] = {
                    "available_ram": physical,
                    "used_ram": physical - free if physical > -1 and free > -1 else -1,
                }

            for cpu in helpers.value_at(control, "cpu", default=[]):
                environment["cpu"][cpu.get("index")] = {
                    "%usage": convert(
                        float, helpers.value_at(cpu, "total", "instant"), default=-1.0
                    )
                }

        for power_supply in helpers.value_at(platform, "power-supply", default=[]):
            environment["power"][str(power_supply.get("id", ""))] = {
                "status": power_supply.get("oper-state") == "up",
                "capacity": convert(float, power_supply.get("capacity"), default=-1.0),
                "output": -1.0,  # not supported in SR Linux
            }

        for fan_tray in helpers.value_at(platform, "fan-tray", default=[]):
            environment["fans"][str(fan_tray.get("id", ""))] = {
                "status": fan_tray.get("oper-state") == "up"
            }

        return environment

    def get_lldp_neighbors(self) -> dict[str, list[models.LLDPNeighborDict]]:
        """
        Returns a dictionary where the keys are local ports and the value is a list
        of dictionaries with hostname and port of the neighbor.
        """
        (lldp_data,) = self.device.get_paths(["/system/lldp"], Datastore.STATE)

        lldp_neighbors = {}
        for interface in helpers.value_at(lldp_data, "interface", default=[]):
            neighbors = [
                {
                    "hostname": neighbor.get("system-name", ""),
                    "port": neighbor.get("port-id", ""),
                }
                for neighbor in interface.get("neighbor", [])
            ]
            if neighbors:
                lldp_neighbors[interface.get("name")] = neighbors
        return lldp_neighbors

    def get_lldp_neighbors_detail(self, interface: str = "") -> models.LLDPNeighborsDetailDict:
        """
        Returns a detailed view of the LLDP neighbors as a dictionary containing
        lists of dictionaries for each interface.
        """
        (lldp_data,) = self.device.get_paths(["/system/lldp"], Datastore.STATE)

        lldp_neighbors = {}
        for lldp_interface in helpers.value_at(lldp_data, "interface", default=[]):
            interface_name = lldp_interface.get("name")
            if interface and interface_name != interface:
                continue

            neighbors = []
            for neighbor in lldp_interface.get("neighbor", []):
                capabilities = []
                enabled_capabilities = []
                for capability in neighbor.get("capability", []):
                    name = helpers.strip_module_prefix(capability.get("name", "")).lower()
                    capabilities.append(name)
                    if capability.get("enabled") is True:
                        enabled_capabilities.append(name)

                neighbors.append(
                    {
                        "parent_interface": interface_name,
                        "remote_port": neighbor.get("port-id", ""),
                        "remote_port_description": neighbor.get("port-description", ""),
                        "remote_chassis_id": neighbor.get("chassis-id", ""),
                        "remote_system_name": neighbor.get("system-name", ""),
                        "remote_system_description": neighbor.get("system-description", ""),
                        "remote_system_capab": capabilities,
                        "remote_system_enable_capab": enabled_capabilities,
                    }
                )
            if neighbors:
                lldp_neighbors[interface_name] = neighbors
        return lldp_neighbors

    def get_network_instances(self, name: str = "") -> dict[str, models.NetworkInstanceDict]:
        """
        Return a dictionary of network instances (VRFs) configured, including
        default/global.
        """
        (ni_data,) = self.device.get_paths(
            [f"/network-instance[name={name or '*'}]"], Datastore.STATE
        )

        network_instances = {}
        for instance in self._network_instance_list(ni_data, name):
            instance_name = instance.get("name", "")
            network_instances[instance_name] = {
                "name": instance_name,
                "type": helpers.strip_module_prefix(instance.get("type", "")),
                "state": {
                    "route_distinguisher": "",  # not supported in SR Linux
                },
                "interfaces": {
                    "interface": {
                        member.get("name", ""): {} for member in instance.get("interface", [])
                    }
                },
            }
        return network_instances

    @staticmethod
    def _network_instance_list(ni_data, requested_name: str = "") -> list[dict]:
        """Normalize a network-instance query result to a list of instances.

        A wildcard path (`[name=*]`) returns `{"...:network-instance": [...]}`,
        while an exact-name path returns the contents of that single instance
        directly (without its `name` key).
        """
        wrapped = helpers.value_at(ni_data, "network-instance")
        if wrapped is not None:
            return wrapped
        if isinstance(ni_data, dict) and ni_data:
            instance = dict(ni_data)
            instance.setdefault("name", requested_name)
            return [instance]
        return []

    def get_vlans(self) -> dict[int, models.VlanDict]:
        """
        Returns a dictionary of VLANs keyed by VLAN ID.

        SR Linux has no global VLAN table; VLANs exist as single-tagged
        encapsulation on bridged subinterfaces attached to mac-vrf network
        instances. The VLAN name is the name of the (first) mac-vrf carrying
        that VLAN ID and the interfaces are the member subinterfaces. Untagged
        bridged subinterfaces and 'vlan-id any' have no VLAN identity and are
        not reported.
        """
        ni_data, interfaces_data = self.device.get_paths(
            ["/network-instance[name=*]", "/interface[name=*]/subinterface"],
            Datastore.STATE,
        )

        # "<interface>.<subinterface-index>" -> [vlan ids]
        vlan_map: dict[str, list[int]] = {}
        for interface in helpers.value_at(interfaces_data, "interface", default=[]):
            for subinterface in interface.get("subinterface", []):
                encap = helpers.value_at(subinterface, "vlan", "encap", default={})
                vlan_ids = []
                single = helpers.value_at(encap, "single-tagged", "vlan-id")
                if single is not None:
                    vlan_id = convert(int, single, default=None)  # None for "any"
                    if vlan_id is not None:
                        vlan_ids.append(vlan_id)
                ranges = helpers.value_at(encap, "single-tagged-range", "low-vlan-id", default=[])
                for entry in ranges:
                    low = convert(int, entry.get("range-low-vlan-id"), default=None)
                    high = convert(int, entry.get("high-vlan-id"), default=low)
                    if low is None or high is None or not 0 < high - low + 1 <= 4094:
                        continue
                    vlan_ids.extend(range(low, high + 1))
                if vlan_ids:
                    vlan_map[subinterface.get("name", "")] = vlan_ids

        vlans: dict[int, models.VlanDict] = {}
        for instance in self._network_instance_list(ni_data):
            if helpers.strip_module_prefix(instance.get("type", "")) != "mac-vrf":
                continue
            for member in instance.get("interface", []):
                subif_name = member.get("name", "")
                for vlan_id in vlan_map.get(subif_name, []):
                    vlan = vlans.setdefault(
                        vlan_id, {"name": instance.get("name", ""), "interfaces": []}
                    )
                    if subif_name not in vlan["interfaces"]:
                        vlan["interfaces"].append(subif_name)
        return vlans

    def get_users(self) -> dict[str, models.UsersDict]:
        """
        Returns a dictionary with the configured users.
        """
        admin_user, users_data = self.device.get_paths(
            [
                "/system/aaa/authentication/admin-user",
                "/system/aaa/authentication/user[username=*]",
            ],
            Datastore.STATE,
        )

        users_dict = {
            "admin": {
                "level": 15,  # built-in admin user has full access
                "password": admin_user.get("password", ""),
                "sshkeys": list(admin_user.get("ssh-key", [])),
            }
        }

        for user in helpers.value_at(users_data, "user", default=[]):
            roles = user.get("role", [])
            users_dict[user.get("username")] = {
                "level": 15 if any("admin" in str(role) for role in roles) else 0,
                "password": user.get("password", ""),
                "sshkeys": list(user.get("ssh-key", [])),
            }
        return users_dict

    def get_snmp_information(self) -> models.SNMPDict:
        """
        Returns a dict containing SNMP configuration.
        """
        (information,) = self.device.get_paths(["/system/information"], Datastore.STATE)

        return {
            "chassis_id": "",  # not exposed via the SNMP config
            "community": {},  # SR Linux configures SNMP access via access-groups
            "contact": information.get("contact", ""),
            "location": information.get("location", ""),
        }

    def get_config(
        self,
        retrieve: str = "all",
        full: bool = False,
        sanitized: bool = False,
        format: str = "text",
    ) -> models.ConfigDict:
        """
        Return the running configuration of the device.

        The candidate configuration only exists client-side in this driver (see
        load_merge_candidate) and the startup config is not retrievable via
        JSON-RPC, so both are always returned as empty strings.
        """
        config = {"running": "", "candidate": "", "startup": ""}

        if retrieve not in ("all", "running"):
            return config

        if format == "cli" or self.running_format == "cli":
            if sanitized:
                raise NotImplementedError("sanitized=True is not implemented with CLI format")
            result = self.device.run_cli_commands(["info flat"])
            config["running"] = (
                result[0].get("text", "") if isinstance(result[0], dict) else str(result[0])
            )
            return config

        (running,) = self.device.get_paths(["/"], Datastore.RUNNING)
        if sanitized:
            system = helpers.value_at(running, "system", default={})
            for key in list(system):
                if helpers.strip_module_prefix(key) in ("aaa", "tls"):
                    del system[key]
        config["running"] = json.dumps(running)
        return config

    def get_ntp_servers(self) -> dict[str, models.NTPServerDict]:
        """
        Returns the NTP servers configuration as dictionary, keyed by server address.
        """
        (ntp,) = self.device.get_paths(["/system/ntp"], Datastore.STATE)

        return {
            server["address"]: {} for server in (ntp or {}).get("server", []) if "address" in server
        }

    def get_ntp_stats(self) -> list[models.NTPStats]:
        """
        Returns a list of NTP synchronization statistics for preferred servers.
        """
        (ntp,) = self.device.get_paths(["/system/ntp"], Datastore.STATE)
        ntp = ntp or {}

        synchronized = str(ntp.get("synchronized", "")).lower() in (
            "synchronized",
            "synchronised",
        )

        stats = []
        for server in ntp.get("server", []):
            if not server.get("prefer"):
                continue
            stats.append(
                {
                    "remote": server.get("address", ""),
                    "referenceid": "",
                    "synchronized": synchronized,
                    "stratum": convert(int, server.get("stratum"), default=-1),
                    "type": "",
                    "when": "",
                    "hostpoll": convert(int, server.get("poll-interval"), default=-1),
                    "reachability": -1,
                    "delay": -1.0,
                    "offset": convert(float, server.get("offset"), default=-1.0),
                    "jitter": convert(float, server.get("jitter"), default=-1.0),
                }
            )
        return stats

    def get_optics(self) -> dict[str, models.OpticsDict]:
        """
        Fetches the power usage on the various transceivers installed on the
        device (in dBm).
        """
        (interfaces_data,) = self.device.get_paths(["/interface[name=*]"], Datastore.STATE)

        def channel_state(channel: dict, leaf: str) -> dict:
            return {
                "instant": convert(
                    float, helpers.value_at(channel, leaf, "latest-value"), default=-1.0
                ),
                "avg": -1.0,
                "min": -1.0,
                "max": -1.0,
            }

        optics = {}
        for interface in helpers.value_at(interfaces_data, "interface", default=[]):
            channels = helpers.value_at(interface, "transceiver", "channel", default=[])
            if not channels:
                continue
            optics[interface["name"]] = {
                "physical_channels": {
                    "channel": [
                        {
                            "index": convert(int, channel.get("index"), default=-1),
                            "state": {
                                "input_power": channel_state(channel, "input-power"),
                                "output_power": channel_state(channel, "output-power"),
                                "laser_bias_current": channel_state(channel, "laser-bias-current"),
                            },
                        }
                        for channel in channels
                    ]
                }
            }
        return optics

    def get_mac_address_table(self) -> list[models.MACAdressTable]:
        """
        Returns a list of dictionaries, each representing an entry in the MAC
        address table of bridged network instances.
        """
        mac_data, interfaces_data = self.device.get_paths(
            [
                "/network-instance[name=*]/bridge-table/mac-table/mac",
                "/interface[name=*]/subinterface",
            ],
            Datastore.STATE,
        )

        # "<interface>.<subinterface-index>" -> vlan-id
        vlan_map = {}
        for interface in helpers.value_at(interfaces_data, "interface", default=[]):
            for subinterface in interface.get("subinterface", []):
                vlan_id = helpers.value_at(
                    subinterface, "vlan", "encap", "single-tagged", "vlan-id"
                )
                if vlan_id is not None:
                    vlan_map[subinterface["name"]] = convert(int, vlan_id, default=-1)

        mac_table = []
        for instance in helpers.value_at(mac_data, "network-instance", default=[]):
            macs = helpers.value_at(instance, "bridge-table", "mac-table", "mac", default=[])
            for mac in macs:
                destination = str(mac.get("destination", ""))
                mac_type = mac.get("type", "")
                mac_table.append(
                    {
                        "mac": mac.get("address", ""),
                        "interface": destination,
                        "vlan": vlan_map.get(destination, -1),
                        "active": True,
                        "static": bool(mac_type) and mac_type != "learnt",
                        "moves": -1,
                        "last_move": -1.0,
                    }
                )
        return mac_table

    def get_route_to(
        self, destination: str = "", protocol: str = "", longer: bool = False
    ) -> dict[str, models.RouteDict]:
        """
        Returns a dictionary of dictionaries containing details of all available
        routes to a destination.
        """
        if longer:
            raise NotImplementedError("'longer' option is not supported")

        route_tables, information = self.device.get_paths(
            ["/network-instance[name=*]/route-table", "/system/information"],
            Datastore.STATE,
        )

        current_time = information.get("current-datetime")
        instances = helpers.value_at(route_tables, "network-instance", default=[])

        def route_protocol(route: dict) -> str:
            # newer releases use route-type, older ones owner (e.g. "srl_nokia-common:bgp")
            return str(route.get("route-type") or route.get("owner") or "")

        # only fetch protocol details (BGP RIB, ISIS) when needed
        protocol_details: dict[str, dict] = {}
        needs_details = any(
            "bgp" in route_protocol(route) or "isis" in route_protocol(route)
            for instance in instances
            for route in helpers.value_at(
                instance, "route-table", "ipv4-unicast", "route", default=[]
            )
        )
        if needs_details:
            protocols_data, rib_data = self.device.get_paths(
                [
                    "/network-instance[name=*]/protocols",
                    "/network-instance[name=*]/bgp-rib",
                ],
                Datastore.STATE,
            )
            for instance in helpers.value_at(protocols_data, "network-instance", default=[]):
                protocol_details.setdefault(instance.get("name"), {})["protocols"] = instance.get(
                    "protocols", {}
                )
            for instance in helpers.value_at(rib_data, "network-instance", default=[]):
                protocol_details.setdefault(instance.get("name"), {})["bgp-rib"] = helpers.value_at(
                    instance, "bgp-rib", default={}
                )

        route_data: dict = {}
        for instance in instances:
            instance_name = instance.get("name")
            route_table = helpers.value_at(instance, "route-table", default={})
            routes = helpers.value_at(route_table, "ipv4-unicast", "route", default=[])
            next_hop_groups = helpers.value_at(route_table, "next-hop-group", default=[])
            next_hops = helpers.value_at(route_table, "next-hop", default=[])

            for route in routes:
                if "next-hop-group" not in route:
                    continue

                prefix = route.get("ipv4-prefix", "")
                owner = route_protocol(route)

                age = -1
                if current_time and route.get("last-app-update"):
                    age = int(helpers.seconds_between(current_time, route["last-app-update"]))

                group = next(
                    (g for g in next_hop_groups if g.get("index") == route["next-hop-group"]),
                    {},
                )
                next_hop_ids = [n.get("next-hop") for n in group.get("next-hop", [])]
                route_next_hops = [n for n in next_hops if n.get("index") in next_hop_ids]

                entries = []
                for next_hop in route_next_hops:
                    ip_address = next_hop.get("ip-address", "")
                    entry = {
                        "protocol": helpers.strip_module_prefix(owner),
                        "current_active": route.get("active", False),
                        "last_active": False,
                        "age": age,
                        "next_hop": ip_address,
                        "outgoing_interface": next_hop.get("subinterface", ""),
                        "selected_next_hop": bool(ip_address),
                        "preference": convert(int, route.get("preference"), default=-1),
                        "inactive_reason": "",
                        "routing_table": instance_name,
                    }

                    details = protocol_details.get(instance_name, {})
                    if "bgp" in owner:
                        attributes = self._bgp_route_attributes(details, prefix, ip_address)
                        if attributes:
                            attributes["metric"] = convert(int, route.get("metric"), default=-1)
                            entry["protocol_attributes"] = attributes
                    elif "isis" in owner:
                        level = helpers.value_at(
                            details,
                            "protocols",
                            "isis",
                            "instance",
                            0,
                            "level",
                            0,
                            "level-number",
                            default=-1,
                        )
                        entry["protocol_attributes"] = {"level": level}

                    entries.append(entry)

                if destination and destination in (prefix, prefix.split("/")[0]):
                    return {prefix: entries}
                route_data[prefix] = entries

        if protocol:
            return {
                prefix: matching
                for prefix, hops in route_data.items()
                if (matching := [h for h in hops if h["protocol"] == protocol])
            }
        if destination:
            # a matching destination would have returned from the loop already
            return {}
        return route_data

    @staticmethod
    def _bgp_route_attributes(details: dict, prefix: str, next_hop_ip: str) -> dict:
        """Extract BGP protocol attributes for a route from the local RIB."""
        bgp = helpers.value_at(details, "protocols", "bgp", default={})
        rib = details.get("bgp-rib", {})

        neighbor = next(
            (n for n in bgp.get("neighbor", []) if n.get("peer-address") == next_hop_ip),
            None,
        )

        # newer releases nest the per-AFI RIBs in an afi-safi list, older ones
        # have ipv4-unicast at the top level of bgp-rib
        ipv4_rib = next(
            (
                helpers.value_at(afi, "ipv4-unicast", default={})
                for afi in rib.get("afi-safi", [])
                if helpers.strip_module_prefix(afi.get("afi-safi-name", "")) == "ipv4-unicast"
            ),
            helpers.value_at(rib, "ipv4-unicast", default={}),
        )
        rib_routes = helpers.value_at(ipv4_rib, "local-rib", "route", default=None)
        if rib_routes is None:
            rib_routes = helpers.value_at(ipv4_rib, "local-rib", "routes", default=[])
        rib_route = next(
            (
                r
                for r in rib_routes
                if r.get("prefix") == prefix
                and r.get("neighbor") == next_hop_ip
                and helpers.strip_module_prefix(str(r.get("origin-protocol", ""))) == "bgp"
            ),
            None,
        )
        if not neighbor or not rib_route:
            return {}

        attr_sets = helpers.value_at(rib, "attr-sets", "attr-set", default=[])
        attr_set = next((a for a in attr_sets if a.get("index") == rib_route.get("attr-id")), {})

        return {
            "local_as": bgp.get("autonomous-system", -1),
            "remote_as": neighbor.get("peer-as", -1),
            "peer_id": neighbor.get("peer-address", ""),
            "as_path": " ".join(
                str(member)
                for segment in helpers.value_at(attr_set, "as-path", "segment", default=[])
                for member in segment.get("member", [])
            ),
            "communities": helpers.value_at(attr_set, "communities", "community", default=[]),
            "local_preference": attr_set.get("local-pref", -1),
            "preference2": -1,
            "metric": -1,
            "metric2": -1,
        }

    # ------------------------------------------------------------------ operations

    def ping(
        self,
        destination: str,
        source: str = "",
        ttl: int = 255,
        timeout: int = 2,
        size: int = 100,
        count: int = 5,
        vrf: str = "",
        source_interface: str = "",
    ) -> models.PingResultDict:
        """
        Execute a ping against the provided destination from the device.
        """
        ping_source = source_interface or source

        command_parts = [
            f"ping {destination}",
            f"-I {ping_source}" if ping_source else "",
            f"-t {ttl}" if ttl else "",
            f"-W {timeout}" if timeout else "",
            f"-s {size}" if size else "",
            f"-c {count}" if count else "",
            f"network-instance {vrf or 'default'}",
        ]
        command = " ".join(part for part in command_parts if part)

        try:
            result = self.device.run_cli_commands([command])
        except (CommandErrorException, ConnectionException) as exc:
            return {"error": str(exc)}

        text = result[0].get("text", "") if isinstance(result[0], dict) else str(result[0])
        return helpers.parse_ping_output(text)

    def traceroute(
        self,
        destination: str,
        source: str = "",
        ttl: int = 255,
        timeout: int = 2,
        vrf: str = "",
    ) -> models.TracerouteResultDict:
        """
        Execute a traceroute against the provided destination from the device.

        Note: SR Linux traceroute does not support the source and timeout options;
        they are ignored.
        """
        command_parts = [
            f"traceroute {destination}",
            f"-m {ttl}" if ttl else "",
            f"network-instance {vrf or 'default'}",
        ]
        command = " ".join(part for part in command_parts if part)

        try:
            result = self.device.run_cli_commands([command])
        except (CommandErrorException, ConnectionException) as exc:
            return {"error": str(exc)}

        text = result[0].get("text", "") if isinstance(result[0], dict) else str(result[0])
        return helpers.parse_traceroute_output(text)

    def cli(self, commands: list[str], encoding: str = "text") -> dict[str, str | dict]:
        """
        Execute a list of CLI commands and return the output of each one,
        as text or as the structured JSON-RPC result ('json' encoding).

        The JSON-RPC cli method aggregates the output of all commands of one
        request into a single result, so each command is sent as its own request
        to preserve the per-command mapping.
        """
        if encoding not in ("text", "json"):
            raise NotImplementedError(f"{encoding} is not a supported encoding")

        output = {}
        for command in commands:
            results = self.device.run_cli_commands([command], output_format=encoding)
            result = results[0] if results else ""
            if encoding == "json":
                output[command] = result
            else:
                output[command] = result.get("text", "") if isinstance(result, dict) else result
        return output

    # ------------------------------------------------------------------ config management
    #
    # The SR Linux JSON-RPC interface has no persistent candidate datastore across
    # requests: a "set" request against the candidate datastore is transactional
    # and commits on success. The NAPALM candidate workflow is therefore emulated
    # client-side: load_*_candidate() stores the intended changes in the driver,
    # compare_config() uses the JSON-RPC "diff" method, and commit_config()
    # applies everything in a single transactional request after creating a
    # checkpoint that rollback() can restore.

    def load_replace_candidate(self, filename=None, config=None) -> None:
        """
        Accepts either a native JSON formatted config, a gNMI-style JSON config
        containing only 'replaces', or SR Linux CLI commands.

        Starts a fresh candidate: any previously loaded (not yet committed)
        candidate is discarded, as a replace is a new configuration baseline.
        """
        try:
            self._load_candidate(filename, config, is_replace=True)
        except ReplaceConfigException:
            raise
        except Exception as exc:
            raise ReplaceConfigException(
                f"Error during load_replace_candidate operation: {exc}"
            ) from exc

    def load_merge_candidate(self, filename=None, config=None) -> None:
        """
        Accepts either a native JSON formatted config (interpreted as 'update /'),
        a gNMI-style JSON config containing any number of 'deletes', 'replaces'
        and 'updates', or SR Linux CLI commands.

        Merges onto any candidate already loaded in this session: consecutive
        loads accumulate and are committed as one transaction. The merged
        config must use the same format (JSON or CLI) as the pending candidate.
        """
        try:
            self._load_candidate(filename, config, is_replace=False)
        except MergeConfigException:
            raise
        except Exception as exc:
            raise MergeConfigException(
                f"Error during load_merge_candidate operation: {exc}"
            ) from exc

    def _load_candidate(self, filename, config, is_replace: bool) -> None:
        exception = ReplaceConfigException if is_replace else MergeConfigException

        if filename:
            with open(filename) as f:
                config = f.read()
        if not config:
            raise exception("Either 'filename' or 'config' argument must be provided")

        # Parse the new change before touching self._candidate, so a failed
        # second load leaves any previously loaded candidate intact.
        fragment = self._parse_candidate_fragment(config, is_replace, exception)

        # load_replace starts a fresh candidate (a replace is a new baseline,
        # as with EOS 'rollback clean-config' and Junos 'overwrite'); load_merge
        # accumulates onto any candidate already loaded in this session.
        merging = not is_replace and self._candidate is not None

        if merging and self._candidate["mode"] != fragment["mode"]:
            raise exception(
                f"cannot merge {fragment['mode']} config into a pending "
                f"{self._candidate['mode']} candidate; discard it first"
            )

        if fragment["mode"] == "json":
            # Validate what commit_config would send: the accumulated commands,
            # not the fragment alone — a merge may reference config that only
            # exists in an earlier staged load. CLI candidates are validated
            # when they are diffed or committed.
            commands = (self._candidate["commands"] if merging else []) + fragment["commands"]
            try:
                self.device.validate_paths(commands)
            except CommandErrorException as exc:
                raise exception(f"Candidate config failed validation: {exc}") from exc

        if not merging:
            self._candidate = fragment
        elif fragment["mode"] == "json":
            self._candidate["commands"] += fragment["commands"]
        else:
            self._candidate["lines"] += fragment["lines"]

    def _parse_candidate_fragment(self, config, is_replace: bool, exception) -> dict:
        """Parse a config string into a candidate fragment.

        Does not mutate driver state and does not touch the device.
        """
        try:
            cfg = json.loads(config)
        except json.JSONDecodeError:
            # not JSON: treat as CLI commands
            lines = [line.strip() for line in config.splitlines() if line.strip()]
            return {"mode": "cli", "replace": is_replace, "lines": lines}

        if isinstance(cfg, dict) and ("deletes" in cfg or "replaces" in cfg or "updates" in cfg):
            if is_replace and ("deletes" in cfg or "updates" in cfg):
                raise exception("'load_replace_candidate' cannot contain 'deletes' or 'updates'")
            commands = [
                {"action": RPCAction.DELETE.value, "path": entry["path"]}
                for entry in cfg.get("deletes", [])
            ]
            commands += [
                {
                    "action": RPCAction.REPLACE.value,
                    "path": entry["path"],
                    "value": entry["value"],
                }
                for entry in cfg.get("replaces", [])
            ]
            commands += [
                {
                    "action": RPCAction.UPDATE.value,
                    "path": entry["path"],
                    "value": entry["value"],
                }
                for entry in cfg.get("updates", [])
            ]
        else:
            action = RPCAction.REPLACE if is_replace else RPCAction.UPDATE
            commands = [{"action": action.value, "path": "/", "value": cfg}]

        return {"mode": "json", "replace": is_replace, "commands": commands}

    def compare_config(self) -> str:
        """
        Returns a string showing the difference between the running configuration
        and the loaded candidate configuration.
        """
        if self._candidate is None:
            return ""

        if self._candidate["mode"] == "json":
            results = self.device.diff_paths(self._candidate["commands"])
            return "\n".join(
                r.get("text", "") if isinstance(r, dict) else str(r) for r in results if r
            ).strip()

        # CLI mode: load the commands into a throwaway named candidate on the
        # device, diff it against running and discard it again. The named
        # candidate persists across JSON-RPC requests, so it is reset before and
        # discarded after; run_cli_commands returns one result per command
        # string, aligned by position, so the diff text is the last result
        # (the "diff" command is always appended last).
        enter = f"enter candidate private name {self._candidate_name}-diff"
        self._discard_named_candidate(enter)
        try:
            commands = [enter, "/"]
            if self._candidate["replace"]:
                commands.append("delete /")
            commands += self._candidate["lines"]
            commands.append("diff")
            results = self.device.run_cli_commands(commands)
        finally:
            self._discard_named_candidate(enter)

        diff_result = results[-1] if results else ""
        return (
            diff_result.get("text", "") if isinstance(diff_result, dict) else str(diff_result)
        ).strip()

    def _discard_named_candidate(self, enter_command: str) -> None:
        """Discard any (possibly stale) content of a named candidate."""
        try:
            self.device.run_cli_commands([enter_command, "discard now"])
        except CommandErrorException:
            pass

    def commit_config(self, message: str = "", revert_in: int | None = None) -> None:
        """
        Commits the loaded candidate configuration.

        A named checkpoint (NAPALM-<session>-<n>) is created before the change
        so that rollback() can restore the previous state.

        When revert_in is given, the commit is confirmed: the device starts a
        revert timer of that many seconds and reverts the change automatically
        unless confirm_commit() is called in time. With commit_save mode the
        'save startup' is deferred until the commit is confirmed, so startup
        never holds a config that may still auto-revert.
        """
        if revert_in is not None and (not isinstance(revert_in, int) or revert_in <= 0):
            raise CommitConfirmException("'revert_in' must be a positive number of seconds")
        if self._candidate is None:
            raise CommitError("No candidate config loaded; nothing to commit")
        if self.has_pending_commit():
            raise CommitError("Pending commit confirm already in process!")

        # checkpoint the pre-change state as the rollback anchor
        self._checkpoint_id += 1
        checkpoint_name = f"{self._checkpoint_prefix}-{self._checkpoint_id}"
        checkpoint_cmd = f"/tools system configuration generate-checkpoint name {checkpoint_name}"
        if message:
            checkpoint_cmd += f' comment "{message}"'

        try:
            self.device.run_cli_commands([checkpoint_cmd])
            self._last_checkpoint = checkpoint_name

            if self._candidate["mode"] == "json":
                self.device.set_paths(
                    self._candidate["commands"],
                    Datastore.CANDIDATE,
                    confirm_timeout=revert_in,
                )
                if revert_in is None and self.commit_mode == "save":
                    self.device.run_cli_commands(["save startup"])
            else:
                # a named candidate: 'commit confirmed' keeps the candidate
                # session open on the device until accepted/rejected, and a
                # shared 'enter candidate private' session would be silently
                # reused (with its stale baseline) by later config operations
                enter = f"enter candidate private name {self._candidate_name}"
                self._discard_named_candidate(enter)
                commands = [enter, "/"]
                if self._candidate["replace"]:
                    commands.append("delete /")
                commands += self._candidate["lines"]
                if revert_in is not None:
                    # not combinable with save/comment; the message is already
                    # recorded in the checkpoint comment above
                    commands.append(f"commit confirmed timeout {revert_in}")
                else:
                    commit = f"commit {self.commit_mode}"
                    if message:
                        commit += f' comment "{message}"'
                    commands.append(commit)
                self.device.run_cli_commands(commands)
                if revert_in is not None:
                    self._pending_cli_candidate = enter
        except CommandErrorException as exc:
            raise CommitError(f"Commit failed: {exc}") from exc

        self._candidate = None
        self._pending_confirm = revert_in is not None

    def has_pending_commit(self) -> bool:
        """
        Returns True when a confirmed commit is awaiting confirmation on the
        device (regardless of which session started it).
        """
        (data,) = self.device.get_paths(["/system/configuration/commit[id=*]"], Datastore.STATE)
        commits = helpers.value_at(data, "commit", default=[])
        if isinstance(commits, dict):
            commits = [commits]
        return any(
            helpers.strip_module_prefix(str(entry.get("status", ""))) == "unconfirmed"
            for entry in commits
            if isinstance(entry, dict)
        )

    def confirm_commit(self) -> None:
        """
        Confirms a pending confirmed commit, cancelling its revert timer. With
        commit_save mode the config is persisted to startup now (deferred from
        commit_config).
        """
        if not self.has_pending_commit():
            raise CommitError("No pending commit-confirm found")
        try:
            self.device.run_cli_commands(["/tools system configuration confirmed-accept"])
            if self.commit_mode == "save":
                self.device.run_cli_commands(["save startup"])
        except CommandErrorException as exc:
            raise CommitError(f"Confirm failed: {exc}") from exc
        self._close_pending_cli_candidate()
        self._pending_confirm = False

    def _close_pending_cli_candidate(self) -> None:
        """Close the candidate session a CLI-mode confirmed commit left open."""
        if self._pending_cli_candidate:
            self._discard_named_candidate(self._pending_cli_candidate)
            self._pending_cli_candidate = None

    def discard_config(self) -> None:
        """
        Discards the loaded candidate configuration. The candidate only exists
        client-side, so this never touches the device.

        A pending confirmed commit is not affected; use rollback() to reject it
        or let its revert timer expire.
        """
        self._candidate = None

    def rollback(self) -> None:
        """
        Reverts changes made by the most recent commit_config call.

        A pending confirmed commit is rejected immediately (its revert timer is
        cancelled and the change reverted); otherwise the named checkpoint that
        commit_config created is loaded.

        Caveat: checkpoints contain the entire system configuration tree and
        restore the system state to the point at which the checkpoint was created
        (i.e. the most recent commit_config call). Changes made to the config
        after that checkpoint was created will be reverted too.
        """
        if self.has_pending_commit():
            try:
                self.device.run_cli_commands(["/tools system configuration confirmed-reject"])
            except CommandErrorException as exc:
                raise CommitError(f"Rollback (confirmed-reject) failed: {exc}") from exc
            self._close_pending_cli_candidate()
            self._pending_confirm = False
            return

        if not self._last_checkpoint:
            raise CommitError("No checkpoint recorded; nothing to roll back to")

        enter = f"enter candidate private name {self._candidate_name}"
        self._discard_named_candidate(enter)
        try:
            self.device.run_cli_commands(
                [
                    enter,
                    f"load checkpoint name {self._last_checkpoint}",
                    f"commit {self.commit_mode}",
                ]
            )
        except CommandErrorException as exc:
            raise CommitError(f"Rollback failed: {exc}") from exc
