# -*- coding: utf-8 -*-
# Copyright 2021 Nokia. All rights reserved.
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

"""
Napalm driver for Nokia SR Linux.

Read https://napalm.readthedocs.io for more information.
"""

import datetime
import enum
import logging
import re
from typing import AnyStr, Optional, Union

import httpx
import jsonpath_ng
from napalm.base import NetworkDriver
from napalm.base.exceptions import (
    CommandErrorException,
    CommitError,
    ConnectionException,
    MergeConfigException,
    ReplaceConfigException,
)


class NokiaSRLinuxDriver(NetworkDriver):
    """Napalm driver for Nokia SR Linux."""

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        """Constructor."""
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.running_format = (
            optional_args.get("running_format", "json") if optional_args else "json"
        )
        self.device: SRLinuxDevice = SRLinuxDevice(
            hostname, username, password, timeout=60, optional_args=optional_args
        )

    def open(self) -> None:
        self.device.open()

    def close(self) -> None:
        self.device.close()

    def get_arp_table(self, vrf: Optional[AnyStr] = "") -> list:
        """
        Returns a list of dictionaries having the following set of keys:
            interface (string)
            mac (string)
            ip (string)
            age (float)
        'vrf' of null-string will default to all VRFs.
        Specific 'vrf' will return the ARP table entries for that VRFs
         (including potentially 'default' or 'global').

        In all cases the same data structure is returned and no reference to the VRF that was
        used is included in the output.
        """
        raise NotImplementedError

    def get_bgp_neighbors(self) -> dict:
        """
        Returns a dictionary of dictionaries. The keys for the first dictionary will be the vrf
        (global if no vrf). The inner dictionary will contain the following data for each vrf:

            router_id
            peers - another dictionary of dictionaries. Outer keys are the IPs of the neighbors.
            The inner keys are:
                local_as (int)
                remote_as (int)
                remote_id - peer router id
                is_up (True/False)
                is_enabled (True/False)
                description (string)
                uptime (int in seconds)
                address_family (dictionary) - A dictionary of address families available for
                the neighbor.
                So far it can be 'ipv4' or 'ipv6'
                    received_prefixes (int)
                    accepted_prefixes (int)
                    sent_prefixes (int)
            Note, if is_up is False and uptime has a positive value then this indicates the
            uptime of the last active BGP session.
        """

        return_data = {"global": {"router_id": "", "peers": {}}}

        jrpc_output = self.device.get_paths(
            ["/network-instance[name=*]/protocols/bgp", "/system/information"],
            SRLinuxDevice.RPCDatastore.STATE,
        )

        # TODO: handle exception

        bgp_data = jrpc_output[0]
        system_data = jrpc_output[1]

        if not system_data.get("current-datetime"):
            raise Exception("Missing 'current-datetime' key in /system/information")

        system_date_time = datetime.datetime.strptime(
            system_data.get("current-datetime"), "%Y-%m-%dT%H:%M:%S.%fZ"
        )

        for network_instance in bgp_data["srl_nokia-network-instance:network-instance"]:
            instance_name = network_instance.get("name")

            # SRLinux global route tables is called "default"
            if instance_name == "default":
                instance_name = "global"

            router_id = NokiaSRLinuxDriver._get_value_from_jsonpath(
                "$.protocols.srl_nokia-bgp:bgp.router-id", network_instance
            )
            global_asn = NokiaSRLinuxDriver._get_value_from_jsonpath(
                "$.protocols.srl_nokia-bgp:bgp.autonomous-system", network_instance
            )

            return_data.update({instance_name: {"router_id": router_id, "peers": {}}})

            # extract BGP Neighbours
            bgp_neighbors = NokiaSRLinuxDriver._get_by_jsonpath(
                "$.protocols.srl_nokia-bgp:bgp.neighbor[*]", network_instance
            )

            for neighbor in bgp_neighbors:
                cur_neighbor = {
                    "local_as": neighbor.get("local-as", {}).get(
                        "as-number", global_asn
                    ),
                    "remote_as": neighbor.get("peer-as", global_asn),
                    "remote_id": neighbor.get(
                        "peer-remote-id", neighbor.get("peer-address")
                    ),
                    "is_up": True
                    if neighbor.get("session-state", "nil") == "established"
                    else False,
                    "is_enabled": True
                    if neighbor.get("admin-state", False) == "enable"
                    else False,
                    "description": neighbor.get("description", ""),
                    "uptime": -1,
                    "address_family": {},
                }

                if cur_neighbor["is_up"]:
                    last_established = datetime.datetime.strptime(
                        neighbor.get("last-established"), "%Y-%m-%dT%H:%M:%S.%fZ"
                    )
                    cur_neighbor["uptime"] = (
                        system_date_time - last_established
                    ).seconds

                for afi_safi in neighbor.get("afi-safi", []):
                    # IPv4
                    if afi_safi.get("afi-safi-name") == "srl_nokia-common:ipv4-unicast":
                        cur_neighbor["address_family"]["ipv4"] = {
                            "received_prefixes": afi_safi.get("received-routes", -1),
                            "sent_prefixes": afi_safi.get("sent-routes", -1),
                            "accepted_prefixes": afi_safi.get("accepted-routes", 0),
                        }
                    # IPv6
                    if afi_safi.get("afi-safi-name") == "srl_nokia-common:ipv6-unicast":
                        cur_neighbor["address_family"]["ipv6"] = {
                            "received_prefixes": afi_safi.get("received-routes", -1),
                            "sent_prefixes": afi_safi.get("sent-routes", -1),
                            "accepted_prefixes": afi_safi.get("accepted-routes", 0),
                        }

                return_data[instance_name]["peers"][neighbor.get("peer-address")] = (
                    cur_neighbor
                )
        return return_data

    def get_bgp_neighbors_detail(self, neighbor_address: Optional[AnyStr] = "") -> dict:
        """
        :param neighbor_address:
        :return:
            Returns a dictionary of dictionaries. The keys for the first dictionary will be the vrf (global if no vrf).
            The keys of the inner dictionary represent the AS number of the neighbors.
            Leaf dictionaries contain the following fields:
                up (True/False)
                local_as (int)
                remote_as (int)
                router_id (string)
                local_address (string)
                routing_table (string)
                local_address_configured (True/False)
                local_port (int)
                remote_address (string)
                remote_port (int)
                multihop (True/False)
                multipath (True/False)
                remove_private_as (True/False)
                import_policy (string)
                export_policy (string)
                input_messages (int)
                output_messages (int)
                input_updates (int)
                output_updates (int)
                messages_queued_out (int)
                connection_state (string)
                previous_connection_state (string)
                last_event (string)
                suppress_4byte_as (True/False)
                local_as_prepend (True/False)
                holdtime (int)
                configured_holdtime (int)
                keepalive (int)
                configured_keepalive (int)
                active_prefix_count (int)
                received_prefix_count (int)
                accepted_prefix_count (int)
                suppressed_prefix_count (int)
                advertised_prefix_count (int)
                flap_count (int)

        """
        raise NotImplementedError

    def get_environment(self):
        """
        Returns a dictionary where:

            fans is a dictionary of dictionaries where the key is the location and the values:
                status (True/False) - True if it's ok, false if it's broken
            temperature is a dict of dictionaries where the key is the location and the values:
                temperature (float) - Temperature in celsius the sensor is reporting.
            is_alert (True/False) - True if the temperature is above the alert threshold
            is_critical (True/False) - True if the temp is above the critical threshold
            power is a dictionary of dictionaries where the key is the PSU id and the values:
                status (True/False) - True if it's ok, false if it's broken
                capacity (float) - Capacity in W that the power supply can support
                output (float) - Watts drawn by the system
            cpu is a dictionary of dictionaries where the key is the ID and the values
                %usage
            memory is a dictionary with:
                available_ram (int) - Total amount of RAM installed in the device
                used_ram (int) - RAM in use in the device
        """
        raise NotImplementedError

    def get_facts(self):
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

        raise NotImplementedError

    def get_interfaces(self) -> dict:
        """
        Returns a dictionary of dictionaries.
        The keys for the first dictionary will be the interfaces in the devices.
        The inner dictionary contains the following data for each interface:
            is_up (True/False)
            is_enabled (True/False)
            description (string)
            last_flapped (float in seconds)
            speed (float in Mbit)
            MTU (in Bytes)
            mac_address (string)
        """

        interfaces = {}

        json_data = self.device.get_paths(
            [
                "/interface[name=*]",
                "/system/information",
            ],
            SRLinuxDevice.RPCDatastore.STATE,
        )

        # TODO: handle exception

        interfaces_json = json_data[0]
        system_data = json_data[1]

        for interface in interfaces_json.get("srl_nokia-interfaces:interface"):
            interfaces[interface.get("name")] = {
                "is_up": True if interface.get("oper-state") == "up" else False,
                "is_enabled": True
                if interface.get("admin-state") == "enable"
                else False,
                "description": interface.get("description"),
                "last-flapped": NokiaSRLinuxDriver._calculate_time_since(
                    system_data.get("current-datetime"), interface.get("last-change")
                ),
                "speed": NokiaSRLinuxDriver._port_speed_to_mbits(
                    interface.get("ethernet", {}).get("port-speed")
                ),
                "mtu": interface.get("mtu"),
                "mac_address": interface.get("ethernet", {}).get("hw-mac-address"),
            }

        return interfaces

    def get_interfaces_counters(self):
        """
        Returns a dictionary of dictionaries where the first key is an interface name
        and the inner dictionary contains the following keys:
            tx_errors (int)
            rx_errors (int)
            tx_discards (int)
            rx_discards (int)
            tx_octets (int)
            rx_octets (int)
            tx_unicast_packets (int)
            rx_unicast_packets (int)
            tx_multicast_packets (int)
            rx_multicast_packets (int)
            tx_broadcast_packets (int)
            rx_broadcast_packets (int)
        """
        raise NotImplementedError

    def get_interfaces_ip(self):
        """
        Returns all configured IP addresses on all interfaces as a dictionary of dictionaries.
        of the main dictionary represent the name of the interface.
        Values of the main dictionary represent are dictionaries that may consist of two keys
        'ipv4' and 'ipv6' (one, both or none) which are themselves dictionaries with the IP addresses as keys.
        Each IP Address dictionary has the following keys:
            prefix_length (int)
        """
        raise NotImplementedError

    def get_ipv6_neighbors_table(self):
        """
        Get IPv6 neighbors table information.

        Return a list of dictionaries having the following set of keys:

            interface (string)
            mac (string)
            ip (string)
            age (float) in seconds
            state (string)
        """
        raise NotImplementedError

    def get_lldp_neighbors(self) -> dict:
        """
        Returns a dictionary where the keys are local ports and the value is a list of dictionaries
        with the following information:
                hostname
                port
        """
        lldp_neighbors = {}
        json_output = self.device.get_paths(
            ["/system/lldp"], SRLinuxDevice.RPCDatastore.STATE
        )

        # TODO: Handle exception

        if not json_output:
            # no lldp interfaces
            return {}

        lldp_interfaces = json_output[0].get("interface")

        for interface in lldp_interfaces:
            if not interface.get("neighbor"):
                continue

            neighbors = []

            for neighor in interface.get("neighbor"):
                neighbors.append(
                    {
                        "port": neighor.get("port-id"),
                        "hostname": neighor.get("system-name"),
                    }
                )
            lldp_neighbors[interface.get("name")] = neighbors

        return lldp_neighbors

    def get_lldp_neighbors_detail(self, interface: Optional[AnyStr] = "") -> dict:
        """
        Returns a detailed view of the LLDP neighbors as a dictionary containing lists
        of dictionaries for each interface.

        Empty entries are returned as an empty string (e.g. '') or list where applicable.

        Inner dictionaries contain fields:
            parent_interface (string)
            remote_port (string)
            remote_port_description (string)
            remote_chassis_id (string)
            remote_system_name (string)
            remote_system_description (string)
            remote_system_capab (list) with any of these values
                other
                repeater
                bridge
                wlan-access-point
                router
                telephone
                docsis-cable-device
                station
            remote_system_enabled_capab (list)
        """
        lldp_neighbors = {}
        json_output = self.device.get_paths(
            ["/system/lldp"], SRLinuxDevice.RPCDatastore.STATE
        )

        # TODO: handle exception

        if not json_output:
            # no lldp interfaces
            return {}

        lldp_interfaces = json_output[0].get("interface")

        # TODO: respect the 'interface' param
        for interface in lldp_interfaces:
            if not interface.get("neighbor"):
                continue

            neighbors = []

            for neighor in interface.get("neighbor"):
                neighbors.append(
                    {
                        "parent_interface": interface.get("name"),
                        "remote_port": neighor.get("port-id"),
                        "remote_port_description": neighor.get("port-description", ""),
                        "remote_chassis_id": neighor.get("chassis-id", ""),
                        "remote_system_name": neighor.get("system-name", ""),
                        "remote_system_description": neighor.get(
                            "system-description", ""
                        ),
                        "remote_system_capab": [
                            cap.get("name").split(":")[1].lower()
                            for cap in neighor.get("capability", [])
                        ],
                    }
                )
            lldp_neighbors[interface.get("name")] = neighbors

        return lldp_neighbors

    def get_network_instances(self, name=""):
        """
        Return a dictionary of network instances (VRFs) configured, including default/global
            Parameters:	name (string) –
            Returns:
                name (dict)
                    name (unicode)
                    type (unicode)
                    state (dict)
                        route_distinguisher (unicode)
                    interfaces (dict)
                        interface (dict)
                            interface name: (dict)
        """
        raise NotImplementedError

    def get_users(self) -> dict:
        """
        Returns a dictionary with the configured users.
        The keys of the main dictionary represents the username.
        The values represent the details of the user, represented by the following keys:
            level (int)
            password (str)
            sshkeys (list)
        The level is an integer between 0 and 15, where 0 is the lowest access
        and 15 represents full access to the device.
        """

        users_dict = {}

        paths_data = self.device.get_paths(
            [
                "/system/aaa/authentication/admin-user",
                "/system/aaa/authentication/user[username=*]",
            ],
            SRLinuxDevice.RPCDatastore.STATE,
        )

        # TODO: handle thrown exception

        # first result is the admin user
        admin_user = paths_data[0]
        users_dict.update(
            {
                "admin": {
                    "level": 0,  # Not supported by SRLinux
                    "password": admin_user["password"],
                    "ssh-keys": [k for k in admin_user["ssh-key"]],
                }
            }
        )

        # all other users
        for user in paths_data[1]["user"]:
            users_dict.update(
                {
                    user["username"]: {
                        "level": 0,
                        "password": user["password"],
                        "ssh-keys": [k for k in user.get("ssh-key", [])],
                    }
                }
            )

        return users_dict

    def get_bgp_config(self, group="", neighbor=""):
        """
        Returns a dictionary containing the BGP configuration. Can return either the whole config, either the config only for a group or neighbor.

        :param neighbor: specific BGP neighbor.
        :param group: specific BGP group.
        :return: Returns the configuration of a specific BGP neighbor /BGP group
        """
        raise NotImplementedError

    def get_snmp_information(self):
        """
        :return:
        Returns a dict of dicts containing SNMP configuration. Each inner dictionary contains these fields

        chassis_id (string)
        community (dictionary)
        contact (string)
        location (string)
        """
        raise NotImplementedError

    def get_config(
        self,
        retrieve: str = "all",
        full: bool = False,
        sanitized: bool = False,
        format: str = "text",
    ):
        """
        :param retrieve: Which configuration type you want to populate, default is all of them. The rest will be set to “”.
        :param full:Retrieve all the configuration. For instance, on ios, “sh run all”.
        :param sanitized:Remove secret data. Default: False.
        :return:Return the configuration of a device.
        """
        raise NotImplementedError

    def get_ntp_servers(self):
        """
        :return:Returns the NTP servers configuration as dictionary. The keys of the dictionary represent the IP Addresses of the servers. Inner dictionaries do not have yet any available keys.
        """
        raise NotImplementedError

    def get_ntp_stats(self):
        """
        :return:Returns a list of NTP synchronization statistics.
        """
        raise NotImplementedError

    def get_optics(self):
        """
        :return:Fetches the power usage on the various transceivers installed on the switch (in dbm), and returns a view that conforms with the openconfig model openconfig-platform-transceiver.yang
        """
        raise NotImplementedError

    def get_mac_address_table(self):
        """
        Returns a lists of dictionaries. Each dictionary represents an entry in the MAC Address Table,
        having the following keys:
            mac (string)
            interface (string)
            vlan (int)
            active (boolean)
            static (boolean)
            moves (int)
            last_move (float)
        """
        raise NotImplementedError

    def get_route_to(self, destination="", protocol="", longer=False):
        """
        Returns a dictionary of dictionaries containing details of all available routes to a destination.
        """
        raise NotImplementedError

    def is_alive(self) -> dict:
        """
        Tests if the device is reachable. Returns a dict with a single key: 'is_alive', value is a bool.
        """
        try:
            alive = self.device.open()
            return {"is_alive": alive}
        except Exception:
            return {"is_alive": False}

    def traceroute(self, destination, source="", ttl=255, timeout=2, vrf=""):
        raise NotImplementedError

    def ping(
        self,
        destination: str,
        source: Optional[str] = "",
        ttl: Optional[int] = 255,
        timeout: Optional[int] = 2,
        size: Optional[int] = 100,
        count: Optional[int] = 5,
        vrf: Optional[AnyStr] = "default",
        source_interface: Optional[AnyStr] = "",
    ) -> dict:
        """
        Executes a ping against the provided destination
        Returns a dictionary in the required NAPALM format.
        TODO: update with format
        """
        # prefer source_interface if given
        ping_src = ""
        if source_interface:
            ping_src = source_interface
        elif source:
            ping_src = source

        ping_cmd = [
            f"ping {destination}",
            f"-I {ping_src}" if ping_src else "",
            f"-t {ttl}" if ttl else "",
            f"-W {timeout}" if timeout else "",
            f"-s {size}" if size else "",
            f"-c {count}" if count else "",
            f"network-instance {vrf}",
        ]
        try:
            result = self.device.run_cli_commands([" ".join(ping_cmd)])
        except Exception as e:
            return {"error": str(e)}
        ping_text = result[0].get("text")
        re_pattern = "(\d+) packets transmitted, (\d+) received, (\d*\.?\d*)% packet loss, time (\w+)ms(\nrtt min/avg/max/mdev = (\d*\.?\d*)/(\d*\.?\d*)/(\d*\.?\d*)/(\d*\.?\d*))?"
        re_match = re.search(re_pattern, ping_text)

        # If DNS doesn't resolve or a host isn't in the route-table, fail the request.
        if not re_match:
            return {"error": "Unable to complete request"}

        groups = re_match.groups()
        pings_pattern = (
            "(\d+\.\d+\.\d+\.\d+)\)?: icmp_seq=\d+ ttl=\d+ time=(\d+\.\d+) ms"
        )
        pings = re.findall(pings_pattern, ping_text)

        # SRL doesn't print stats if at least one ping isn't successful.
        has_stats = len(groups) == 9

        ping_results = [{"ip_address": p[0], "rtt": p[1]} for p in pings]
        return {
            "success": {
                "probes_sent": groups[0],
                "packet_loss": int(groups[0]) - int(groups[1]),
                "rtt_min": groups[5] if has_stats else -1.0,
                "rtt_max": groups[7] if has_stats else -1.0,
                "rtt_avg": groups[6] if has_stats else -1.0,
                "rtt_stddev": groups[8] if has_stats else -1.0,
                "results": ping_results,
            }
        }

    def cli(self, commands, encoding="text"):
        """
        Will execute a list of commands and return the output in a dictionary format.
        """
        raise NotImplementedError

    def compare_config(self) -> AnyStr:
        """
        Compares the current running configuration with the loaded candidate configuration.
        Returns a string that represents the diff between these config datastore's.
        """
        raise NotImplementedError

    def load_replace_candidate(self, filename=None, config=None):
        """
        Accepts either a native JSON formatted config, or a gNMI style JSON config
        containing only 'replaces'
        """
        raise NotImplementedError

    def load_merge_candidate(self, filename=None, config=None):
        """
        Accepts either a native JSON formatted config (interpreted as 'update /')
        or a gNMI style JSON config containing any number of 'deletes','replaces','updates'
        """
        raise NotImplementedError

    def commit_config(self, message="", revert_in=None):
        """
        This method creates a system-wide checkpoint containing the current state before this configuration change.
        """
        raise NotImplementedError

    def discard_config(self):
        """
        Discards the current candidate configuration changes.
        """
        raise NotImplementedError

    def rollback(self):
        """
        Reverts changes made by the most recent commit_config call, by loading the named checkpoint that was created

        Caveat: Checkpoints contain the entire system configuration tree, and restore the system state to the point at which
                the (named) checkpoint was created (i.e. most recent commit_config call)
                If changes were made to the config after that checkpoint was created, those changes will be reverted too (!)

        In a highly concurrent environment in which multiple systems are provisioning nodes, it may be better to implement fine-grained
        rollback consisting of only incremental changes, rather than the entire system state. In that case, 'rollback' would be implemented
        by another call to commit_config, containing the original config subtree.
        """
        return NotImplementedError

    @staticmethod
    def _jsonpath_expr(jsonpath: AnyStr) -> jsonpath_ng.jsonpath.Child:
        """
        Builds and escapes a provided JSONPath string and returns a jsonpath.Child object.
        """
        # need to single-quote keys with ':' in them
        keys = jsonpath.split(".")

        quoted_keys = []
        for k in keys:
            # find keys with [...] at the end
            if "[" in k and ":" in k:
                x = re.findall("(.*)(\[.*])", k)
                # quote the key portion, leaving the slice indicator unquoted
                quoted_key = f"['{x[0][0]}']{x[0][1]}"
                quoted_keys.append(quoted_key)
            elif ":" in k:
                # quote keys with : in them
                quoted_keys.append(f"['{k}']")
            else:
                # don't touch otherwise
                quoted_keys.append(k)

        return jsonpath_ng.parse(".".join(quoted_keys))

    @staticmethod
    def _get_by_jsonpath(jsonpath: AnyStr, data: dict) -> list:
        """
        Fetch a subtree from a jsonpath string and return a list of results.
        """
        expr = NokiaSRLinuxDriver._jsonpath_expr(jsonpath)
        matches = expr.find(data)
        return [m.value for m in matches]

    @staticmethod
    def _get_value_from_jsonpath(jsonpath: AnyStr, data: dict) -> Union[None, AnyStr]:
        """
        Get a single value from a jsonpath string and return it.
        """
        expr = NokiaSRLinuxDriver._jsonpath_expr(jsonpath)
        matches = expr.find(data)

        return matches[0].value if matches else None

    @staticmethod
    def _calculate_time_since(system_time: AnyStr, reference_time: AnyStr) -> int:
        """
        Calculate the difference between a timestamp and the system's time.
        SRL timestamps are in the format "%Y-%m-%dT%H:%M:%S.%fZ"
        """
        system_datetime = datetime.datetime.strptime(
            system_time, "%Y-%m-%dT%H:%M:%S.%fZ"
        )
        ref_datetime = datetime.datetime.strptime(
            reference_time, "%Y-%m-%dT%H:%M:%S.%fZ"
        )
        return (ref_datetime - system_datetime).seconds

    @staticmethod
    def _port_speed_to_mbits(port_speed: str) -> float:
        """
        Convert a string port-speed to a floating point of Megabits
        """
        port_speeds = {
            "10M": 10000.0,
            "100M": 100000.0,
            "1G": 1000000.0,
            "10G": 10000000.0,
            "25G": 25000000.0,
            "40G": 40000000.0,
            "50G": 50000000.0,
            "100G": 100000000.0,
            "200G": 200000000.0,
            "400G": 400000000.0,
            "800G": 800000000.0,
            "1T": 1000000000.0,
        }
        return port_speeds.get(port_speed)


class SRLinuxDevice(object):
    """
    Represents a Nokia SR Linux device and abstracts the connection Protocol
    used to talk to the device.
    """

    class RPCMethod(str, enum.Enum):
        """
        Enum class used to represent RPC Methods
        """

        GET = "get"
        SET = "set"
        VALIDATE = "validate"
        CLI = "cli"

    class RPCAction(str, enum.Enum):
        """
        Enum class used to represent RPC Actions
        """

        REPLACE = "replace"
        UPDATE = "update"
        DELETE = "delete"

    class RPCDatastore(str, enum.Enum):
        """
        Enum class used to represent SR Linux Data stores for RPC calls.
        """

        CANDIDATE = "candidate"
        RUNNING = "running"
        STATE = "state"
        TOOLS = "tools"

    def __init__(
        self,
        hostname: str,
        username: str,
        password: str,
        timeout: Optional[int] = 60,
        optional_args: Optional[dict] = None,
    ):
        """Constructor."""
        self.device = None
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout

        if optional_args is None:
            optional_args = {}

        # Optional Arguments
        self.jsonrpc_port = optional_args.get("jsonrpc_port", 443)
        self.skip_verify = optional_args.get("skip_verify", False)
        self.insecure = optional_args.get("insecure", False)
        self.tls_ca = optional_args.get("tls_ca", "")
        self.tls_cert_path = optional_args.get("tls_cert_path", "")
        self.tls_key_path = optional_args.get("tls_key_path", "")
        self.tls_key_password = optional_args.get("tls_key_password", "")

        self.jsonrpc_session = self._new_jsonrpc_client()

        # Warn about incompatible/oddball settings
        if self.jsonrpc_port == 80:
            if not self.insecure:
                logging.warning(
                    "Secure JSON RPC uses port 443, not 80."
                    + "Set 'insecure=True' flag to indicate this is ok"
                )
        elif self.jsonrpc_port != 443:
            logging.warning(
                f"Non-default JSON RPC port configured ({self.jsonrpc_port}), typically only 443(default) or 80 are used"
            )

        if not self.insecure:
            if not self.tls_ca:
                logging.warning(
                    "Incompatible settings: insecure=False "
                    + "requires certificate parameter 'tls_ca' to be set "
                    + "when using self-signed certificates"
                )

    def open(self):
        """Check the supplied init params actually work, throw an exception if not."""
        # Set up a JSON RPC Client and test connectivity to the endpoint.
        path = "/system/information/version"
        ok, data = self.get_paths([path], SRLinuxDevice.RPCDatastore.STATE)

        if ok:
            return True
        else:
            raise Exception(
                "Error opening connection. Error: " + data.get("error").get("message")
            )

    def close(self):
        """Cleanup the HTTP Client"""
        self.jsonrpc_session.close()

    def get_paths(self, paths: list, datastore: RPCDatastore) -> list:
        """
        Get the subtrees from a list of YANG paths from the specified datastore.
        Returns a list of results.
        """
        commands = [{"path": p, "datastore": datastore} for p in paths]

        ok, result = self._jsonrpc_request(
            SRLinuxDevice.RPCMethod.GET, {"commands": commands}
        )

        if ok:
            return result.get("result")
        else:
            raise Exception(
                "Error getting subtrees from YANG path. Error: " + result.get("error")
            )

    def run_cli_commands(self, commands: list) -> list:
        """
        Runs a list of  CLI commands on the device, returns the result or raises an exception if
        a command isn't valid or fails. Returns a list of results.
        """
        ok, response = self._jsonrpc_request(
            SRLinuxDevice.RPCMethod.CLI, {"commands": commands}
        )

        if ok:
            return response.get("result")
        else:
            raise Exception(response.get("error", {}).get("message"))

    def _jsonrpc_request(self, method: RPCMethod, params: dict) -> (bool, dict):
        """
        Make a JSON RPC request, raise an exception if the HTTP request returns anything other than 2xx
        Return a boolean success value (if HTTP 2xx) and the result.
        """
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        request_data = {
            "jsonrpc": "2.0",
            "id": datetime.datetime.now().strftime("%s"),
            "method": method,
            "params": params,
        }

        proto = (
            "https"
            if (
                self.jsonrpc_port == 443
                or (self.jsonrpc_port != 80 and not self.insecure)
            )
            else "http"
        )
        url = f"{proto}://{self.hostname}:{self.jsonrpc_port}/jsonrpc"

        result = self.jsonrpc_session.post(
            url, headers=headers, json=request_data, timeout=self.timeout
        )

        if result.status_code == httpx.codes.OK and result.json().get("error"):
            return False, result.json()
        elif result.status_code == httpx.codes.OK:
            return True, result.json()
        elif result.status_code == httpx.codes.BAD_REQUEST:
            raise Exception("Request raised HTTP/400 BAD REQUEST")
        else:
            raise Exception(f"Request raised unknown status code {result.status_code}")

    def _new_jsonrpc_client(self):
        """
        Create a JSON RPC Client, preconfigured with TLS if required.
        """
        cert = None
        if not self.insecure:
            cert = (
                (self.tls_cert_path, self.tls_key_path, self.tls_key_password)
                if self.tls_key_password
                else (self.tls_cert_path, self.tls_key_path)
            )

        opts = {"verify": (not self.insecure), "auth": (self.username, self.password)}

        if cert:
            opts["cert"] = cert

        return httpx.Client(**opts)
