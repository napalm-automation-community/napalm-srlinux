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
Napalm driver for SR Linux.

Read https://napalm.readthedocs.io for more information.
"""
import base64
import json
import logging
import os
import re
import datetime
import grpc
from google.protobuf import json_format
from napalm_srl import gnmi_pb2, jsondiff

from napalm.base import NetworkDriver
from napalm.base.helpers import convert, mac, as_number
from napalm.base.exceptions import (
    ConnectionException,
    MergeConfigException,
    ReplaceConfigException,
    CommandErrorException,
    CommitError,
)

import requests

from requests.packages.urllib3.poolmanager import PoolManager
from requests.packages.urllib3.util import ssl_
from requests.adapters import HTTPAdapter

class TLSHttpAdapter(HTTPAdapter):
    """
    "Transport adapter" to re-enable the ECDHE-RSA-AES256-SHA cipher as fallback

    urllib3 version 2.0.2 reduced the list of ciphers offered by default,
    removing the ECDHE-RSA-AES256-SHA cipher. When the cipher list is left empty
    in SR Linux CLI, by default it only accepts this cipher
    """
    def __init__(self, ciphers=None, **kwargs):
        self.ciphers = ciphers
        super(TLSHttpAdapter, self).__init__(**kwargs)

    def init_poolmanager(self, connections, maxsize, block=False):
        logging.warning( f"Enabled TLS ciphers: {self.ciphers}" )
        ctx = ssl_.create_urllib3_context(ciphers=self.ciphers,cert_reqs=ssl_.CERT_REQUIRED)
        ctx.check_hostname = False # for some reason, CERT_REQUIRED becomes None
        self.poolmanager = PoolManager(
           num_pools=connections, maxsize=maxsize,
           ssl_context=ctx, block=block)

class NokiaSRLDriver(NetworkDriver):
    """Napalm driver for SRL."""

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        """Constructor."""
        self.device = None
        self._metadata = None
        # still need to figure out why these variables are used
        self.config_session = None
        self.locked = False
        self.profile = ["srl"]
        self.platform = "srl"

        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.private_candidate_name = None

        self._stub = None
        self._channel = None
        self.running_format = optional_args.get("running_format","json") if optional_args else "json"

        self.device = SRLAPI(hostname, username, password, timeout=60, optional_args=optional_args)

        self.pending_commit = False
        self.cand_config_file_path = f"/tmp/{hostname}.json"
        self.chkpoint_id = 0

    def open(self):
        self.device.open()

    def close(self):
        self.device.close()

    def _find_txt(self, value_dict, key, default=""):
        value = ""
        try:
            if isinstance(value_dict, dict):
                value = value_dict.get(key) if value_dict.get(key) else default
        except Exception as findTxtErr01:  # in case of any exception, returns default
            logging.error(findTxtErr01)
            value = default
        return str(value)

    def _str_to_dict(self, value):
        if value:
            return eval(value.replace("'", '"'))
        else:
            return ""

    def _str_to_list(self, value):
        if value:
            return list(eval(value.replace("'", '"')))
        else:
            return ""

    def get_arp_table(self, vrf=""):
        """
            Returns a list of dictionaries having the following set of keys:
                interface (string)
                mac (string)
                ip (string)
                age (float)
            ‘vrf’ of null-string will default to all VRFs.
            Specific ‘vrf’ will return the ARP table entries for that VRFs
             (including potentially ‘default’ or ‘global’).

            In all cases the same data structure is returned and no reference to the VRF that was
            used is included in the output.
        """
        try:
            arp_table = []
            subinterface_names = []

            def _find_neighbors(is_ipv4, ip_dict):
                ip_dict = eval(ip_dict.replace("'", '"'))
                neighbor_list = self._find_txt(ip_dict, "neighbor")
                if neighbor_list:
                    neighbor_list = list(eval(neighbor_list))
                    for neighbor in neighbor_list:
                        ipv4_address = ""
                        ipv6_address = ""
                        timeout = -1.0
                        reachable_time = -1.0
                        if is_ipv4:
                            ipv4_address = self._find_txt(neighbor, "ipv4-address")
                            timeout = convert(
                                float, self._find_txt(ip_dict, "timeout"), default=-1.0
                            )
                        else:
                            ipv6_address = self._find_txt(neighbor, "ipv6-address")
                            reachable_time = convert(
                                float,
                                self._find_txt(ip_dict, "reachable-time"),
                                default=-1.0,
                            )
                        arp_table.append(
                            {
                                "interface": sub_interface_name,
                                "mac": self._find_txt(neighbor, "link-layer-address"),
                                "ip": ipv4_address if is_ipv4 else ipv6_address,
                                "age": timeout if is_ipv4 else reachable_time,
                            }
                        )

            if vrf:
                vrf_path = {"network-instance[name={}]".format(vrf)}
            else:
                vrf_path = {"network-instance[name=*]"}
            pathType = "STATE"
            vrf_output = self.device._gnmiGet("", vrf_path, pathType)
            if not vrf_output:
                return []
            for vrf in vrf_output["srl_nokia-network-instance:network-instance"]:
                if "interface" in vrf.keys():
                    subinterface_list = self._find_txt(vrf, "interface")
                    subinterface_list = list(eval(subinterface_list))
                    for dictionary in subinterface_list:
                        if "name" in dictionary.keys():
                            subinterface_names.append(self._find_txt(dictionary, "name"))

            interface_path = {"interface[name=*]"}
            interface_output = self.device._gnmiGet("", interface_path, pathType)

            for interface in interface_output["srl_nokia-interfaces:interface"]:
                interface_name = self._find_txt(interface, "name")
                if interface_name:
                    sub_interface = self._find_txt(interface, "subinterface")
                    if sub_interface:
                        sub_interface = list(eval(sub_interface))
                        for dictionary in sub_interface:
                            sub_interface_name = self._find_txt(dictionary, "name")
                            if sub_interface_name in subinterface_names:
                                ipv4_data = self._find_txt(dictionary, "ipv4")
                                if ipv4_data:
                                    ipv4_data = eval(ipv4_data.replace("'", '"'))
                                    ipv4_arp_dict = self._find_txt(
                                        ipv4_data, "srl_nokia-interfaces-nbr:arp"
                                    )
                                    if ipv4_arp_dict:
                                        _find_neighbors(True, ipv4_arp_dict)

                                ipv6_data = self._find_txt(dictionary, "ipv6")
                                if ipv6_data:
                                    ipv6_data = eval(ipv6_data.replace("'", '"'))
                                    ipv6_neighbor_dict = self._find_txt(
                                        ipv6_data, "srl_nokia-if-ip-nbr:neighbor-discovery"
                                    )
                                    if ipv6_neighbor_dict:
                                        _find_neighbors(False, ipv6_neighbor_dict)
            return arp_table
        except Exception as e:
            logging.error("Error occurred : {}".format(e))

    def get_bgp_neighbors(self):
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
                    So far it can be ‘ipv4’ or ‘ipv6’
                        received_prefixes (int)
                        accepted_prefixes (int)
                        sent_prefixes (int)
                Note, if is_up is False and uptime has a positive value then this indicates the
                uptime of the last active BGP session.
        """
        try:
            bgp_neighbors = {
                "global": {
                    "router_id": "",
                    "peers": {}
                }
            }
            system_date_time = ""

            def _build_prefix_dict():
                prefix_limit = {}
                ipv4_unicast = self._find_txt(bgp_neighbor, "ipv4-unicast")
                if ipv4_unicast:
                    ipv4_unicast = eval(ipv4_unicast.replace("'", '"'))
                    prefix_limit.update(
                        {
                            "ipv4": {
                                "sent_prefixes": convert(
                                    int,
                                    self._find_txt(ipv4_unicast, "sent-routes"),
                                    default=-1,
                                ),
                                "received_prefixes": convert(
                                    int,
                                    self._find_txt(ipv4_unicast, "received-routes"),
                                    default=-1,
                                ),
                                "accepted_prefixes": convert(
                                    int,
                                    self._find_txt(ipv4_unicast, "active-routes"),
                                    default=-1,
                                ),
                            }
                        }
                    )
                ipv6_unicast = self._find_txt(bgp_neighbor, "ipv6-unicast")
                if ipv6_unicast:
                    ipv6_unicast = eval(ipv6_unicast.replace("'", '"'))
                    prefix_limit.update(
                        {
                            "ipv6": {
                                "sent_prefixes": convert(
                                    int,
                                    self._find_txt(ipv6_unicast, "sent-routes"),
                                    default=-1,
                                ),
                                "received_prefixes": convert(
                                    int,
                                    self._find_txt(ipv6_unicast, "received-routes"),
                                    default=-1,
                                ),
                                "accepted_prefixes": convert(
                                    int,
                                    self._find_txt(ipv6_unicast, "active-routes"),
                                    default=-1,
                                ),
                            }
                        }
                    )
                return prefix_limit

            path = {"/network-instance[name=*]"}
            system_path = {"system/information"}
            pathType = "STATE"
            output = self.device._gnmiGet("", path, pathType)
            system_output = self.device._gnmiGet("", system_path, pathType)

            for key, value in system_output["srl_nokia-system:system"].items():
                system_date_time = self._find_txt(value, "current-datetime")
                if system_date_time:
                    system_date_time = datetime.datetime.strptime(
                        system_date_time, "%Y-%m-%dT%H:%M:%S.%fZ"
                    ).timestamp()

            for network_instance in output["srl_nokia-network-instance:network-instance"]:
                instance_name = self._find_txt(network_instance, "name")
                router_id = self._find_txt(network_instance, "router-id")
                global_autonomous_system_number = self._find_txt(
                    network_instance, "autonomous-system",
                )
                bgp_neighbors.update({instance_name: {"router_id": router_id, "peers": {}}})
                protocols = self._find_txt(network_instance, "protocols")
                if protocols:
                    protocols = eval(protocols.replace("'", '"'))
                    bgp_dict = self._find_txt(protocols, "srl_nokia-bgp:bgp")
                    if bgp_dict:
                        bgp_dict = eval(bgp_dict.replace("'", '"'))
                        bgp_neighbors_list = self._find_txt(bgp_dict, "neighbor")
                        if bgp_neighbors_list:
                            bgp_neighbors_list = list(
                                eval(bgp_neighbors_list.replace("'", '"'))
                            )
                            for bgp_neighbor in bgp_neighbors_list:
                                peer_ip = self._find_txt(bgp_neighbor, "peer-address")
                                if peer_ip:
                                    local_as = self._find_txt(bgp_neighbor, "local-as")
                                    explicit_peer_as = self._find_txt(
                                        bgp_neighbor, "peer-as"
                                    )

                                    local_as_number = -1
                                    peer_as_number = (
                                        explicit_peer_as
                                        if explicit_peer_as
                                        else global_autonomous_system_number
                                    )
                                    if local_as:
                                        local_as = list(eval(local_as.replace("'", '"')))

                                        for dictionary in local_as:
                                            explicit_local_as_number = self._find_txt(
                                                dictionary, "as-number"
                                            )
                                            local_as_number = (
                                                explicit_local_as_number
                                                if explicit_local_as_number
                                                else global_autonomous_system_number
                                            )
                                    last_established = self._find_txt(
                                        bgp_neighbor, "last-established"
                                    )
                                    if last_established:
                                        last_established = datetime.datetime.strptime(
                                            last_established, "%Y-%m-%dT%H:%M:%S.%fZ"
                                        ).timestamp()
                                    bgp_neighbors[instance_name]["peers"].update(
                                        {
                                            peer_ip: {
                                                "local_as": as_number(local_as_number),
                                                "remote_as": as_number(peer_as_number),
                                                "remote_id": peer_ip,
                                                "is_up": True
                                                if self._find_txt(
                                                    bgp_neighbor, "session-state"
                                                )
                                                   == "established"
                                                else False,
                                                "is_enabled": True
                                                if self._find_txt(
                                                    bgp_neighbor, "admin-state"
                                                )
                                                   == "enable"
                                                else False,
                                                "description": self._find_txt(
                                                    bgp_neighbor, "description"
                                                ),
                                                "uptime": convert(
                                                    int,
                                                    (system_date_time - last_established) if isinstance(last_established,
                                                                                                        float) else -1,
                                                    default=-1,
                                                ),
                                                "address_family": _build_prefix_dict(),
                                            }
                                        }
                                    )

            return bgp_neighbors
        except Exception as e:
            logging.error("Error occurred : {}".format(e))

    def get_bgp_neighbors_detail(self, neighbor_address=""):
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
        try:
            bgp_neighbor_detail = {}

            path = {"/network-instance[name=*]"}
            pathType = "STATE"
            output = self.device._gnmiGet("", path, pathType)

            for network_instance in output["srl_nokia-network-instance:network-instance"]:
                instance_name = self._find_txt(network_instance, "name")
                router_id = self._find_txt(network_instance, "router-id")
                global_autonomous_system_number = self._find_txt(
                    network_instance, "autonomous-system",
                )
                protocols = self._find_txt(network_instance, "protocols")
                if protocols:
                    protocols = eval(protocols.replace("'", '"'))
                    bgp_dict = self._find_txt(protocols, "srl_nokia-bgp:bgp")
                    if bgp_dict:
                        bgp_dict = eval(bgp_dict.replace("'", '"'))
                        bgp_neighbors_list = self._find_txt(bgp_dict, "neighbor")
                        if bgp_neighbors_list:
                            bgp_neighbors_list = list(
                                eval(bgp_neighbors_list.replace("'", '"'))
                            )
                            bgp_neighbor_detail[instance_name] = {}
                            for bgp_neighbor in bgp_neighbors_list:
                                peer_ip = self._find_txt(bgp_neighbor, "peer-address")
                                if peer_ip:
                                    if neighbor_address and not neighbor_address == peer_ip:
                                        continue
                                    local_as = self._find_txt(bgp_neighbor, "local-as")
                                    explicit_peer_as = self._find_txt(
                                        bgp_neighbor, "peer-as"
                                    )
                                    local_as_number = -1
                                    peer_as_number = (
                                        explicit_peer_as
                                        if explicit_peer_as
                                        else global_autonomous_system_number
                                    )

                                    if local_as:
                                        local_as = list(
                                            eval(local_as.replace("'", '"'))
                                        )
                                        for dictionary in local_as:
                                            explicit_local_as_number = self._find_txt(
                                                dictionary, "as-number"
                                            )
                                            local_as_number = (
                                                explicit_local_as_number
                                                if explicit_local_as_number
                                                else global_autonomous_system_number
                                            )
                                    transport = self._str_to_dict(
                                        self._find_txt(bgp_neighbor, "transport")
                                    )
                                    local_address = ""
                                    if transport:
                                        local_address = self._find_txt(
                                            transport, "local-address"
                                        )
                                    timers = self._str_to_dict(
                                        self._find_txt(bgp_neighbor, "timers")
                                    )
                                    sent_messages = self._str_to_dict(
                                        self._find_txt(bgp_neighbor, "sent-messages")
                                    )
                                    received_messages = self._str_to_dict(
                                        self._find_txt(
                                            bgp_neighbor, "received-messages"
                                        )
                                    )
                                    ipv4_unicast = self._str_to_dict(
                                        self._find_txt(bgp_neighbor, "ipv4-unicast")
                                    )
                                    active_ipv4 = -1
                                    received_ipv4 = -1
                                    suppressed_ipv4 = -1
                                    advertised_ipv4 = -1
                                    if ipv4_unicast:
                                        active_ipv4 = convert(
                                            int,
                                            self._find_txt(
                                                ipv4_unicast, "active-routes"
                                            ),
                                            default=-1,
                                        )
                                        received_ipv4 = convert(
                                            int,
                                            self._find_txt(
                                                ipv4_unicast, "received-routes"
                                            ),
                                            default=-1,
                                        )
                                        suppressed_ipv4 = convert(
                                            int,
                                            self._find_txt(
                                                ipv4_unicast, "rejected-routes"
                                            ),
                                            default=-1,
                                        )
                                        advertised_ipv4 = convert(
                                            int,
                                            self._find_txt(ipv4_unicast, "sent-routes"),
                                            default=-1,
                                        )
                                    ipv6_unicast = self._str_to_dict(
                                        self._find_txt(bgp_neighbor, "ipv6-unicast")
                                    )
                                    # bgp_neighbor_detail[instance_name][
                                    #     as_number(peer_as_number)
                                    # ].append(
                                    peer_data = {
                                        "up": True
                                        if self._find_txt(
                                            bgp_neighbor, "session-state"
                                        )
                                           == "established"
                                        else False,
                                        "local_as": as_number(local_as_number),
                                        "remote_as": as_number(peer_as_number),
                                        "router_id": router_id,
                                        "local_address": local_address,
                                        "routing_table": self._find_txt(
                                            bgp_neighbor, "peer-group"
                                        ),
                                        "local_address_configured": False
                                        if local_address
                                        else True,
                                        "local_port": convert(
                                            int,
                                            self._find_txt(transport, "local-port"),
                                            default=-1,
                                        )
                                        if transport
                                        else -1,
                                        "remote_address": peer_ip,
                                        "remote_port": convert(
                                            int,
                                            self._find_txt(
                                                transport, "remote-port"
                                            ),
                                            default=-1,
                                        ),
                                        "multihop": False,  # Not yet supported in SRLinux
                                        "multipath": False,  # Not yet supported in SRLinux
                                        "remove_private_as": False,  # Not yet supported in SRLinux
                                        "import_policy": self._find_txt(
                                            bgp_neighbor, "import-policy"
                                        ),
                                        "export_policy": self._find_txt(
                                            bgp_neighbor, "export-policy"
                                        ),
                                        "input_messages": convert(
                                            int,
                                            self._find_txt(
                                                received_messages, "total-messages"
                                            ),
                                            default=-1,
                                        ),
                                        "output_messages": convert(
                                            int,
                                            self._find_txt(
                                                sent_messages, "total-messages"
                                            ),
                                            default=-1,
                                        ),
                                        "input_updates": convert(
                                            int,
                                            self._find_txt(
                                                received_messages, "total-updates"
                                            ),
                                            default=-1,
                                        ),
                                        "output_updates": convert(
                                            int,
                                            self._find_txt(
                                                sent_messages, "total-updates"
                                            ),
                                            default=-1,
                                        ),
                                        "messages_queued_out": convert(
                                            int,
                                            self._find_txt(
                                                sent_messages, "queue-depth"
                                            ),
                                            default=-1,
                                        ),
                                        "connection_state": self._find_txt(
                                            bgp_neighbor, "session-state"
                                        ),
                                        "previous_connection_state": self._find_txt(
                                            bgp_neighbor, "last-state"
                                        ),
                                        "last_event": self._find_txt(
                                            bgp_neighbor, "last-event"
                                        ),
                                        "suppress_4byte_as": False,  # Not yet supported in SRLinux
                                        "local_as_prepend": convert(
                                            bool,
                                            self._find_txt(
                                                local_as, "prepend-local-as"
                                            ),
                                            default=False,
                                        ),
                                        "holdtime": convert(
                                            int,
                                            self._find_txt(timers, "hold-time"),
                                            default=-1,
                                        ),
                                        "configured_holdtime": convert(
                                            int,
                                            self._find_txt(
                                                timers, "negotiated-hold-time"
                                            ),
                                            default=-1,
                                        ),
                                        "keepalive": convert(
                                            int,
                                            self._find_txt(
                                                timers, "keepalive-interval"
                                            ),
                                            default=-1,
                                        ),
                                        "configured_keepalive": convert(
                                            int,
                                            self._find_txt(
                                                timers,
                                                "negotiated-keepalive-interval",
                                            ),
                                            default=-1,
                                        ),
                                        "active_prefix_count": active_ipv4
                                        if active_ipv4 != -1
                                        else convert(
                                            int,
                                            self._find_txt(
                                                ipv6_unicast, "active-routes"
                                            ),
                                            default=-1,
                                        ),
                                        "received_prefix_count": received_ipv4
                                        if received_ipv4 != -1
                                        else convert(
                                            int,
                                            self._find_txt(
                                                ipv6_unicast, "received-routes"
                                            ),
                                            default=-1,
                                        ),
                                        "accepted_prefix_count": active_ipv4
                                        if active_ipv4 != -1
                                        else convert(
                                            int,
                                            self._find_txt(
                                                ipv6_unicast, "active-routes"
                                            ),
                                            default=-1,
                                        ),
                                        "suppressed_prefix_count": suppressed_ipv4
                                        if suppressed_ipv4 != -1
                                        else convert(
                                            int,
                                            self._find_txt(
                                                ipv6_unicast, "rejected-routes"
                                            ),
                                            default=-1,
                                        ),
                                        "advertised_prefix_count": advertised_ipv4
                                        if advertised_ipv4 != -1
                                        else convert(
                                            int,
                                            self._find_txt(
                                                ipv6_unicast, "sent-routes"
                                            ),
                                            default=-1,
                                        ),
                                        "flap_count": -1,  # Not yet supported in SRLinux
                                    }
                                    # )
                                    peer_as_number = as_number(peer_as_number)
                                    if peer_as_number in bgp_neighbor_detail[instance_name]:
                                        bgp_neighbor_detail[instance_name][peer_as_number].append(peer_data)
                                    else:
                                        bgp_neighbor_detail[instance_name][peer_as_number] = [peer_data]
            return bgp_neighbor_detail
        except Exception as e:
            logging.error("Error occurred : {}".format(e))

    def get_environment(self):
        """
            Returns a dictionary where:

                fans is a dictionary of dictionaries where the key is the location and the values:
                    status (True/False) - True if it’s ok, false if it’s broken
                temperature is a dict of dictionaries where the key is the location and the values:
                    temperature (float) - Temperature in celsius the sensor is reporting.
                is_alert (True/False) - True if the temperature is above the alert threshold
                is_critical (True/False) - True if the temp is above the critical threshold
                power is a dictionary of dictionaries where the key is the PSU id and the values:
                    status (True/False) - True if it’s ok, false if it’s broken
                    capacity (float) - Capacity in W that the power supply can support
                    output (float) - Watts drawn by the system
                cpu is a dictionary of dictionaries where the key is the ID and the values
                    %usage
                memory is a dictionary with:
                    available_ram (int) - Total amount of RAM installed in the device
                    used_ram (int) - RAM in use in the device
        """
        try:
            environment_data = {
                "fans": {},
                "power": {},
                "temperature": {},
                "memory": {},
                "cpu": {}
            }
            path = {"/platform"}
            pathType = "STATE"
            output = self.device._gnmiGet("", path, pathType)

            for component in output["srl_nokia-platform:platform"][
                "srl_nokia-platform-control:control"
            ]:
                slot = self._find_txt(component, "slot")
                if slot:
                    temperature = self._find_txt(component, "temperature")
                    if temperature:
                        temperature = eval(temperature.replace("'", '"'))
                        environment_data["temperature"].update(
                            {
                                slot: {
                                    "temperature": convert(
                                        float,
                                        self._find_txt(temperature, "instant"),
                                        default=-1.0,
                                    ),
                                    "is_alert": convert(
                                        bool,
                                        self._find_txt(temperature, "alarm-status"),  # Not able to detect alarm-status
                                        default=False),
                                    "is_critical": False,  # Not supported yet in SRLinux
                                }
                            }
                        )
                    memory = self._find_txt(component, "srl_nokia-platform-memory:memory")
                    environment_data["memory"] = {
                        "available_ram": -1,
                        "used_ram": -1

                    }
                    if memory:
                        memory = eval(memory.replace("'", '"'))
                        physical = convert(
                            int, self._find_txt(memory, "physical"), default=-1
                        )
                        free_memory = convert(
                            int, self._find_txt(memory, "free"), default=-1
                        )
                        environment_data["memory"].update(
                            {
                                "available_ram": physical,
                                "used_ram": physical - free_memory
                                if physical and free_memory > -1
                                else -1,
                            }
                        )
                    cpus = self._getObj(component, *["srl_nokia-platform-cpu:cpu"])
                    if cpus:
                        for cpu in cpus:
                            environment_data["cpu"].update(
                                {
                                    self._getObj(cpu, *["index"]): {
                                        "%usage": float(self._getObj(cpu, *["total", "instant"], default=-1.0))
                                    }
                                }
                            )

            for power_supply in output["srl_nokia-platform:platform"][
                "srl_nokia-platform-psu:power-supply"
            ]:
                environment_data["power"].update(
                    {
                        self._find_txt(power_supply, "id"): {
                            "status": True
                            if self._find_txt(power_supply, "oper-state") == "up"
                            else False,
                            "capacity": convert(
                                float, self._find_txt(power_supply, "capacity"), default=-1.0
                            ),
                            "output": -1.0,  # Not supported yet in SRLinx
                        }
                    }
                )

            # fan_ouput = self.device._gnmiGet("", fan_path, pathType)
            # print("OUTPUT FAN:", fan_ouput)

            for fans in output["srl_nokia-platform:platform"][
                "srl_nokia-platform-fan:fan-tray"
            ]:
                environment_data["fans"].update(
                    {
                        self._find_txt(fans, "id"): {
                            "status": True
                            if self._find_txt(fans, "oper-state") == "up"
                            else False
                        }
                    }
                )
                # for fan in output["srl-nokia-platform:platform"]:
            #     print("FAN:", fan)

            return environment_data
        except Exception as e:
            logging.error("Error occurred : {}".format(e))

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

        # Providing path for getting information from router
        try:
            path = {"/platform/chassis", "system/information", "system/name/host-name"}
            interface_path = {"interface[name=*]"}
            pathType = "STATE"

            output = self.device._gnmiGet("", path, pathType)
            interface_output = self.device._gnmiGet("", interface_path, pathType)

            # defining output variables
            interface_list = []
            uptime = -1.0
            version = ""
            hostname = ""
            serial_number = ""
            chassis_type = ""
            # getting interface names from the list
            for interface in interface_output["srl_nokia-interfaces:interface"]:
                interface_list.append(interface["name"])
            # getting system and platform information
            for key, value in output.items():
                if "system" in key and isinstance(value, dict):
                    for key_1, value_1 in value.items():
                        if "information" in key_1:
                            version = self._find_txt(value_1, "version")
                            uptime = self._find_txt(value_1, "uptime")
                            if uptime:
                                uptime = datetime.datetime.strptime(
                                    uptime, "%Y-%m-%dT%H:%M:%S.%fZ"
                                ).timestamp()
                        if "name" in key_1:
                            hostname = self._find_txt(value_1, "host-name")
                if "platform" in key and isinstance(value, dict):
                    for key_1, value_1 in value.items():
                        if "chassis" in key_1:
                            chassis_type = self._find_txt(value_1, "type")
                            serial_number = self._find_txt(value_1, "serial-number")
            return {
                "hostname": hostname,
                "fqdn": hostname,
                "vendor": u"Nokia",
                "model": chassis_type,
                "serial_number": serial_number,
                "os_version": version,
                "uptime": convert(float, uptime, default=-1.0),
                "interface_list": interface_list,
            }
        except Exception as e:
            logging.error("Error occurred : {}".format(e))

    def get_interfaces(self):
        """
           Returns a dictionary of dictionaries.
           The keys for the first dictionary will be the interfaces in the devices.
           The inner dictionary will containing the following data for each interface:
               is_up (True/False)
               is_enabled (True/False)
               description (string)
               last_flapped (float in seconds)
               speed (float in Mbit)
               MTU (in Bytes)
               mac_address (string)
        """
        try:
            interfaces = {}
            path = {"interface[name=*]"}
            pathType = "STATE"
            output = self.device._gnmiGet("", path, pathType)

            # looping over interfaces to get information
            for interface in output["srl_nokia-interfaces:interface"]:
                interface_name = self._find_txt(interface, "name")
                if interface_name:
                    last_flapped = self._find_txt(interface, "last-change")
                    if last_flapped:
                        last_flapped = datetime.datetime.strptime(
                            last_flapped, "%Y-%m-%dT%H:%M:%S.%fZ"
                        ).timestamp()
                    speed = -1.0
                    mac_address = ""
                    for key, value in interface.items():
                        if "ethernet" in key:
                            speed = self._find_txt(value, "port-speed")
                            if speed:
                                regex = re.compile(r"(\d+|\s+)")
                                speed = regex.split(speed)
                                speed = convert(float, speed[1], default=-1.0)
                            mac_address = self._find_txt(
                                value, "hw-mac-address", default=""
                            )
                    interfaces.update(
                        {
                            interface_name: {
                                "is_up": True
                                if self._find_txt(interface, "oper-state") == "up"
                                else False,
                                "is_enabled": True
                                if self._find_txt(interface, "admin-state") == "enable"
                                else False,
                                "description": self._find_txt(interface, "description"),
                                "last_flapped": last_flapped if last_flapped else -1.0,
                                "mtu": convert(
                                    int, self._find_txt(interface, "mtu"), default=-1
                                ),
                                "speed": convert(float, speed, default=-1.0),
                                "mac_address": mac(mac_address) if mac_address else "",
                            }
                        }
                    )

            return interfaces
        except Exception as e:
            logging.error("Error occurred : {}".format(e))

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
        try:
            interface_counters = {}

            path = {"interface[name=*]"}
            pathType = "STATE"
            output = self.device._gnmiGet("", path, pathType)

            for interface in output["srl_nokia-interfaces:interface"]:
                interface_name = self._find_txt(interface, "name")
                if interface_name:
                    statistics_interface = self._find_txt(interface, "statistics")
                    if statistics_interface:
                        statistics_interface = self._str_to_dict(statistics_interface)
                    sub_interface = self._find_txt(interface, "subinterface")
                    if sub_interface:
                        sub_interface = self._str_to_list(sub_interface)
                        for dictionary in sub_interface:
                            sub_interface_name = self._find_txt(dictionary, "name")
                            if sub_interface_name:
                                ifctrs = {
                                    "tx_errors": -1,
                                    "rx_errors": -1,
                                    "tx_discards": -1,
                                    "rx_discards": -1,
                                    "tx_octets": -1,
                                    "rx_octets": -1,
                                    "tx_unicast_packets": -1,
                                    "rx_unicast_packets": -1,
                                    "tx_multicast_packets": -1,
                                    "rx_multicast_packets": -1,
                                    "tx_broadcast_packets": -1,
                                    "rx_broadcast_packets": -1
                                }
                                interface_counters[sub_interface_name] = ifctrs
                                statistics = self._find_txt(dictionary, "statistics")
                                if statistics:
                                    statistics = self._str_to_dict(statistics)
                                    ifctrs = {
                                        "tx_errors": convert(
                                            int,
                                            self._find_txt(
                                                statistics, "out-error-packets"
                                            ),
                                            default=-1,
                                        ),
                                        "rx_errors": convert(
                                            int,
                                            self._find_txt(
                                                statistics, "in-error-packets"
                                            ),
                                            default=-1,
                                        ),
                                        "tx_discards": convert(
                                            int,
                                            self._find_txt(
                                                statistics, "out-discarded-packets"
                                            ),
                                            default=-1,
                                        ),
                                        "rx_discards": convert(
                                            int,
                                            self._find_txt(
                                                statistics, "in-discarded-packets"
                                            ),
                                            default=-1,
                                        ),
                                        "tx_octets": convert(
                                            int,
                                            self._find_txt(statistics, "out-octets"),
                                            default=-1,
                                        ),
                                        "rx_octets": convert(
                                            int,
                                            self._find_txt(statistics, "in-octets"),
                                            default=-1,
                                        ),
                                        # unicast, broadcast, multicast packet statistics
                                        # are taken at the interface level
                                        "tx_unicast_packets": convert(
                                            int,
                                            self._find_txt(
                                                statistics_interface,
                                                "out-unicast-packets",
                                            ),
                                            default=-1,
                                        ),
                                        "rx_unicast_packets": convert(
                                            int,
                                            self._find_txt(
                                                statistics_interface,
                                                "in-unicast-packets",
                                            ),
                                            default=-1,
                                        ),
                                        "tx_multicast_packets": convert(
                                            int,
                                            self._find_txt(
                                                statistics_interface,
                                                "out-multicast-packets",
                                            ),
                                            default=-1,
                                        ),
                                        "rx_multicast_packets": convert(
                                            int,
                                            self._find_txt(
                                                statistics_interface,
                                                "in-multicast-packets",
                                            ),
                                            default=-1,
                                        ),
                                        "tx_broadcast_packets": convert(
                                            int,
                                            self._find_txt(
                                                statistics_interface,
                                                "out-broadcast-packets",
                                            ),
                                            default=-1,
                                        ),
                                        "rx_broadcast_packets": convert(
                                            int,
                                            self._find_txt(
                                                statistics_interface,
                                                "in-broadcast-packets",
                                            ),
                                            default=-1,
                                        ),
                                    }
                                    interface_counters[sub_interface_name].update(ifctrs)

            return interface_counters
        except Exception as e:
            logging.error("Error occurred : {}".format(e))

    def get_interfaces_ip(self):
        """
            Returns all configured IP addresses on all interfaces as a dictionary of dictionaries.
            of the main dictionary represent the name of the interface.
            Values of the main dictionary represent are dictionaries that may consist of two keys
            ‘ipv4’ and ‘ipv6’ (one, both or none) which are themselves dictionaries with the IP addresses as keys.
            Each IP Address dictionary has the following keys:
                prefix_length (int)
        """
        try:
            interfaces_ip = {}

            path = {"interface[name=*]/subinterface"}
            pathType = "STATE"
            output = self.device._gnmiGet("", path, pathType)

            for interface in output["srl_nokia-interfaces:interface"]:
                for s in interface["subinterface"]:
                    ip_addr = {}
                    for v in ["ipv4","ipv6"]:
                      if v in s and 'address' in s[v]:
                          for addr in s[v]["address"]:
                            ip_l = addr['ip-prefix'].split('/')
                            e = { ip_l[0]: { "prefix_length": int(ip_l[1]) } }
                            if v not in ip_addr:
                              ip_addr[v] = e
                            else:
                              ip_addr[v].update( e )
                    interfaces_ip[ s['name'] ] = ip_addr

            return interfaces_ip
        except Exception as e:
            logging.exception(f"Error occurred : {e}")

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
        try:
            ipv6_neighbor_list = []

            path = {"interface[name=*]"}
            pathType = "STATE"
            output = self.device._gnmiGet("", path, pathType)

            for interface in output["srl_nokia-interfaces:interface"]:
                interface_name = self._find_txt(interface, "name")
                if interface_name:
                    sub_interface = self._str_to_list(
                        self._find_txt(interface, "subinterface")
                    )
                    if sub_interface:
                        for dictionary in sub_interface:
                            sub_interface_name = self._find_txt(dictionary, "name")
                            if sub_interface_name:
                                ipv6 = self._str_to_dict(self._find_txt(dictionary, "ipv6"))
                                if ipv6:
                                    neighbour_discovery = self._str_to_dict(
                                        self._find_txt(
                                            ipv6,
                                            "srl_nokia-interfaces-nbr:neighbor-discovery",
                                        )
                                    )

                                    if neighbour_discovery:
                                        neighbors = self._str_to_dict(
                                            self._find_txt(neighbour_discovery, "neighbor", )
                                        )
                                        if neighbors:
                                            for neighbor in neighbors:
                                                next_state_time = self._find_txt(
                                                    neighbor, "next-state-time"
                                                )
                                                if next_state_time:
                                                    next_state_time = datetime.datetime.strptime(
                                                        next_state_time,
                                                        "%Y-%m-%dT%H:%M:%S.%fZ",
                                                    ).timestamp()
                                                ipv6_neighbor_list.append(
                                                    {
                                                        "interface": sub_interface_name,
                                                        "mac": self._find_txt(
                                                            neighbor, "link-layer-address",
                                                        ),
                                                        "ip": self._find_txt(
                                                            neighbor, "ipv6-address"
                                                        ),
                                                        "age": convert(
                                                            float,
                                                            next_state_time,
                                                            default=-1.0,
                                                        ),
                                                        "state": self._find_txt(
                                                            neighbor, "current-state"
                                                        ),
                                                    }
                                                )
            return ipv6_neighbor_list
        except Exception as e:
            logging.error("Error occurred : {}".format(e))

    def get_lldp_neighbors(self):
        """
            Returns a dictionary where the keys are local ports and the value is a list of dictionaries
            with the following information:
                    hostname
                    port
        """
        try:
            lldp_neighbors = {}

            path = {"/system/lldp"}
            pathType = "STATE"
            output = self.device._gnmiGet("", path, pathType)

            for key, value in output["srl_nokia-system:system"].items():
                chassis_id = self._find_txt(value, "chassis-id")
                if chassis_id == "":
                    continue
                interfaces = self._str_to_list(self._find_txt(value, "interface"))
                if interfaces:
                    for dictionary in interfaces:
                        interface_name = self._find_txt(dictionary, "name")
                        neighbors = self._str_to_list(
                            self._find_txt(dictionary, "neighbor")
                        )
                        neighbor_data = []
                        for neighbor in neighbors:
                            neighbor_data.append({
                                "hostname": self._find_txt(neighbor, "system-name"),
                                "port": self._find_txt(neighbor, "port-id"),
                            })
                        lldp_neighbors.update({interface_name: neighbor_data})

            return lldp_neighbors
        except Exception as e:
            logging.error("Error occurred : {}".format(e))

    def get_lldp_neighbors_detail(self, interface=""):
        """
            Returns a detailed view of the LLDP neighbors as a dictionary containing lists
            of dictionaries for each interface.

            Empty entries are returned as an empty string (e.g. ‘’) or list where applicable.

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
        try:
            lldp_neighbors_detail = {}

            path = {"/system/lldp"}
            pathType = "STATE"
            output = self.device._gnmiGet("", path, pathType)

            interface_name_list = []
            if not output:
                return {}
            for key, value in output["srl_nokia-system:system"].items():
                chassis_id = self._find_txt(value, "chassis-id")
                if chassis_id == "":
                    continue
                interfaces = self._str_to_list(self._find_txt(value, "interface"))
                if interfaces:
                    for dictionary in interfaces:
                        interface_name = self._find_txt(dictionary, "name")
                        if interface:
                            if interface_name == interface:
                                interface_name_list.append(interface_name)
                            else:
                                continue
                        else:
                            interface_name_list.append(interface_name)
                        neighbors = self._str_to_list(
                            self._find_txt(dictionary, "neighbor")
                        )
                        neighbor_data = []
                        for neighbor in neighbors:
                            capability_list = self._str_to_list(
                                self._find_txt(neighbor, "capability")
                            )
                            capabilities = []
                            capabilities_enabled = []
                            for capability in capability_list:
                                capabilities.append(capability["name"])
                                if capability["enabled"] is True:
                                    capabilities_enabled.append(capability["name"])
                            neighbor_data.append({
                                "parent_interface": interface_name,
                                "remote_port": self._find_txt(neighbor, "port-id"),
                                "remote_port_description": self._find_txt(
                                    neighbor, "port-description"
                                ),
                                "remote_chassis_id": self._find_txt(
                                    neighbor, "chassis-id"
                                ),
                                "remote_system_name": self._find_txt(
                                    neighbor, "system-name"
                                ),
                                "remote_system_description": self._find_txt(
                                    neighbor, "system-description"
                                ),
                                "remote_system_capab": capabilities,
                                "remote_system_enable_capab": capabilities_enabled,
                            })
                            lldp_neighbors_detail.update({interface_name: neighbor_data})

            return lldp_neighbors_detail
        except Exception as e:
            logging.error("Error occurred : {}".format(e))

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
        try:
            network_instances = {}

            if name:
                vrf_path = {"network-instance[name={}]".format(name)}
            else:
                vrf_path = {"network-instance[name=*]"}
            pathType = "STATE"
            vrf_output = self.device._gnmiGet("", vrf_path, pathType)
            if not vrf_output:
                return {}
            for vrf in vrf_output["srl_nokia-network-instance:network-instance"]:
                # vrf_name = self._find_txt(vrf, "name")
                vrf_name = name if name else self._find_txt(vrf, "name")
                vrf_type = self._find_txt(vrf, "type")
                network_instances.update(
                    {
                        vrf_name: {
                            "name": vrf_name,
                            "type": vrf_type,
                            "state": {
                                "route_distinguisher": ""  # Not supported yet in SRLinux
                            },
                            "interfaces": {"interface": {}},
                        }
                    }
                )
                interface_list = self._str_to_list(self._find_txt(vrf, "interface"))
                if interface_list:
                    for interface in interface_list:
                        interface_name = self._find_txt(interface, "name")
                        network_instances[vrf_name]["interfaces"]["interface"].update(
                            {interface_name: {}}
                        )

            return network_instances
        except Exception as e:
            logging.error("Error occurred : {}".format(e))

    def get_users(self):
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
        try:
            users_dict = {}

            path = {"system/aaa/authentication/admin-user"}
            path_type = "STATE"
            output = self.device._gnmiGet("", path, path_type)

            for key, value in output["srl_nokia-system:system"]["srl_nokia-aaa:aaa"]["authentication"].items():
                username = self._find_txt(value, "username")
                users_dict.update({
                    username: {
                        "level": 0,  # Not supported yet in SRLinux
                        "password": self._find_txt(value, "password"),
                        "sshkeys": []  # Not supported yet in SRLinux
                    }
                })
            return users_dict
        except Exception as e:
            logging.error("Error occurred : {}".format(e))

    def get_bgp_config(self, group="", neighbor=""):
        """
        Returns a dictionary containing the BGP configuration. Can return either the whole config, either the config only for a group or neighbor.

        :param neighbor: specific BGP neighbor.
        :param group: specific BGP group.
        :return: Returns the configuration of a specific BGP neighbor /BGP group
        """
        try:
            path = {"/network-instance/protocols/bgp"}
            path_type = "STATE"
            output = self.device._gnmiGet("", path, path_type)
            groups_keys_path = ["srl_nokia-network-instance:network-instance", 0, "protocols", "srl_nokia-bgp:bgp", "group"]
            neighbors_keys_path = ["srl_nokia-network-instance:network-instance", 0, "protocols", "srl_nokia-bgp:bgp",
                                   "neighbor"]
            multipath_keys_path = ["srl_nokia-network-instance:network-instance", 0, "protocols", "srl_nokia-bgp:bgp",
                                   "ipv4-unicast", "multipath", "allow-multiple-as"]
            groups = self._getObj(output, *groups_keys_path, default=[])
            neighbors = self._getObj(output, *neighbors_keys_path, default=[])
            multipath = self._getObj(output, *multipath_keys_path, default=False)
            groups_data = {}
            for g in groups:
                group_name = self._getObj(g, *["group-name"])
                g_description = self._getObj(g, *["description"])
                local_address = self._getObj(g, *["transport", "local-address"])
                g_local_as = self._getObj(g, *["local-as", 0, "as-number"])
                g_remote_as = self._getObj(g, *["peer-as"])
                g_export_policy = self._getObj(g, *["export-policy"])
                g_import_policy = self._getObj(g, *["import-policy"])
                g_ipv4_unicast = self._getObj(g, *["ipv4-unicast"])
                g_ipv6_unicast = self._getObj(g, *["ipv6-unicast"])
                ct_neighbors = [n for n in neighbors if self._getObj(n, *["peer-group"]) == group_name]
                neighbors_data = {}
                for n in ct_neighbors:
                    n_ip_address = self._getObj(n, *["peer-address"])
                    n_description = self._getObj(n, *["description"])
                    n_import_policy = self._getObj(n, *["import-policy"])
                    n_export_policy = self._getObj(n, *["export-policy"])
                    n_local_address = self._getObj(n, *["transport", "local-address"])
                    n_local_as = self._getObj(n, *["local-as", 0, "as-number"], default=-1)
                    n_remote_as = self._getObj(n, *["peer-as"], default=-1)
                    n_ipv4_unicast = self._getObj(n, *["ipv4-unicast"])
                    n_ipv6_unicast = self._getObj(n, *["ipv6-unicast"])
                    n_route_reflector_client = self._getObj(n, *["route-reflector", "client"], default=False)
                    n_nhs = self._getObj(n, *["next-hop-self"], default=False)
                    neighbors_data.update({
                        n_ip_address: {
                            "description": n_description,
                            "import_policy": n_import_policy,
                            "export_policy": n_export_policy,
                            "local_address": n_local_address,
                            "local_as": n_local_as,
                            "remote_as": n_remote_as,
                            "authentication_key": "",
                            "prefix_limit": {
                                "inet": {
                                    "unicast": {
                                        'limit': self._getObj(n_ipv4_unicast, *["prefix-limit", "max-received-routes"],
                                                              default=-1),
                                        'teardown': {
                                            'threshold': self._getObj(n_ipv4_unicast,
                                                                      *["prefix-limit", "warning-threshold-pct"],
                                                                      default=-1),
                                            "timeout": -1,
                                        }
                                    }
                                },
                                "inet6": {
                                    "unicast": {
                                        'limit': self._getObj(n_ipv6_unicast, *["prefix-limit", "max-received-routes"],
                                                              default=-1),
                                        'teardown': {
                                            'threshold': self._getObj(n_ipv6_unicast,
                                                                      *["prefix-limit", "warning-threshold-pct"],
                                                                      default=-1),
                                            "timeout": -1,
                                        }
                                    }
                                }
                            },
                            "route_reflector_client": n_route_reflector_client,
                            "nhs": n_nhs
                        }
                    })
                ct_grp_data = {
                    group_name: {
                        "type": "internal" if g_local_as == g_remote_as else "external",
                        "description": g_description,
                        "apply_groups": [],  # Not Supported
                        "multihop_ttl": -1,  # Not Supported
                        "multipath": multipath,
                        "local_address": local_address,
                        "local_as": g_local_as,
                        "remote_as": g_remote_as,
                        "import_policy": g_import_policy,
                        "export_policy": g_export_policy,
                        "remove_private_as": False,  # Not Supported
                        "prefix_limit": {
                            "inet": {
                                "unicast": {
                                    'limit': self._getObj(g_ipv4_unicast, *["prefix-limit", "max-received-routes"],
                                                          default=-1),
                                    'teardown': {
                                        'threshold': self._getObj(g_ipv4_unicast,
                                                                  *["prefix-limit", "warning-threshold-pct"], default=-1),
                                        "timeout": -1,
                                    }
                                }
                            },
                            "inet6": {
                                "unicast": {
                                    'limit': self._getObj(g_ipv6_unicast, *["prefix-limit", "max-received-routes"],
                                                          default=-1),
                                    'teardown': {
                                        'threshold': self._getObj(g_ipv6_unicast,
                                                                  *["prefix-limit", "warning-threshold-pct"], default=-1),
                                        "timeout": -1,
                                    }
                                }
                            }
                        },
                        "neighbors": neighbors_data
                    }
                }
                if group and group == group_name:
                    return ct_grp_data
                    # return self._removeNotFound(ct_grp_data)
                if neighbor and neighbor in neighbors_data.keys():
                    ct_grp_data[group_name]["neighbors"] = {}
                    ct_grp_data[group_name]["neighbors"][neighbor] = neighbors_data[neighbor]
                    return ct_grp_data
                    # return self._removeNotFound(ct_grp_data)
                groups_data.update(ct_grp_data)
            # return groups_data if not group or not neighbor else {}
            # if group or neighbor is true and is present , then return shd have happened in for loop
            return {} if group or neighbor else groups_data
            # return {} if group or neighbor else self._removeNotFound(groups_data)
        except Exception as e:
            logging.error("Error occurred : {}".format(e))

    def get_snmp_information(self):
        """
        :return:
        Returns a dict of dicts containing SNMP configuration. Each inner dictionary contains these fields

        chassis_id (string)
        community (dictionary)
        contact (string)
        location (string)
        """
        try:
            contact_path = {"/system/information/contact"}
            location_path = {"/system/information/location"}
            path_type = "STATE"
            contact_output = self.device._gnmiGet("", contact_path, path_type)
            location_output = self.device._gnmiGet("", location_path, path_type)
            contact = self._getObj(contact_output,
                                   *['srl_nokia-system:system', 'srl_nokia-system-info:information', 'contact'])
            location = self._getObj(location_output,
                                    *['srl_nokia-system:system', 'srl_nokia-system-info:information', 'location'])
            output = {
                "chassis_id": "",
                "community": {},
                "contact": contact,
                "location": location
            }
            return output
        except Exception as e:
            logging.error("Error occurred : {}".format(e))
    # def get_config_jsonrpc(self, retrieve='all', full=False, sanitized=False):
    #     """
    #     :param retrieve: Which configuration type you want to populate, default is all of them. The rest will be set to “”.
    #     :param full:Retrieve all the configuration. For instance, on ios, “sh run all”.
    #     :param sanitized:Remove secret data. Default: False.
    #     :return:Return the configuration of a device.
    #     """
    #     cmds = [
    #         {
    #             "datastore": "running",
    #             "path": "/"
    #         }
    #     ]
    #     running = self.device._jsonrpcGet(cmds)
    #     if retrieve == 'all':
    #         return {
    #             "running": str(running),
    #             "candidate": "",
    #             "startup": ""
    #         }
    #     if retrieve == 'running':
    #         return {
    #             "running": str(running),
    #             "candidate": "",
    #             "startup": ""
    #         }
    #
    #     if retrieve == 'candidate':
    #         return {
    #             "running": "",
    #             "candidate": "",
    #             "startup": ""
    #         }
    #     if retrieve == 'startup':
    #         return {
    #             "running": "",
    #             "candidate": "",
    #             "startup": ""
    #         }


    def get_config(self, retrieve='all', full=False, sanitized=False):
        """
        :param retrieve: Which configuration type you want to populate, default is all of them. The rest will be set to “”.
        :param full:Retrieve all the configuration. For instance, on ios, “sh run all”.
        :param sanitized:Remove secret data. Default: False.
        :return:Return the configuration of a device.
        """
        try:
            if retrieve not in ['all','running']:
                # Only 'running' or 'all' is supported for get_config
                return {
                    "running": "",
                    "candidate": "",
                    "startup": ""
                }

            if self.running_format == 'cli':
                if sanitized:
                    raise NotImplementedError(
                        "sanitized=True is not implemented with CLI format")
                output = self.device._jsonrpcRunCli(["info flat"])
                running_config = self._return_result(output)
            else:
                running = self.device._gnmiGet("", {"/"}, "CONFIG")
                if sanitized:
                    if "srl_nokia-system:system" in running:
                        _system = running["srl_nokia-system:system"]
                        if "srl_nokia-aaa:aaa" in _system:
                            del _system["srl_nokia-aaa:aaa"]
                        if "srl_nokia-tls:tls" in _system:
                            del _system["srl_nokia-tls:tls"]
                running_config = json.dumps(running) # don't use sort_keys=True

            return {
                "running": running_config,
                "candidate": "",
                "startup": ""
            }
        except NotImplementedError as e:
            raise e
        except Exception as e:
            logging.error(f"Error occurred in get_config: {e}")
            return {
                "running": "",
                "candidate": "",
                "startup": ""
            }

    def get_ntp_servers(self):
        """
        :return:Returns the NTP servers configuration as dictionary. The keys of the dictionary represent the IP Addresses of the servers. Inner dictionaries do not have yet any available keys.
        """
        try:
            path = {"/system/ntp"}
            path_type = "STATE"
            output = self.device._gnmiGet("", path, path_type)
            ntp_servers = self._getObj(output, *['srl_nokia-system:system','srl_nokia-ntp:ntp', "server"], default=[])
            server_data = {}
            for s in ntp_servers:
                if "address" in s:
                    server_data.update({
                        s["address"]:{}
                    })
            return server_data
        except Exception as e:
            logging.error("Error occurred : {}".format(e))

            # # def get_ntp_peers(self):
    # #     """
    # #     :return:Returns the NTP peers configuration as dictionary. The keys of the dictionary represent the IP Addresses of the peers. Inner dictionaries do not have yet any available keys.
    # #     """
    # #     path = {"/system/ntp/server"}
    # #     path_type = "STATE"
    # #     output = self.device._gnmiGet("", path, path_type)
    # #     ntp_servers = self._getObj(output, *['srl_nokia-system:system/srl_nokia-ntp:ntp', "server"])
    # #     peers_data = {}
    # #     for s in ntp_servers:
    # #         if "address" in s:
    # #             peers_data.update({
    # #                 s["address"]:{}
    # #             })
    # #     return peers_data
    #     pass

    def get_ntp_stats(self):
        """
        :return:Returns a list of NTP synchronization statistics.
        """
        try:
            path = {"/system/ntp"}
            path_type = "STATE"
            output = self.device._gnmiGet("", path, path_type)
            ntp_servers = self._getObj(output, *['srl_nokia-system:system', 'srl_nokia-ntp:ntp', "server"], default=[])
            synchronized = self._getObj(output, *['srl_nokia-system:system', 'srl_nokia-ntp:ntp', 'synchronized'])
            stats_data = []
            for s in ntp_servers:
                prefer = s["prefer"] if "prefer" in s else None
                if synchronized.lower() == "synchronized" or synchronized.lower() == "synchronised":
                    synced = True
                else:
                    synced = False
                if prefer:
                    offset = self._getObj(s, *["offset"], default=-1.0)
                    jitter = self._getObj(s, *["jitter"], default=-1.0)
                    stats_data.append({
                        'remote': self._getObj(s, *["address"]),
                        "referenceid": "",
                        'synchronized': synced,
                        'stratum': self._getObj(s, *["stratum"], default=-1),
                        "type": "",
                        "when": "",
                        'hostpoll': self._getObj(s, *["poll-interval"], default=-1),
                        "reachability": -1,
                        "delay": -1.0,
                        'offset': float(offset),
                        'jitter': float(jitter)
                    })
            return stats_data
        except Exception as e:
            logging.error("Error occurred : {}".format(e))

    def get_optics(self):
        """
        :return:Fetches the power usage on the various transceivers installed on the switch (in dbm), and returns a view that conforms with the openconfig model openconfig-platform-transceiver.yang
        """
        try:
            path = {"/interface"}
            path_type = "STATE"
            output = self.device._gnmiGet("", path, path_type)
            interfaces = self._getObj(output, *['srl_nokia-interfaces:interface'], default=[])
            channel_data = {}
            for i in interfaces:
                name = self._getObj(i, *["name"])
                channel = self._getObj(i, *["transceiver", "channel"], default={})
                channel_data.update({
                    name: {
                        'physical_channels': {
                            'channel': [
                                {
                                    'index': self._getObj(channel, *["index"], default=-1),
                                    'state': {
                                        'input_power': {
                                            'instant': self._getObj(channel, *["input-power", "latest_value"],
                                                                    default=-1.0),
                                            "avg": -1.0,
                                            "min": -1.0,
                                            "max": -1.0
                                        },
                                        'output_power': {
                                            'instant': self._getObj(channel, *["output-power", "latest_value"],
                                                                    default=-1.0),
                                            "avg": -1.0,
                                            "min": -1.0,
                                            "max": -1.0
                                        },
                                        'laser_bias_current': {
                                            'instant': self._getObj(channel, *["laser-bias-current", "latest_value"],
                                                                    default=-1.0),
                                            "avg": -1.0,
                                            "min": -1.0,
                                            "max": -1.0
                                        },
                                    }
                                }
                            ]
                        }
                    }
                })
            return channel_data
        except Exception as e:
            logging.error("Error occurred : {}".format(e))

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
        try:
            path = {"/network-instance/bridge-table/mac-table/mac"}
            path_type = "STATE"
            output = self.device._gnmiGet("", path, path_type)
            mac_data = []
            instances = self._getObj(output, *['srl_nokia-network-instance:network-instance'], default=[])
            for i in instances:
                mac_output = self._getObj(i, *['bridge-table', 'srl_nokia-bridge-table-mac-table:mac-table', 'mac'],
                                          default=[])
                for m in mac_output:
                    dest_splits = str(m['destination']).split(".")
                    int = dest_splits[0]
                    subint = dest_splits[1] if len(dest_splits) >= 2 else "*"
                    vlan_path = {
                    "/interface[name={}]/subinterface[index={}]/vlan/encap/single-tagged/vlan-id".format(int, subint)}
                    vlan_output = self.device._gnmiGet("", vlan_path, "STATE")
                    vlanid = self._getObj(vlan_output, *['srl_nokia-interfaces:interface', 0, 'subinterface', 0,
                                                         'srl_nokia-interfaces-vlans:vlan', 'encap', 'single-tagged',
                                                         'vlan-id'], default=-1)
                    type = self._getObj(m, *["type"])
                    static = False if not type else type != "learnt"
                    m_data = {
                        'mac': self._getObj(m, *['address']),
                        'interface': self._getObj(m, *['destination']),
                        'vlan': vlanid,
                        "active": False,
                        'static': static,
                        "moves": -1,
                        "last_move": -1.0
                    }
                    mac_data.append(m_data)
            return mac_data
        except Exception as e:
            logging.error("Error occurred : {}".format(e))

    def get_route_to(self, destination='', protocol='', longer=False):
        """
        :return:Returns a dictionary of dictionaries containing details of all available routes to a destination.
        """
        try:
            path = {"/network-instance"}
            path_type = "STATE"
            output = self.device._gnmiGet("", path, path_type)
            dpath = {"/system/information/current-datetime"}
            doutput = self.device._gnmiGet("", dpath, "STATE")
            ctdatetime = self._getObj(doutput,
                                      *['srl_nokia-system:system', 'srl_nokia-system-info:information', 'current-datetime'],
                                      default=None)
            interfaces = self._getObj(output, *['srl_nokia-network-instance:network-instance'], default=[])
            route_data = {}
            for i in interfaces:
                routes = self._getObj(i, *["route-table", "srl_nokia-ip-route-tables:ipv4-unicast", "route"], default=[])
                next_hop_groups = self._getObj(i, *["route-table", "srl_nokia-ip-route-tables:next-hop-group"], default=[])
                next_hops = self._getObj(i, *["route-table", "srl_nokia-ip-route-tables:next-hop"], default=[])
                name = self._getObj(i, *["name"])
                for r in routes:
                    if "next-hop-group" not in r:
                        continue
                    next_hop_group_id = r["next-hop-group"]
                    next_hop_group = [n for n in next_hop_groups if n["index"] == next_hop_group_id]
                    next_hop_group = next_hop_group[0]  # definitely this will be present . list cannot be empty
                    next_hop_ids = [n["next-hop"] for n in next_hop_group["next-hop"]]

                    ct_next_hops = [n for n in next_hops if n["index"] in next_hop_ids]
                    ct_next_hops_data = []
                    for next_hop in ct_next_hops:
                        ip_address = self._getObj(next_hop, *["ip-address"])
                        subinterface = self._getObj(next_hop, *["subinterface"])
                        if ctdatetime and self._getObj(r, *["last-app-update"], default=None):
                            ctdatetime_obj = datetime.datetime.strptime(ctdatetime, "%Y-%m-%dT%H:%M:%S.%fZ")
                            last_app_date = datetime.datetime.strptime(r["last-app-update"], "%Y-%m-%dT%H:%M:%S.%fZ")
                            age = int((ctdatetime_obj - last_app_date).total_seconds())
                        else:
                            age = -1
                        ct_protocol = str(r["owner"]).split(":")[-1]
                        data = {
                            "protocol": ct_protocol,
                            "current_active": self._getObj(r, *["active"], default=False),
                            "last_active": False,
                            "age": age,
                            "next_hop": ip_address,
                            "outgoing_interface": subinterface,
                            "selected_next_hop": True if ip_address else False,
                            "preference": self._getObj(r, *["preference"], default=-1),
                            "inactive_reason": "",
                            "routing_table": name,
                        }
                        if "bgp" in r["owner"]:
                            bgp_protocol = self._getObj(i, *["protocols", "srl_nokia-bgp:bgp"], default={})
                            bgp_rib_routes = self._getObj(i, *["srl_nokia-rib-bgp:bgp-rib", "ipv4-unicast", "local-rib",
                                                               "routes"], default=[])
                            bgp_rib_attrsets = self._getObj(i, *["srl_nokia-rib-bgp:bgp-rib", "attr-sets", "attr-set"],
                                                            default=[])
                            neighbor = [b for b in bgp_protocol["neighbor"] if b["peer-address"] == ip_address]
                            neighbor = neighbor[0]  # exactly one neighbor will be present if it is bgp
                            rib_route = [rr for rr in bgp_rib_routes if
                                         rr["prefix"] == r["ipv4-prefix"] and rr["neighbor"] == ip_address and rr[
                                             "origin-protocol"] == "bgp"]
                            rib_route = rib_route[0]
                            attr_id = rib_route["attr-id"]
                            att_set = [a for a in bgp_rib_attrsets if a["index"] == attr_id][0]
                            data.update({
                                "protocol_attributes": {
                                    "local_as": self._getObj(bgp_protocol, *["autonomous-system"], default=-1),
                                    "remote_as": self._getObj(neighbor, *["peer-as"], default=-1),
                                    "peer_id": self._getObj(neighbor, *["peer-address"]),
                                    "as_path": str(self._getObj(att_set, *["as-path", "segment", 0, "member", 0])),
                                    "communities": self._getObj(att_set, *["communities", "community"], default=[]),
                                    "local_preference": self._getObj(att_set, *["local-pref"], default=-1),
                                    "preference2": -1,
                                    "metric": self._getObj(r, *["metric"], default=-1),
                                    "metric2": -1
                                }
                            })
                        if "isis" in r["owner"]:
                            isis_protocol = self._getObj(i, *["protocols", "srl_nokia-isis:isis", "instance"])[0]
                            level = self._getObj(isis_protocol, *["level", 0, "level-number"], default=-1)
                            data.update({
                                "protocol_attributes": {
                                    "level": level
                                }
                            })
                        ct_next_hops_data.append(data)
                    if destination and (
                            destination == r["ipv4-prefix"] or destination == str(r["ipv4-prefix"]).split("/")[0]):
                        return {
                            r["ipv4-prefix"]: ct_next_hops_data
                        }
                    route_data.update({
                        r["ipv4-prefix"]: ct_next_hops_data
                    })
            if protocol:
                route_data_filtered = {}
                for ipv4_prefix, nhs in route_data.items():
                    next_hop_filtered = [n for n in nhs if n["protocol"] == protocol]
                    if next_hop_filtered:
                        route_data_filtered.update({
                            ipv4_prefix: next_hop_filtered
                        })
                return route_data_filtered
            if destination:  # if destination was present , it should not reach here, rather returned earlier.
                return {}
            return route_data
        except Exception as e:
            logging.error("Error occurred : {}".format(e))

    def is_alive(self):
        alive = False
        if self._channel:
            try:
                output = self.device._jsonrpcRunCli(["date"])
                if "result" in output:
                    alive = True
            except Exception as e:
                logging.error( f"Exception in is_alive: {e} -> returning False" )
        return { "is_alive": alive }

    def traceroute(self, destination, source="", ttl=255, timeout=2, vrf=""):
        try:
            if not vrf:
                vrf = "default"
            command = "traceroute {} {} {}".format(
                destination,
                "-m {}".format(ttl) if ttl else "",
                "network-instance {}".format(vrf) if vrf else "",
            )
            output = self.device._jsonrpcRunCli([command])
            if "error" in output:
                return {
                    "error": output["error"]
                }
            if "result" not in output:
                return {
                    "error": "No result in output: {}".format(output)
                }
            result = output["result"][0]['text']
            if "* * *" in result:
                return {
                    'error': 'unknown host {}'.format(destination)
                }
            hops = result.split("byte packets")[1]
            hop_list = hops.split("\n")
            probes = {}
            for h in hop_list:
                if h.strip():
                    h_splits = re.split(r" |\(|\)", h.strip())
                    splts = [s.strip() for s in h_splits if s.strip()]
                    ct_probe = {
                        1: {
                            'rtt': float(splts[3]),
                            'ip_address': splts[2],
                            'host_name': splts[1]
                        },
                        2: {
                            'rtt': float(splts[5]),
                            'ip_address': splts[2],
                            'host_name': splts[1]
                        },
                        3: {
                            'rtt': float(splts[7]),
                            'ip_address': splts[2],
                            'host_name': splts[1]
                        }
                    }
                    probes[int(splts[0])] = ct_probe
            return {"success": probes}
        except Exception as e:
            logging.error("Error occurred : {}".format(e))

    def _ping(self, destination, source="", ttl=255, timeout=2, size=100, count=5, vrf=""):
        try:
            if not vrf:
                vrf = "default"
            output = self.device._jsonrpcRunCli(["ping {} {} {} {} {} {} {}".format(
                destination,
                "-I {}".format(source) if source else "",
                "-t {}".format(ttl) if ttl else "",
                "-W {}".format(timeout) if timeout else "",
                "-s {}".format(size) if size else "",
                "-c {}".format(count) if count else "",
                "network-instance {}".format(vrf) if vrf else "",
            )])
            if "error" in output:
                value = output["error"]["message"]
                return {"error": value.strip()}
            result = output["result"][0]['text']
            if "Destination Host Unreachable" in result:
                return {"error": "unknown host {}".format(destination)}
            pings = result.split("bytes of data.")[1]
            ping_list = [p for p in pings.split("\n") if p.strip()]
            rtt_line = ping_list[-1]
            success_data = {}
            r_splits = [r for r in re.split(" |/|=", rtt_line.strip()) if r.strip()]
            stats_line = ping_list[-2]
            s_splits = [s for s in stats_line.split(" ")]
            loss = s_splits[5].strip("%")
            sent = int(s_splits[0])
            lost_packets = int(sent * int(loss) / 100)
            success_data.update({
                'probes_sent': sent,
                'packet_loss': lost_packets,
                'rtt_min': float(r_splits[5]),
                'rtt_max': float(r_splits[7]),
                'rtt_avg': float(r_splits[6]),
                'rtt_stddev': float(r_splits[8]),
            })
            ping_lines = []
            for line in ping_list:
                if "ping statistics" in line:
                    break
                if line.strip():
                    ping_lines.append(line)
            results = []
            for p in ping_lines:
                p_splits = [s for s in re.split(" |:|=", p.strip()) if s.strip()]
                results.append({
                    'ip_address': p_splits[3],
                    'rtt': float(p_splits[9])
                })
            success_data.update({
                "results": results
            })
            return {"success": success_data}
        except Exception as e:
            logging.error("Error occurred : {}".format(e))

    def cli(self, commands, encoding="text"):
        """
        Will execute a list of commands and return the output in a dictionary format.
        """
        if encoding not in ("text",):
            raise NotImplementedError("%s is not a supported encoding" % encoding)

        try:
            output = {}
            jsonrpc_output = self.device._jsonrpcRunCli(commands)
            if "error" in jsonrpc_output:
                return jsonrpc_output
            result = jsonrpc_output["result"]
            for (c, r) in zip(commands, result):
                output[c] = r
            return output
        except Exception as e:
            logging.error("Error occurred : {}".format(e))

    def _clear_candidate(self):
      try:
        os.remove(self.cand_config_file_path)
        return True
      except Exception:
        return False

    def _cli_commit(self, message='', revert_in=None):
      """
       Commits the changes requested by the method load_replace_candidate or load_merge_candidate.
       :return:
      """
      try:
          cmds = [
              # "enter candidate private name {}".format(self.private_candidate_name),
              "enter candidate private ",
              "/",
              'commit now comment "{}"'.format(message) if message else "commit now"
          ]
          output = self.device._jsonrpcRunCli(cmds)
          return self._return_result(output)
      except Exception as e:
          logging.error("Error occurred in _cli_commit: {}".format(e))
          raise CommitError(e) from e

    def compare_config(self):
        try:
            if not self._is_commit_pending(): #means to do compare for merge operation i.e onbox -remote diff
                return self._compare_config_on_box()
            else: #means to do compare for replace operation i.e offbox -local diff
                if self.running_format == "cli":
                    raise NotImplementedError("compare_config for 'cli' format is not supported")

                running_config = self.get_config()["running"]
                running_config_dict = json.loads(running_config)
                cand_config = None
                with open(self.cand_config_file_path) as f:
                    cand_config = json.load(f)
                    if 'updates' in cand_config:
                        return cand_config # The update is the diff
                    cand_config = cand_config['replaces'][0]['value']
                return self._diff_json(cand_config, running_config_dict)
        except Exception as e:
            logging.error("Error occurred in compare_config: {}".format(e))
            raise CommandErrorException(e) from e

    def _compare_config_on_box(self):
        """
        A string showing the difference between the running configuration and the candidate configuration.
        The running_config is loaded automatically just before doing the comparison so there is no need for you to do it.
        :return:
        """
        cmds = [
            "enter candidate private",
            "/",
            "diff"
        ]
        output = self.device._jsonrpcRunCli(cmds)
        if "result" in output:
            result = output["result"]
            return result[-1]["text"] if "text" in result[-1] else "" if result[-1] =={} else result[-1]
        elif "error" in output:
            return output["error"]
        return output

    def load_replace_candidate(self, filename=None, config=None):
      """
      Accepts either a native JSON formatted config, or a gNMI style JSON config
      containing only 'replaces'
      """
      try:
        return self._load_candidate(filename,config,is_replace=True)
      except Exception as e:
        raise ReplaceConfigException("Error during load_replace_candidate operation") from e

    def load_merge_candidate(self, filename=None, config=None):
      """
      Accepts either a native JSON formatted config (interpreted as 'update /')
      or a gNMI style JSON config containing any number of 'deletes','replaces','updates'
      """
      try:
        return self._load_candidate(filename,config,is_replace=False)
      except Exception as e:
        raise MergeConfigException("Error during load_merge_candidate operation") from e

    def _return_result(self,output):
      if "result" in output:
        result = output["result"]
        return result[-1]["text"] if "text" in result[-1] else result[-1]
      elif "error" in output:
        raise Exception(f"Error message from SRL : {output}")
      raise Exception(f"result not found in output. Output : {output}")

    def _load_candidate(self,filename,config,is_replace):
      if self._is_commit_pending():
        raise Exception("Candidate config is already loaded. Discard it to reload")

      if filename:
        with open(filename,"r") as f:
          config = f.read()
        if not config:
          raise Exception("Configuration is empty")
      elif not config:
        raise Exception("Either 'filename' or 'config' argument must be provided")

      cfg = None
      try:
        cfg = json.loads(config)   # try to load it as json, could keep order of keys
        if 'deletes' in cfg or 'updates' in cfg or 'replaces' in cfg:
          if is_replace:
            if ('deletes' in cfg or 'updates' in cfg):
              raise Exception("'load_replace_candidate' cannot contain 'deletes' or 'updates'")
            elif "path" not in cfg["replaces"] or cfg["replaces"]["path"] != "/":
              raise Exception("'load_replace_candidate' must use 'replaces' with a single path of '/'")
        else:
          cfg = { 'replaces' if is_replace else 'updates': [ { 'path': '/', 'value': cfg } ] }

        with open(self.cand_config_file_path, 'w') as f:
          json.dump(cfg, f, sort_keys=True)
        return "JSON candidate config loaded for " + ("replace" if is_replace else "merge")
      except json.decoder.JSONDecodeError: # Upon error, assume it's CLI commands
        cmds = [
          "enter candidate private",
          "/",
        ]
        if is_replace:
          cmds.append("delete /")
        cmds.extend( config.split("\n") )
        output = self.device._jsonrpcRunCli(cmds)
        return self._return_result(output)

    def commit_config(self, message='', revert_in=None):
      """
      This method creates a system-wide checkpoint containing the current state before this configuration change.
      """
      if revert_in:
        raise NotImplementedError("'revert_in' not implemented")

      # Create named checkpoint
      self.chkpoint_id = self.chkpoint_id + 1
      chkpt_cmds = [
        f"/tools system configuration generate-checkpoint name NAPALM-{self.chkpoint_id}"
      ]
      result = self.device._jsonrpcRunCli(chkpt_cmds)
      logging.info( f"Checkpoint 'NAPALM-{self.chkpoint_id}' created: {result}" )

      if self._is_commit_pending():
        with open(self.cand_config_file_path,"r") as f:
          try:
            json_config = json.load(f)
            if message:
              raise NotImplementedError("'message' not supported with JSON config")
            self.device._commit_json_config(json_config)
            self._clear_candidate()
            return "JSON config committed"

          # except grpc._channel._InactiveRpcError as e:
            # Log but do not raise
          # logging.error(e)

          except Exception as e:
            logging.error(e)
            raise CommitError(e) from e
      else:
        return self._cli_commit(message,revert_in)

    def discard_config(self):
      if not self._clear_candidate():
        cmds = [
         "enter candidate private",
         "/",
         "discard now"
        ]
        output = self.device._jsonrpcRunCli(cmds)
        return output["result"] if "result" in output else output

      return "Candidate config discarded"

    def _is_commit_pending(self):
        return os.path.isfile(self.cand_config_file_path)

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
        try:
            output = self.device._jsonrpcRunCli(
                [
                    "enter candidate private",
                    f"load checkpoint name NAPALM-{self.chkpoint_id}",   # Use named checkpoint to avoid parallel overwrite
                    "commit now"
                ]
            )
            return output
        except Exception as e:
            logging.error("Error occurred : {}".format(e))
            raise CommitError(e) from e

    def _getObj(self, obj, *keys, default=""):
        try:
            if len(keys) == 1:
                output = obj[keys[0]]
                return output if output else default
            else:
                output = self._getObj(obj[keys[0]], *keys[1:], default=default)
                return output if output else default
        except Exception as e:
            logging.error(e)
            # raise type(e)("{} occurred when trying to get path {}".format(e, keys))
            # return "##NOTFOUND##"
            return default

    def _get_old(self, obj, *keys, default=""):
        try:
            if len(keys) == 1:
                return obj[keys[0]]
            else:
                return self._get_old(obj[keys[0]], *keys[1:])
        except Exception as e:
            raise type(e)("{} occurred when trying to get path {}".format(e, keys))
            # return "##NOTFOUND##"
            # return default

    def _removeNotFound(self, obj):
        """
        removes the ##NOTFOUND## from the obj
        :param obj: shd be a dict or list. Can be nested
        :return:
        """
        if isinstance(obj, dict):
            result = {}
            for k, v in obj.items():
                if isinstance(v, dict) or isinstance(v, list):
                    result[k] = self._removeNotFound(v)
                elif isinstance(v, str) and v == "##NOTFOUND##":
                    continue
                else:
                    result[k] = v
            return result
        elif isinstance(obj, list):
            result = []
            for r in obj:
                if isinstance(r, dict) or isinstance(r, list):
                    result.append(self._removeNotFound(r))
                elif isinstance(r, str) and r == "##NOTFOUND##":
                    continue
                else:
                    result.append(r)
            return result

    def _diff_json(self, newjson, oldjson):
        try:
            j = jsondiff.jsondiff()
            return j.cmp_dict(newjson, oldjson)
        except Exception as e:
            logging.error("Error occurred : {}".format(e))

class SRLAPI(object):
    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        """Constructor."""
        self.device = None
        self._metadata = None

        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout

        self._stub = None
        self._channel = None

        if optional_args is None:
            optional_args = {}
        self.gnmi_port = optional_args.get("gnmi_port", 57400)
        self.jsonrpc_port = optional_args.get("jsonrpc_port", 443)
        if self.gnmi_port:
            self.target = str(self.hostname) + ":" + str(self.gnmi_port)
        self.target_name = optional_args.get("target_name", "")
        self.skip_verify = optional_args.get("skip_verify", False)
        self.insecure = optional_args.get("insecure", False)
        self.encoding = optional_args.get("encoding", "JSON_IETF")

        self.tls_ca = optional_args.get("tls_ca", "")
        self.tls_cert = optional_args.get("tls_cert", "")
        self.tls_key = optional_args.get("tls_key", "")

        ciphers = optional_args.get("jsonrpc_ciphers",
          "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:ECDHE-RSA-AES256-SHA")

        self.jsonrpc_session = requests.session()
        self.jsonrpc_session.mount("https://", TLSHttpAdapter(ciphers=ciphers))

        # Warn about incompatible/oddball settings
        if self.jsonrpc_port == 80:
            if not self.insecure:
                logging.warning( "Secure JSON RPC uses port 443, not 80. " +
                                 "Set 'insecure=True' flag to indicate this is ok" )
        elif self.jsonrpc_port != 443:
            logging.warning( f"Non-default JSON RPC port configured ({self.jsonrpc_port}), typically only 443(default) or 80 are used" )

        if not self.insecure:
            if not self.tls_ca:
                logging.warning( "Incompatible settings: insecure=False " + 
                                 "requires certificate parameter 'tls_ca' to be set " +
                                 "when using self-signed certificates" )

    def open(self):
        """Implement the NAPALM method open (mandatory)"""
        try:
            # read the certificates
            certs = {}
            if self.tls_ca:
                certs["root_certificates"] = self._readFile(self.tls_ca)
            if self.tls_cert:
                certs["certificate_chain"] = self._readFile(self.tls_cert)
            if self.tls_key:
                certs["private_key"] = self._readFile(self.tls_key)

            # If not provided and 'insecure' flag is set, fetch CA cert from server
            if 'root_certificates' not in certs and self.insecure:
                # Lazily import dependencies
                from cryptography import x509
                import ssl
                from cryptography.hazmat.backends import default_backend

                ssl_cert = ssl.get_server_certificate((self.hostname, self.gnmi_port)).encode("utf-8")
                certs["root_certificates"] = ssl_cert
                logging.warning("Using server certificate as root CA due to 'insecure' flag, not recommended for production use" )
                if not self.target_name:
                  ssl_cert_deserialized = x509.load_pem_x509_certificate(ssl_cert, default_backend())
                  ssl_cert_common_names = ssl_cert_deserialized.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
                  self.target_name = ssl_cert_common_names[0].value
                  logging.warning(f'ssl_target_name_override(={self.target_name}) is auto-discovered, should be used for testing only!')

            credentials = grpc.ssl_channel_credentials(**certs)
            self._metadata = [("username", self.username), ("password", self.password)]

            # open a secure channel, note that this does *not* send username/pwd yet...
            self._channel = grpc.secure_channel(
                target=self.target,
                credentials=credentials,
                options=(("grpc.ssl_target_name_override", self.target_name),),
            )

            if self._stub is None:
                self._stub = gnmi_pb2.gNMIStub(self._channel)
                # print("stub", self._stub)
        except Exception as e:
            logging.error("Error in Connection to SRL : {}".format(e))
            raise ConnectionException(e) from e

    def close(self):
        """Implement the NAPALM method close (mandatory)"""
        try:
            if not self._channel:
                logging.warning("No grpc channels created to close")
                return
            self._channel.close()
            self._channel = None
            self._stub = None
        except Exception as e:
            logging.error("Error occurred : {}".format(e))
            raise ConnectionException(e) from e

    @staticmethod
    def _readFile(filename):
        """
        Reads a binary certificate/key file
        Parameters:
            optionName(str): used to read filename from options
        Returns:
            File content
        Raises:
            ConnectionException: file does not exist or read excpetions
        """
        path = "/etc/ssl:/etc/ssl/certs:/etc/ca-certificates"

        if filename:
            if filename.startswith("~"):
                filename = os.path.expanduser(filename)
            if not filename.startswith("/"):
                for entry in path.split(":"):
                    if os.path.isfile(os.path.join(entry, filename)):
                        filename = os.path.join(entry, filename)
                        break
            if os.path.isfile(filename):
                try:
                    with open(filename, "rb") as f:
                        return f.read()
                except Exception as exc:
                    raise ConnectionException(
                        "Failed to read cert/keys file %s: %s" % (filename, exc)
                    )
            else:
                raise ConnectionException(
                    "Cert/keys file %s does not exist" % filename
                )
        return None

    def _jsonrpcRunCli(self, cmds):
        data = {
            "jsonrpc": "2.0",
            "id": 0,
            "method": "cli",
            "params": {
                "commands": cmds
            }
        }
        return self._jsonrpcPost(data)

    def _jsonrpcSet(self, cmds, other_params=None):
        data = {
            "jsonrpc": "2.0",
            "id": 0,
            "method": "set",
            "params": {
                "commands": cmds
            }
        }
        if other_params:
            data["params"].update(other_params)
        return self._jsonrpcPost(data)

    def _jsonrpcGet(self, cmds, other_params=None):
        data = {
            "jsonrpc": "2.0",
            "id": 0,
            "method": "get",
            "params": {
                "commands": cmds
            }
        }
        if other_params:
            data["params"].update(other_params)
        return self._jsonrpcPost(data)

    def _jsonrpcPost(self, json_data, timeout=None):
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        proto = "https" if (self.jsonrpc_port==443 or (self.jsonrpc_port!=80 and not self.insecure)) else "http"
        geturl = f"{proto}://{self.username}:{self.password}@{self.hostname}:{self.jsonrpc_port}/jsonrpc"
        cert = ( self.tls_cert, self.tls_key ) if self.tls_cert and self.tls_key else None
        resp = self.jsonrpc_session.post(geturl, headers=headers, json=json_data,
                                   timeout=timeout if timeout else self.timeout,
                                   cert=cert,
                                   verify=False if self.skip_verify else self.tls_ca)
        resp.raise_for_status()
        return resp.json() if resp.text else ""

    def _gnmiGet(self, prefix, path, pathType):
        """
            Executes a gNMI Get request
            Encoding that is used for data serialization is automatically determined
            based on the remote device capabilities. This gNMI plugin has implemented
            suppport for JSON_IETF (preferred) and JSON (fallback).
            Parameters:
                type (str): Type of data that is requested: ALL, CONFIG, STATE
                prefix (str): Path prefix that is added to all paths (XPATH syntax)
                paths (list): List of paths (str) to be captured
            Returns:
                str: GetResponse message converted into JSON format
        """
        # Remove all input parameters from kwargs that are not set

        input = {"path": path, "type": pathType, "encoding": self.encoding}
        input["path"] = [self._encodeXpath(path) for path in input["path"]]
        input["prefix"] = self._encodeXpath(prefix)

        try:
            request = json_format.ParseDict(input, gnmi_pb2.GetRequest())
            response = self._stub.Get(request, metadata=self._metadata)
            # print("response:", response)
        except Exception as e:
            if "StatusCode.INVALID_ARGUMENT" in str(e):
                return ""
            #logging.exception(e)
            else:
                for line in str(e).splitlines(False):
                    if "detail" in line:
                        raise Exception(line.strip()) from e
        output = self._mergeToSingleDict(
            json_format.MessageToDict(response)["notification"]
        )
        return output

    # def _gnmiSet1(self, prefix=None, updates=None, replaces=None, deletes=None, extensions=None):
    #     request = gnmi_pb2.SetRequest()
    #     if prefix:
    #         request.prefix.CopyFrom(prefix)
    #     test_list = [updates, replaces, deletes]
    #     if not any(test_list):
    #         raise Exception("At least update, replace, or delete must be specified!")
    #     for item in test_list:
    #         if not item:
    #             continue
    #         if not isinstance(item, (list, set)):
    #             raise Exception("updates, replaces, and deletes must be iterables!")
    #     if updates:
    #         updates1 =[]
    #         for u in updates:
    #             update = gnmi_pb2.Update()
    #             update.val.json_ietf_val = gnmi_pb2.Path(u["val"])
    #             update.path.CopyFrom(u["path"])
    #             updates1.append(update)
    #         request.update.extend(updates1)
    #     if replaces:
    #         request.replace.extend(replaces)
    #     if deletes:
    #         request.delete.extend(deletes)
    #     if extensions:
    #         request.extension.extend(extensions)
    #
    #
    #     response = self._stub.Set(request, metadata={"username":""})
    #     print(response)


    # def _gnmi_update(self, update_path, update_json):
    #     update = gnmi_pb2.Update()
    #     path = json_format.ParseDict(self._encodeXpath(update_path), gnmi_pb2.Path())
    #     update.path.CopyFrom(path)
    #     update.val.json_ietf_val = json.dumps(update_json).encode("utf-8")
    #     updates = [update]
    #     self._gnmiSet(update = updates)


    # def gnmi_replace(self, replace_json):
    #     update = gnmi_pb2.Update()
    #     #path = json_format.ParseDict(self._encodeXpath(replace_path), gnmi_pb2.Path())
    #     #update.path.CopyFrom(path)
    #     update.val.json_ietf_val = json.dumps(replace_json).encode("utf-8")
    #     updates = [update]
    #     self._gnmiSet(replace = updates)

    # def _gnmiSet(self, prefix=None, delete=None, replace=None, update=None):
    #     request = gnmi_pb2.SetRequest()
    #     if prefix: request.prefix.CopyFrom(prefix)
    #     if update: request.update.extend(update)
    #     if delete: request.delete.extend(delete)
    #     if replace: request.replace.extend(replace)
    #     self._stub.Set(request, metadata=self._metadata)

    def _commit_json_config(self,json_config):
        request = gnmi_pb2.SetRequest()
        if 'deletes' in json_config:
          request.delete.extend( [ json_format.ParseDict(self._encodeXpath(p), gnmi_pb2.Path()) for p in json_config['deletes']] )
        for k in ('replaces','updates'):
          if k in json_config:
            items = []
            for u in json_config[k]:
              update = gnmi_pb2.Update()
              path = json_format.ParseDict(self._encodeXpath(u['path']), gnmi_pb2.Path())
              update.path.CopyFrom(path)
              update.val.json_ietf_val = json.dumps(u['value']).encode("utf-8")
              items.append(update)
            if k=='replaces':
              request.replace.extend( items )
            else:
              request.update.extend( items )
        self._stub.Set(request, metadata=self._metadata)

    @staticmethod
    def _encodeXpath(path):
        """
        Encodes XPATH to dict representation that allows conversion to gnmi_pb.Path object
        Parameters:
            xpath (str): path string using XPATH syntax
        Returns:
            (dict): path dict using gnmi_pb2.Path structure for easy conversion
        """
        mypath = []
        xpath = path.strip("\t\n\r /")
        if xpath:
            path_elements = re.split(r"""/(?=(?:[^\[\]]|\[[^\[\]]+\])*$)""", xpath)
            for e in path_elements:
                entry = {"name": e.split("[", 1)[0]}
                eKeys = re.findall(r"\[(.*?)\]", e)
                dKeys = dict(x.split("=", 1) for x in eKeys)
                if dKeys:
                    entry["key"] = dKeys
                mypath.append(entry)
            return {"elem": mypath}
        return {}

    def _mergeToSingleDict(self, rawData):
        result = {}

        for entry in rawData:
            if "syncResponse" in entry and entry["syncResponse"]:
                # Ignore: SyncResponse is sent after initial update
                break
            elif "update" not in entry:
                # Ignore: entry without updates
                break
            elif "timestamp" not in entry:
                # Subscribe response, enter update context
                entry = entry["update"]
            else:
                # Get response, keep context
                pass

            prfx = result
            if ("prefix" in entry) and ("elem" in entry["prefix"]):
                prfx_elements = entry["prefix"]["elem"]
            else:
                prfx_elements = []

            for elem in prfx_elements:
                eleName = elem["name"]
                if "key" in elem:
                    eleKey = json.dumps(elem["key"])
                    eleName = "___" + eleName
                    # Path Element has key => must be list()
                    if eleName in prfx:
                        # Path Element exists => Change Context
                        prfx = prfx[eleName]
                        if eleKey not in prfx:
                            # List entry does not exist => Create
                            prfx[eleKey] = elem["key"]
                        prfx = prfx[eleKey]
                    else:
                        # Path Element does not exist => Create
                        prfx[eleName] = {}
                        prfx = prfx[eleName]
                        prfx[eleKey] = elem["key"]
                        prfx = prfx[eleKey]
                else:
                    # Path Element hasn't key => must be dict()
                    if eleName in prfx:
                        # Path Element exists => Change Context
                        prfx = prfx[eleName]
                    else:
                        # Path Element does not exist => Create
                        prfx[eleName] = {}
                        prfx = prfx[eleName]

            for _upd in entry["update"]:
                if "val" not in _upd:
                    # requested path without content (no value) => skip
                    continue
                elif ("path" in _upd) and ("elem" in _upd["path"]):
                    path_elements = _upd["path"]["elem"]
                    cPath = prfx
                elif prfx_elements:
                    path_elements = prfx_elements
                    cPath = result
                else:
                    # No path at all, replace the objecttree with value
                    result = self._decodeVal(_upd["val"])
                    prfx = result
                    continue

                # If path_elements has more than just a single entry,
                # we need to create/navigate to the specified subcontext
                for elem in path_elements[:-1]:
                    eleName = elem["name"]
                    if "key" in elem:
                        eleKey = json.dumps(elem["key"])
                        eleName = "___" + eleName
                        # Path Element has key => must be list()
                        if eleName in cPath:
                            # Path Element exists => Change Context
                            cPath = cPath[eleName]
                            if eleKey not in cPath:
                                # List entry does not exist => Create
                                cPath[eleKey] = elem["key"]
                            cPath = cPath[eleKey]
                        else:
                            # Path Element does not exist => Create
                            cPath[eleName] = {}
                            cPath = cPath[eleName]
                            cPath[eleKey] = elem["key"]
                            cPath = cPath[eleKey]
                    else:
                        # Path Element hasn't key => must be dict()
                        if eleName in cPath:
                            # Path Element exists => Change Context
                            cPath = cPath[eleName]
                        else:
                            # Path Element does not exist => Create
                            cPath[eleName] = {}
                            cPath = cPath[eleName]

                # The last entry of path_elements is the leaf element
                # that needs to be created/updated
                leaf_elem = path_elements[-1]
                if "key" in leaf_elem:
                    eleKey = json.dumps(leaf_elem["key"])
                    eleName = "___" + leaf_elem["name"]
                    if eleName not in cPath:
                        cPath[eleName] = {}
                    cPath = cPath[eleName]
                    cPath[eleKey] = self._decodeVal(_upd["val"])
                else:
                    cPath[leaf_elem["name"]] = self._decodeVal(_upd["val"])

        return self._dictToList(result)

    def _decodeVal(self, val):
        """
        Decodes value from dict representation converted from gnmi_pb.TypedValue object
        Parameters:
            val (dict): decoded gnmi_pb.TypedValue object
        Returns:
            (ANY): extracted data
        """
        if "jsonIetfVal" in val:
            return json.loads(base64.b64decode(val["jsonIetfVal"]))
        elif "jsonVal" in val:
            return json.loads(base64.b64decode(val["jsonVal"]))
        else:
            raise ConnectionException(
                "gNMI plugin does not support encoding for value: %s" % json.dumps(val)
            )

    def _dictToList(self, aDict):
        for key in aDict.keys():
            if key.startswith("___"):
                aDict[key[3:]] = [
                    self._dictToList(val) if isinstance(val, dict) else val
                    for val in aDict[key].values()
                ]
                del aDict[key]
            else:
                if isinstance(aDict[key], dict):
                    aDict[key] = self._dictToList(aDict[key])
        return aDict
