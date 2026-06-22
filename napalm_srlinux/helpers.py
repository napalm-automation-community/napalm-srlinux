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

"""Pure helper functions for the SR Linux NAPALM driver.

Everything in this module is free of I/O so it can be unit tested without a
device or any mocking.
"""

import datetime
import re
from typing import Any

# SR Linux timestamps, e.g. "2024-08-24T09:36:31.000Z"
SRL_TIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"

# port-speed leaf value -> Mbit/s (NAPALM interface speed unit)
PORT_SPEED_MBITS = {
    "10M": 10.0,
    "100M": 100.0,
    "1G": 1000.0,
    "10G": 10_000.0,
    "25G": 25_000.0,
    "40G": 40_000.0,
    "50G": 50_000.0,
    "100G": 100_000.0,
    "200G": 200_000.0,
    "400G": 400_000.0,
    "800G": 800_000.0,
    "1T": 1_000_000.0,
}


def determine_jsonrpc_port(optional_args: dict | None) -> int:
    """Determine the JSON-RPC port from the driver's optional arguments.

    An explicitly configured ``jsonrpc_port`` always wins; otherwise port 80
    is used for ``insecure`` (plain http) connections and 443 for https.
    """
    optional_args = optional_args or {}

    if optional_args.get("jsonrpc_port"):
        return int(optional_args["jsonrpc_port"])
    if optional_args.get("insecure"):
        return 80
    return 443


def compose_jsonrpc_url(hostname: str, port: int, insecure: bool = False) -> str:
    """Compose the JSON-RPC endpoint URL."""
    proto = "http" if insecure else "https"
    return f"{proto}://{hostname}:{port}/jsonrpc"


def strip_module_prefix(name: str) -> str:
    """Strip a YANG module prefix from a value, e.g. "srl_nokia-common:ipv4-unicast" -> "ipv4-unicast"."""
    return name.split(":", 1)[-1]


def value_at(obj: Any, *keys: str | int, default: Any = None) -> Any:
    """Traverse nested dicts/lists, returning ``default`` when any step is missing.

    Keys with a YANG module prefix are matched both verbatim and by their
    unprefixed name, so ``value_at(d, "interface")`` finds
    ``d["srl_nokia-interfaces:interface"]`` too.
    """
    cur = obj
    for key in keys:
        if isinstance(cur, list):
            if not isinstance(key, int) or key >= len(cur):
                return default
            cur = cur[key]
        elif isinstance(cur, dict):
            if key in cur:
                cur = cur[key]
            else:
                match = [v for k, v in cur.items() if strip_module_prefix(k) == key]
                if not match:
                    return default
                cur = match[0]
        else:
            return default
    return cur if cur is not None else default


def parse_srl_time(timestamp: str) -> datetime.datetime:
    """Parse an SR Linux timestamp string."""
    return datetime.datetime.strptime(timestamp, SRL_TIME_FORMAT)


def seconds_between(system_time: str, reference_time: str) -> float:
    """Seconds elapsed between a (past) reference timestamp and the system time."""
    return (parse_srl_time(system_time) - parse_srl_time(reference_time)).total_seconds()


def port_speed_to_mbits(port_speed: str | None) -> float:
    """Convert an SR Linux port-speed leaf (e.g. "100G") to Mbit/s."""
    return PORT_SPEED_MBITS.get(port_speed, 0.0)


_PING_STATS_RE = re.compile(
    r"(\d+) packets transmitted, (\d+) received, (\d*\.?\d*)% packet loss"
    r"(?:.*?rtt min/avg/max/mdev = (\d*\.?\d*)/(\d*\.?\d*)/(\d*\.?\d*)/(\d*\.?\d*))?",
    re.DOTALL,
)
_PING_PROBE_RE = re.compile(
    r"from (?:(\S+) \()?((?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]+)\)?: "
    r"icmp_seq=\d+ ttl=\d+ time=(\d+\.?\d*) ms"
)


def parse_ping_output(text: str) -> dict:
    """Parse SR Linux ping CLI output into the NAPALM ping dictionary."""
    stats = _PING_STATS_RE.search(text)
    if not stats:
        return {"error": "Unable to parse ping output"}

    sent = int(stats.group(1))
    received = int(stats.group(2))
    has_rtt = stats.group(4) is not None

    results = [
        {"ip_address": m.group(2), "rtt": float(m.group(3))}
        for m in _PING_PROBE_RE.finditer(text)
    ]

    return {
        "success": {
            "probes_sent": sent,
            "packet_loss": sent - received,
            "rtt_min": float(stats.group(4)) if has_rtt else -1.0,
            "rtt_avg": float(stats.group(5)) if has_rtt else -1.0,
            "rtt_max": float(stats.group(6)) if has_rtt else -1.0,
            "rtt_stddev": float(stats.group(7)) if has_rtt else -1.0,
            "results": results,
        }
    }


_TRACEROUTE_HOP_RE = re.compile(
    r"^\s*(\d+)\s+(.*)$",
)
_TRACEROUTE_PROBE_RE = re.compile(
    r"(?:(\S+)\s+\(((?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]+)\)\s+)?(\d+\.?\d*)\s*ms"
)


def parse_traceroute_output(text: str) -> dict:
    """Parse SR Linux traceroute CLI output into the NAPALM traceroute dictionary."""
    hops: dict[int, dict] = {}

    for line in text.splitlines():
        hop_match = _TRACEROUTE_HOP_RE.match(line)
        if not hop_match or "traceroute to" in line:
            continue
        hop_index = int(hop_match.group(1))
        remainder = hop_match.group(2)

        probes: dict[int, dict] = {}
        probe_index = 0
        last_host, last_ip = "", ""
        for probe in _TRACEROUTE_PROBE_RE.finditer(remainder):
            probe_index += 1
            host, ip, rtt = probe.group(1), probe.group(2), probe.group(3)
            if host:
                last_host, last_ip = host, ip
            probes[probe_index] = {
                "rtt": float(rtt),
                "ip_address": last_ip,
                "host_name": last_host,
            }
        if "*" in remainder and not probes:
            probes[1] = {"rtt": -1.0, "ip_address": "*", "host_name": "*"}
        if probes:
            hops[hop_index] = {"probes": probes}

    if not hops:
        return {"error": "Unable to parse traceroute output"}
    return {"success": hops}
