# Copyright 2024 Nokia
# Licensed under the Apache License 2.0.
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the pure helper functions (no I/O, no fixtures)."""


from napalm_srlinux import helpers

PING_OUTPUT = """PING 192.168.1.1 (192.168.1.1) 100(128) bytes of data.
108 bytes from 192.168.1.1: icmp_seq=1 ttl=64 time=0.422 ms
108 bytes from 192.168.1.1: icmp_seq=2 ttl=64 time=0.301 ms
108 bytes from 192.168.1.1: icmp_seq=3 ttl=64 time=0.298 ms

--- 192.168.1.1 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2037ms
rtt min/avg/max/mdev = 0.298/0.340/0.422/0.057 ms
"""

PING_OUTPUT_TOTAL_LOSS = """PING 10.0.0.99 (10.0.0.99) 100(128) bytes of data.

--- 10.0.0.99 ping statistics ---
5 packets transmitted, 0 received, 100% packet loss, time 4094ms

"""

TRACEROUTE_OUTPUT = """traceroute to 192.168.1.1 (192.168.1.1), 30 hops max, 60 byte packets
 1  gateway (172.20.20.1)  0.351 ms  0.243 ms  0.231 ms
 2  192.168.1.1 (192.168.1.1)  1.046 ms  1.232 ms  1.115 ms
"""


class TestDetermineJsonrpcPort:
    def test_default(self):
        assert helpers.determine_jsonrpc_port({}) == 443

    def test_none(self):
        assert helpers.determine_jsonrpc_port(None) == 443

    def test_explicit_port(self):
        assert helpers.determine_jsonrpc_port({"jsonrpc_port": 8080}) == 8080

    def test_insecure(self):
        assert helpers.determine_jsonrpc_port({"insecure": True}) == 80

    def test_explicit_port_wins_over_insecure(self):
        assert helpers.determine_jsonrpc_port({"jsonrpc_port": 9000, "insecure": True}) == 9000


class TestComposeJsonrpcUrl:
    def test_https(self):
        assert helpers.compose_jsonrpc_url("srl", 443) == "https://srl:443/jsonrpc"

    def test_insecure_http(self):
        assert helpers.compose_jsonrpc_url("srl", 80, insecure=True) == "http://srl:80/jsonrpc"


class TestPortSpeedToMbits:
    def test_one_gigabit_is_1000_mbit(self):
        assert helpers.port_speed_to_mbits("1G") == 1000.0

    def test_ten_megabit(self):
        assert helpers.port_speed_to_mbits("10M") == 10.0

    def test_one_terabit(self):
        assert helpers.port_speed_to_mbits("1T") == 1_000_000.0

    def test_unknown(self):
        assert helpers.port_speed_to_mbits("3G") == 0.0

    def test_missing(self):
        assert helpers.port_speed_to_mbits(None) == 0.0


class TestSecondsBetween:
    def test_simple(self):
        delta = helpers.seconds_between(
            "2024-08-24T10:00:30.000Z", "2024-08-24T10:00:00.000Z"
        )
        assert delta == 30.0

    def test_delta_longer_than_a_day(self):
        """Regression: a naive .seconds would drop the days component."""
        delta = helpers.seconds_between(
            "2024-08-26T10:00:00.000Z", "2024-08-24T10:00:00.000Z"
        )
        assert delta == 2 * 24 * 3600.0


class TestValueAt:
    DATA = {
        "srl_nokia-interfaces:interface": [
            {"name": "ethernet-1/1", "ethernet": {"port-speed": "25G"}}
        ],
        "plain": {"nested": 42},
    }

    def test_module_prefixed_key(self):
        assert helpers.value_at(self.DATA, "interface", 0, "name") == "ethernet-1/1"

    def test_verbatim_key(self):
        assert helpers.value_at(self.DATA, "plain", "nested") == 42

    def test_missing_returns_default(self):
        assert helpers.value_at(self.DATA, "plain", "nope", default="x") == "x"

    def test_list_index_out_of_range(self):
        assert helpers.value_at(self.DATA, "interface", 5, "name", default=None) is None

    def test_traversal_through_non_container(self):
        assert helpers.value_at(self.DATA, "plain", "nested", "deeper", default=-1) == -1


class TestStripModulePrefix:
    def test_prefixed(self):
        assert helpers.strip_module_prefix("srl_nokia-common:ipv4-unicast") == "ipv4-unicast"

    def test_unprefixed(self):
        assert helpers.strip_module_prefix("router") == "router"


class TestParsePingOutput:
    def test_successful_ping(self):
        result = helpers.parse_ping_output(PING_OUTPUT)
        success = result["success"]
        assert success["probes_sent"] == 3
        assert success["packet_loss"] == 0
        assert success["rtt_min"] == 0.298
        assert success["rtt_avg"] == 0.340
        assert success["rtt_max"] == 0.422
        assert success["rtt_stddev"] == 0.057
        assert len(success["results"]) == 3
        assert success["results"][0] == {"ip_address": "192.168.1.1", "rtt": 0.422}

    def test_total_loss_has_no_rtt_stats(self):
        result = helpers.parse_ping_output(PING_OUTPUT_TOTAL_LOSS)
        success = result["success"]
        assert success["probes_sent"] == 5
        assert success["packet_loss"] == 5
        assert success["rtt_min"] == -1.0
        assert success["results"] == []

    def test_types_are_correct(self):
        success = helpers.parse_ping_output(PING_OUTPUT)["success"]
        assert isinstance(success["probes_sent"], int)
        assert isinstance(success["packet_loss"], int)
        assert isinstance(success["rtt_min"], float)
        for probe in success["results"]:
            assert isinstance(probe["rtt"], float)

    def test_garbage_input(self):
        assert "error" in helpers.parse_ping_output("no ping output here")


class TestParseTracerouteOutput:
    def test_successful_traceroute(self):
        result = helpers.parse_traceroute_output(TRACEROUTE_OUTPUT)
        hops = result["success"]
        assert set(hops) == {1, 2}
        assert hops[1]["probes"][1] == {
            "rtt": 0.351,
            "ip_address": "172.20.20.1",
            "host_name": "gateway",
        }
        assert hops[2]["probes"][3]["rtt"] == 1.115

    def test_garbage_input(self):
        assert "error" in helpers.parse_traceroute_output("nothing useful")
