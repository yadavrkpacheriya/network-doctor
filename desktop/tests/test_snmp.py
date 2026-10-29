# -*- coding: utf-8 -*-
"""Tests for nd_snmp / nd_plugins against a small fake SNMP agent on localhost.
Run from desktop/:  python -m unittest discover -s tests"""

import os
import socket
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import nd_plugins  # noqa: E402
import nd_snmp as S  # noqa: E402

MAC_PC = bytes.fromhex("001122334455")
MAC_AP = bytes.fromhex("A0B1C2D3E4F5")

MIB = {
    "1.3.6.1.2.1.1.1.0": b"TP-Link JetStream 24-Port Gigabit Switch",
    "1.3.6.1.2.1.1.2.0": (S.OID, "1.3.6.1.4.1.11863.5.1"),
    "1.3.6.1.2.1.1.3.0": (S.TIMETICKS, 9000000),  # 1 day 1 h
    "1.3.6.1.2.1.1.5.0": b"sw-accounts",
    "1.3.6.1.2.1.1.6.0": b"2nd floor rack",
    # ifTable: descr, oper, speed, in octets
    "1.3.6.1.2.1.2.2.1.2.1": b"gigabitEthernet 1/0/1",
    "1.3.6.1.2.1.2.2.1.2.2": b"gigabitEthernet 1/0/2",
    "1.3.6.1.2.1.2.2.1.5.1": (S.GAUGE32, 1000000000),
    "1.3.6.1.2.1.2.2.1.5.2": (S.GAUGE32, 100000000),
    "1.3.6.1.2.1.2.2.1.8.1": 1,
    "1.3.6.1.2.1.2.2.1.8.2": 2,
    "1.3.6.1.2.1.2.2.1.10.1": (S.COUNTER32, 12345),
    "1.3.6.1.2.1.2.2.1.14.1": (S.COUNTER32, 7),
    # ifXTable: name, high speed, 64-bit counters
    "1.3.6.1.2.1.31.1.1.1.1.1": b"Gi1/0/1",
    "1.3.6.1.2.1.31.1.1.1.1.2": b"Gi1/0/2",
    "1.3.6.1.2.1.31.1.1.1.6.1": (S.COUNTER64, 2 ** 40),
    "1.3.6.1.2.1.31.1.1.1.15.1": (S.GAUGE32, 1000),
    # LLDP: neighbour on local port 1
    "1.0.8802.1.1.2.1.3.7.1.4.1": b"Gi1/0/1",
    "1.0.8802.1.1.2.1.4.1.1.5.0.1.1": MAC_AP,
    "1.0.8802.1.1.2.1.4.1.1.7.0.1.1": b"eth0",
    "1.0.8802.1.1.2.1.4.1.1.9.0.1.1": b"ap-lobby",
    # BRIDGE-MIB: bridge port -> ifIndex, MAC table
    "1.3.6.1.2.1.17.1.4.1.2.1": 1,
    "1.3.6.1.2.1.17.1.4.1.2.2": 2,
    "1.3.6.1.2.1.17.4.3.1.2.0.17.34.51.68.85": 2,
    "1.3.6.1.2.1.17.4.3.1.3.0.17.34.51.68.85": 3,
    "1.3.6.1.2.1.17.4.3.1.2.160.177.194.211.228.245": 1,
    "1.3.6.1.2.1.17.4.3.1.3.160.177.194.211.228.245": 3,
    "1.3.6.1.2.1.17.4.3.1.2.170.170.170.170.170.170": 1,
    "1.3.6.1.2.1.17.4.3.1.3.170.170.170.170.170.170": 4,  # the switch itself: skipped
}


class FakeAgent:
    def __init__(self, mib, community="public", write_community="private"):
        self.mib = mib
        self.write_community = write_community
        self.keys = sorted(mib, key=S.oid_key)
        self.community = community
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.requests = 0
        threading.Thread(target=self._serve, daemon=True).start()

    def _next(self, oid):
        k = S.oid_key(oid)
        for o in self.keys:
            if S.oid_key(o) > k:
                return o
        return None

    def _serve(self):
        while True:
            try:
                data, addr = self.sock.recvfrom(65535)
            except OSError:
                return
            self.requests += 1
            r = S.parse_message(data)
            if r["community"] not in (self.community, self.write_community):
                continue  # real agents stay silent on a wrong community
            out, err = [], 0
            if r["type"] == S.SET:
                out = r["varbinds"]
                if r["community"] != self.write_community:
                    err = 6  # noAccess: the read-only community cannot write
                else:
                    for o, v in out:
                        self.mib[o] = v
            if r["type"] == S.GET:
                out = [(o, self.mib.get(o, S.Missing(S.NO_SUCH_OBJECT))) for o, _ in r["varbinds"]]
            elif r["type"] == S.GETNEXT:
                for o, _ in r["varbinds"]:
                    n = self._next(o)
                    out.append((n, self.mib[n]) if n else (o, S.Missing(S.END_OF_MIB)))
            elif r["type"] == S.GETBULK:
                o = r["varbinds"][0][0]
                for _ in range(r["error_index"]):  # max-repetitions
                    n = self._next(o)
                    if not n:
                        out.append((o, S.Missing(S.END_OF_MIB)))
                        break
                    out.append((n, self.mib[n]))
                    o = n
            self.sock.sendto(S.build_message(S.RESPONSE, r["request_id"], out, r["community"], r["version"], err,
                                             1 if err else 0), addr)

    def close(self):
        self.sock.close()


class Ber(unittest.TestCase):
    def test_oid_roundtrip(self):
        for oid in ("1.3.6.1.2.1.1.1.0", "1.0.8802.1.1.2.1.4.1.1.9", "1.3.6.1.4.1.14988.1", "2.999.3"):
            _, body, _ = S.read_tlv(S.enc_oid(oid), 0)
            self.assertEqual(S.dec_oid(body), oid)

    def test_integers(self):
        for v in (0, 1, 127, 128, 255, 256, -1, -129, 2 ** 31 - 1):
            tag, body, _ = S.read_tlv(S.enc_int(v), 0)
            self.assertEqual(S.dec_value(tag, body), v)
        tag, body, _ = S.read_tlv(S.enc_uint(2 ** 63 + 5, S.COUNTER64), 0)
        self.assertEqual(S.dec_value(tag, body), 2 ** 63 + 5)

    def test_long_length(self):
        big = b"x" * 300
        tag, body, nxt = S.read_tlv(S.tlv(S.OCTET_STRING, big), 0)
        self.assertEqual((tag, body, nxt), (S.OCTET_STRING, big, 304))

    def test_message_roundtrip(self):
        pkt = S.build_message(S.GET, 42, [("1.3.6.1.2.1.1.5.0", None)], "secret", 1)
        r = S.parse_message(pkt)
        self.assertEqual((r["type"], r["request_id"], r["community"]), (S.GET, 42, "secret"))
        self.assertEqual(r["varbinds"], [("1.3.6.1.2.1.1.5.0", None)])

    def test_truncated(self):
        with self.assertRaises(S.SnmpError):
            S.parse_message(S.build_message(S.GET, 1, [("1.3.6.1", None)])[:-3])

    def test_helpers(self):
        self.assertEqual(S.text(b"sw-1\x00"), "sw-1")
        self.assertEqual(S.text(MAC_PC), "00:11:22:33:44:55")
        self.assertEqual(S.vendor_of_oid("1.3.6.1.4.1.14988.1"), "MikroTik")
        self.assertEqual(S.uptime_text(9000000), "1 d 1 h 0 min")
        self.assertEqual(S.speed_text(1000), "1 Gbps")
        self.assertEqual(S.speed_text(2500), "2.5 Gbps")
        self.assertEqual(S.speed_text(100), "100 Mbps")


class AgentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.agent = FakeAgent(MIB)

    @classmethod
    def tearDownClass(cls):
        cls.agent.close()

    def client(self, version="2c", community="public"):
        return S.Snmp("127.0.0.1", community, version, port=self.agent.port, timeout=1, retries=0)

    def test_get(self):
        r = self.client().get("1.3.6.1.2.1.1.5.0", "1.3.6.1.2.1.1.99.0")
        self.assertEqual(r, {"1.3.6.1.2.1.1.5.0": b"sw-accounts"})

    def test_walk_v2c_and_v1_agree(self):
        root = "1.3.6.1.2.1.2.2.1"
        self.assertEqual(self.client("2c").walk(root), self.client("1").walk(root))
        self.assertEqual(len(self.client().walk(root)), 8)

    def test_wrong_community(self):
        with self.assertRaises(S.SnmpError):
            self.client(community="wrong").get("1.3.6.1.2.1.1.5.0")

    def test_read_device(self):
        c = self.client()
        info = S.system_info(c)
        self.assertEqual((info["name"], info["vendor"], info["location"]), ("sw-accounts", "TP-Link", "2nd floor rack"))
        ifs = S.interfaces(c)
        self.assertEqual([i["name"] for i in ifs], ["Gi1/0/1", "Gi1/0/2"])
        self.assertEqual([i["status"] for i in ifs], ["up", "down"])
        self.assertEqual([i["speed_mbps"] for i in ifs], [1000, 100])
        self.assertEqual(ifs[0]["in_octets"], 2 ** 40)  # 64-bit counter preferred
        self.assertEqual(ifs[1]["in_octets"], None)
        self.assertEqual(ifs[0]["in_errors"], 7)
        nb = S.lldp_neighbors(c)
        self.assertEqual(nb, [{"local_port": "Gi1/0/1", "name": "ap-lobby", "port": "eth0", "port_descr": "",
                               "descr": "", "chassis": "A0:B1:C2:D3:E4:F5"}])
        macs = S.mac_table(c, ifs)
        self.assertEqual(macs, {"00:11:22:33:44:55": "Gi1/0/2", "A0:B1:C2:D3:E4:F5": "Gi1/0/1"})
        self.assertEqual(S.ports_with_devices(macs), {"Gi1/0/1": ["A0:B1:C2:D3:E4:F5"],
                                                      "Gi1/0/2": ["00:11:22:33:44:55"]})

    def test_plugin(self):
        p = nd_plugins.SnmpPlugin()
        orig = S.Snmp.__init__

        def at_agent(this, host, community="public", version="2c", port=161, **kw):
            orig(this, host, community, version, port=self.agent.port, timeout=1, retries=0)
        S.Snmp.__init__ = at_agent
        try:
            self.assertTrue(p.probe("127.0.0.1", {}))
            self.assertFalse(p.probe("127.0.0.1", {"community": "wrong"}))
            self.assertIs(nd_plugins.find("127.0.0.1", {}), nd_plugins.PLUGINS[0])
            d = p.read("127.0.0.1", {"community": "public"})
            self.assertEqual(d["system"]["name"], "sw-accounts")
            self.assertEqual(len(d["macs"]), 2)
        finally:
            S.Snmp.__init__ = orig


class LiveTraffic(unittest.TestCase):
    """counters() -> rates() -> port_warnings() / mac_moves(): the live traffic and loop check."""

    def test_counters_and_rates(self):
        mib = dict(MIB)
        mib["1.3.6.1.2.1.31.1.1.1.9.1"] = (S.COUNTER64, 1000)          # broadcasts in
        mib["1.3.6.1.2.1.31.1.1.1.7.1"] = (S.COUNTER64, 5000)          # unicast in
        mib["1.3.6.1.2.1.31.1.1.1.10.1"] = (S.COUNTER64, 0)            # out octets
        agent = FakeAgent(mib)
        try:
            c = S.Snmp("127.0.0.1", port=agent.port, timeout=1, retries=0)
            a = S.counters(c, clock=lambda: 100.0)
            self.assertEqual(a["bits"]["in"], 64)
            self.assertEqual(a["ports"][1]["in"], 2 ** 40)
            self.assertEqual(a["ports"][1]["in_err"], 7)
            mib["1.3.6.1.2.1.31.1.1.1.6.1"] = (S.COUNTER64, 2 ** 40 + 12_500_000)  # 100 Mbit in 10 s
            mib["1.3.6.1.2.1.31.1.1.1.9.1"] = (S.COUNTER64, 1000 + 30_000)        # 3000 broadcasts / s
            b = S.counters(c, clock=lambda: 110.0)
        finally:
            agent.close()
        r = S.rates(a, b)[1]
        self.assertAlmostEqual(r["in"], 1_250_000)  # bytes / s = 10 Mbit/s
        self.assertAlmostEqual(r["bcast"], 3000)
        self.assertAlmostEqual(S.utilisation(r, 1000), 1.0)
        w = S.port_warnings(r, 1000)
        self.assertEqual(w[0][0], "crit")
        self.assertIn("storm", w[0][1])

    def test_wrap_and_reset(self):
        a = {"time": 0, "ports": {1: {"in": 2 ** 32 - 100, "out": 500}}, "bits": {"in": 32, "out": 64}}
        b = {"time": 2, "ports": {1: {"in": 100, "out": 10}}, "bits": {"in": 32, "out": 64}}
        r = S.rates(a, b)[1]
        self.assertEqual(r["in"], 100)       # 32-bit counter wrapped: 200 bytes in 2 s
        self.assertNotIn("out", r)           # 64-bit counter went back: device reset, no rate

    def test_warnings(self):
        self.assertEqual(S.port_warnings({"in": 1000, "bcast": 20, "ucast": 500}, 1000), [])
        loop = S.port_warnings({"bcast": 400, "ucast": 100}, 1000)
        self.assertEqual(loop[0][0], "crit")
        self.assertEqual(S.port_warnings({"bcast": 400, "ucast": 5000}, 1000), [])  # busy server, not a loop
        busy = S.port_warnings({"in": 11_000_000}, 100)  # 88 Mbit/s on a 100 Mbit port
        self.assertEqual([lv for lv, _ in busy], ["warn"])
        self.assertIsNone(S.utilisation({"in": 5}, 0))

    def test_mac_moves(self):
        before = {"A": "Gi1/0/2", "B": "Gi1/0/2", "C": "Gi1/0/10", "D": "Gi1/0/5"}
        after = {"A": "Gi1/0/10", "B": "Gi1/0/10", "C": "Gi1/0/2", "D": "Gi1/0/5", "E": "Gi1/0/7"}
        self.assertEqual(S.mac_moves(before, after), {("Gi1/0/2", "Gi1/0/10"): ["A", "B", "C"]})


class PortControl(unittest.TestCase):
    """Turning a port off / on and renaming it, only with the write community."""

    def setUp(self):
        self.mib = dict(MIB)
        self.mib["1.3.6.1.2.1.2.2.1.7.2"] = 1
        self.mib["1.3.6.1.2.1.31.1.1.1.18.2"] = b"old desk"
        self.agent = FakeAgent(self.mib)

    def tearDown(self):
        self.agent.close()

    def client(self, community):
        return S.Snmp("127.0.0.1", community, port=self.agent.port, timeout=1, retries=0)

    def test_read_community_is_refused(self):
        with self.assertRaises(S.SnmpError) as e:
            S.set_port(self.client("public"), 2, False)
        self.assertIn("read-WRITE community", str(e.exception))
        self.assertEqual(self.mib["1.3.6.1.2.1.2.2.1.7.2"], 1)

    def test_port_off_on_and_rename(self):
        c = self.client("private")
        self.assertEqual(S.set_port(c, 2, False), "down")
        self.assertEqual(S.set_port(c, 2, True), "up")
        self.assertEqual(S.set_alias(c, 2, "Reception PC"), "old desk")
        self.assertEqual(S.text(self.mib["1.3.6.1.2.1.31.1.1.1.18.2"]), "Reception PC")

    def test_port_risk(self):
        macs = {"AA": "Gi1/0/1", "BB": "Gi1/0/2", **{f"C{i}": "Gi1/0/24" for i in range(10)}}
        self.assertIn("this PC", S.port_risk("Gi1/0/1", macs, ["AA"]))
        self.assertIn("10 devices", S.port_risk("Gi1/0/24", macs))
        self.assertEqual(S.port_risk("Gi1/0/2", macs, ["AA"]), "")


if __name__ == "__main__":
    unittest.main()
