"""3.19: bandwidth plan, fixed-IP plan, CCTV isolation, NVR sizing and the camera chart (nd_bandwidth)."""
import os
import re
import sys
import time
import unittest
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import nd_bandwidth as B  # noqa: E402
import nd_core as core  # noqa: E402


def dev(ip, cat, name="", mac=None, **kw):
    d = {"ip": ip, "mac": mac or "AA:BB:CC:00:00:%02X" % int(ip.split(".")[-1]), "category": cat, "online": True,
         "name": name}
    d.update(kw)
    return d


NET = [
    dev("192.168.0.20", core.CAT_CAM, "Dahua DVR", ports=[37777]),
    dev("192.168.0.21", core.CAT_CAM, "NVR office"),
    dev("192.168.0.105", core.CAT_CAM, "Hikvision Camera .105"),
    dev("192.168.0.106", core.CAT_CAM, "Hikvision Camera .106"),
    dev("192.168.0.38", core.CAT_PC, "MUKESH-DESIGN"),
    dev("192.168.0.9", core.CAT_PC, "HR"),
    dev("192.168.0.101", core.CAT_PHONE, "Phone .101"),
    dev("192.168.0.50", core.CAT_PRN, "Printer"),
    dev("192.168.0.1", core.CAT_ROUTER, "Router"),
]


def lint(text):
    """Every line is a comment, a path, a RouterOS command or a :-statement; quotes and braces are balanced."""
    for n, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.startswith("#"):
            continue
        assert line[0] in "/:a", f"line {n} starts oddly: {line[:60]}"
        assert line.count('"') % 2 == 0, f"line {n}: odd number of quotes: {line}"
        assert line.count("{") == line.count("}"), f"line {n}: braces: {line}"
        assert line.count("[") == line.count("]"), f"line {n}: brackets: {line}"


class Groups(unittest.TestCase):
    def test_recorders_and_cameras(self):
        g = {d["ip"]: B.group_of(d) for d in NET}
        self.assertEqual(g["192.168.0.20"], "nvr")
        self.assertEqual(g["192.168.0.21"], "nvr")
        self.assertEqual(g["192.168.0.105"], "cam")
        self.assertEqual(g["192.168.0.38"], "pc")
        self.assertEqual(g["192.168.0.101"], "mobile")
        self.assertEqual(g["192.168.0.50"], "other")
        self.assertEqual(g["192.168.0.1"], "infra")

    def test_override_wins_and_boost_expires(self):
        d = NET[4]
        self.assertEqual(B.group_of(d, over={d["mac"]: "vip"}), "vip")
        self.assertEqual(B.group_of(NET[2], over={NET[2]["mac"]: "nvr"}), "nvr")
        now = 1000.0
        over = B.effective_over({}, {d["mac"]: {"until": now + 60}, "x": {"until": now - 1}, "y": {"until": None}}, now)
        self.assertEqual(over.get(d["mac"]), "vip")
        self.assertNotIn("x", over)
        self.assertEqual(over["y"], "vip")  # "until I stop" has no end time

    def test_groups_ips_skip_gateway_and_offline(self):
        off = dict(NET[5], online=False)
        out = B.groups_ips([NET[0], NET[4], off, NET[8]], {}, {}, gw_ip="192.168.0.1")
        self.assertEqual(out["nvr"], ["192.168.0.20"])
        self.assertEqual(out["pc"], ["192.168.0.38"])
        self.assertEqual(out["infra"], [])


class Plan(unittest.TestCase):
    def test_defaults_match_the_office_plan(self):
        p = B.compute_pools({})
        self.assertEqual((p["usable"], p["nvr"], p["mobile"], p["vip"], p["pc"]), (95.0, 10.0, 20.0, 5.0, 60.0))
        self.assertEqual(p["errors"], [])

    def test_everybody_busy_share(self):
        p = B.compute_pools({}, {"pc": 25})
        self.assertEqual(p["pc_busy"], 2.4)

    def test_upload_smaller_than_download(self):
        p = B.compute_pools({"down": 100, "up": 50})
        self.assertEqual(p["line"], 50.0)
        self.assertTrue(p["warnings"])
        self.assertEqual((p["usable"], p["pc"], p["errors"]), (47.5, 12.5, []))
        self.assertTrue(B.compute_pools({"down": 100, "up": 30})["errors"])  # 28.5 usable < 10 + 20 + 5

    def test_too_much_reserved(self):
        p = B.compute_pools({"nvr": 60, "mobile": 30})
        self.assertTrue(p["errors"])
        with self.assertRaises(ValueError):
            B.queue_commands({"nvr": 60, "mobile": 30}, {}, "192.168.0.0/24", "ether1")

    def test_rate_text(self):
        self.assertEqual(B.rate(5), "5M")
        self.assertEqual(B.rate(2.5), "2500k")


class Queues(unittest.TestCase):
    groups = {"nvr": ["192.168.0.20", "192.168.0.21"], "vip": ["192.168.0.38"], "mobile": ["192.168.0.101"]}

    def build(self, plan=None, groups=None):
        return B.queue_commands(plan or {}, self.groups if groups is None else groups, "192.168.0.0/24", "ether1")

    def test_script_is_well_formed(self):
        a, u = self.build()
        lint(a)
        lint(u)

    def test_order_and_targets(self):
        a, _ = self.build()
        names = re.findall(r"^add name=(ND-[A-Z]+) ", a, re.M)
        self.assertEqual(names, ["ND-TOTAL", "ND-NVR", "ND-VIP", "ND-MOBILE", "ND-PC"])  # first match wins
        self.assertIn("target=192.168.0.20/32,192.168.0.21/32", a)
        self.assertIn("ND-PC target=192.168.0.0/24", a)
        self.assertNotIn("dst=", a)  # no dependency on the internet port name

    def test_guarantees_fit_in_the_line(self):
        a, _ = self.build()
        at = [float(x[:-1]) for x in re.findall(r"limit-at=(\d+M)/", a)]
        self.assertEqual(at, [10.0, 5.0, 20.0, 60.0])
        self.assertLessEqual(sum(at), 95.0)

    def test_per_user_caps(self):
        a, _ = self.build()
        self.assertIn("name=ND-pc-up kind=pcq pcq-classifier=src-address pcq-rate=5M", a)
        self.assertIn("name=ND-pc-dn kind=pcq pcq-classifier=dst-address pcq-rate=5M", a)
        self.assertIn("name=ND-mobile-up kind=pcq pcq-classifier=src-address pcq-rate=4M", a)
        self.assertIn("name=ND-vip-up kind=pcq pcq-classifier=src-address pcq-rate=20M", a)

    def test_empty_groups_give_their_share_to_pcs(self):
        a, _ = self.build(groups={"nvr": ["192.168.0.20"]})
        self.assertNotIn("ND-VIP", a.replace("ND-vip", ""))
        self.assertNotIn("name=ND-MOBILE", a)
        self.assertIn("ND-PC", a)
        at = [float(x[:-1]) for x in re.findall(r"limit-at=(\d+M)/", a)]
        self.assertEqual(at, [10.0, 85.0])

    def test_borrow_off_keeps_hard_pools(self):
        a, _ = self.build({"borrow": False})
        self.assertIn("name=ND-NVR target=192.168.0.20/32,192.168.0.21/32 parent=ND-TOTAL priority=1/1 "
                      "limit-at=10M/10M max-limit=10M/10M", a)

    def test_fasttrack_off_and_undo(self):
        a, u = self.build()
        self.assertIn("fasttrack-connection", a)
        self.assertIn('ND-off: ', a)
        self.assertIn('comment~"^ND-off: "', u)
        self.assertIn('[:pick $c 8 [:len $c]]', u)  # len("ND-off: ") == 8
        self.assertEqual(len("ND-off: "), 8)
        self.assertIn('remove [find where name~"^ND-"]', u)

    def test_fasttrack_is_the_last_step(self):
        a, _ = self.build()
        self.assertGreater(a.index("fasttrack-connection"), a.index("add name=ND-PC "))

    def test_works_without_wan(self):
        a, _ = B.queue_commands({}, self.groups, "192.168.0.0/24")
        lint(a)


class Cameras(unittest.TestCase):
    def test_isolation_rules(self):
        a, u = B.camera_block_commands(["192.168.0.106", "192.168.0.105"], ["192.168.0.20"], "ether1")
        lint(a)
        lint(u)
        self.assertIn("src-address-list=ND-CAM out-interface=ether1", a)
        self.assertIn("in-interface=ether1 dst-address-list=ND-CCTV connection-state=new", a)
        self.assertIn("add list=ND-CAM address=192.168.0.105", a)
        self.assertNotIn("list=ND-CAM address=192.168.0.20", a)  # the NVR keeps its outbound cloud connection
        self.assertIn("list=ND-CCTV address=192.168.0.20", a)
        self.assertIn("to-addresses=192.168.0.20", a)
        self.assertIn("place-before=0", a)
        self.assertIn('comment~"^ND: camera"', u)
        self.assertIn('/ip firewall nat', u)

    def test_cam_ips_sorted_and_unique(self):
        a, _ = B.camera_block_commands(["192.168.0.106", "192.168.0.9", "192.168.0.9"], [], "pppoe-out1")
        ips = re.findall(r"list=ND-CAM address=(\S+)", a)
        self.assertEqual(ips, ["192.168.0.9", "192.168.0.106"])
        self.assertIn("pppoe-out1", a)

    def test_needs_wan(self):
        with self.assertRaises(ValueError):
            B.camera_block_commands(["192.168.0.5"], [], " ".strip())


class FixedIPs(unittest.TestCase):
    ranges = B.default_ranges("192.168.0.0/24")

    def test_default_blocks(self):
        self.assertEqual(self.ranges["nvr"], ("192.168.0.20", "192.168.0.29"))
        self.assertEqual(self.ranges["mobile"], ("192.168.0.200", "192.168.0.250"))
        self.assertEqual(B.default_ranges("10.0.0.0/28"), {})

    def test_keep_everything_by_default(self):
        rows = B.ip_plan(NET, "192.168.0.1", self.ranges, set())
        self.assertTrue(all(r["action"] == "keep" and r["ip_new"] == r["ip_now"] for r in rows))
        self.assertEqual(len(rows), len(NET) - 1)  # not the router

    def test_move_phone_into_its_block(self):
        rows = B.ip_plan(NET, "192.168.0.1", self.ranges, {"mobile"}, net="192.168.0.0/24")
        r = next(x for x in rows if x["dev"]["ip"] == "192.168.0.101")
        self.assertEqual((r["action"], r["ip_new"]), ("move", "192.168.0.200"))
        self.assertEqual(B.extra_ips(rows), {r["dev"]["mac"]: ["192.168.0.101"]})
        res = B.reservation_rows(rows)
        self.assertIn("192.168.0.200", [x["ip"] for x in res])

    def test_two_moves_get_different_ips(self):
        devs = [dev("192.168.0.7", core.CAT_PHONE), dev("192.168.0.8", core.CAT_PHONE)]
        rows = B.ip_plan(devs, "192.168.0.1", self.ranges, {"mobile"}, net="192.168.0.0/24")
        self.assertEqual([r["ip_new"] for r in rows], ["192.168.0.200", "192.168.0.201"])

    def test_skips(self):
        devs = [dev("192.168.0.7", core.CAT_PC, random=True), dev("192.168.0.8", core.CAT_PC, conflict=True),
                dev("192.168.0.9", core.CAT_PC, mac="AA:00:00:00:00:09"),
                dev("192.168.0.9", core.CAT_PC, mac="AA:00:00:00:00:10"), dev("192.168.0.11", core.CAT_PC)]
        rows = B.ip_plan(devs, "192.168.0.1", self.ranges, set())
        self.assertEqual([r["action"] for r in rows], ["skip", "skip", "skip", "skip", "keep"])
        self.assertEqual(len(B.reservation_rows(rows)), 1)

    def test_hand_typed_ip_is_marked_manual(self):
        rows = B.ip_plan([NET[0]], "192.168.0.1", self.ranges, {"nvr"}, ip_type_of=lambda d: "Likely static",
                         net="192.168.0.0/24")
        self.assertTrue(rows[0]["manual"])
        self.assertEqual(rows[0]["action"], "keep")  # .20 is already inside the NVR block

    def test_reservation_commands_and_csv(self):
        rows = B.ip_plan(NET, "192.168.0.1", self.ranges, set())
        a, u = B.reservation_commands(rows, {})
        lint(a)
        self.assertIn('mac-address="AA:BB:CC:00:00:14"', a)
        self.assertIn("/ip dhcp-server lease", u)
        csv_text = B.ip_list_csv(rows)
        self.assertIn("Dahua DVR", csv_text)
        self.assertEqual(csv_text.count("\n"), len(rows) + 1)


class Wan(unittest.TestCase):
    def test_detect(self):
        self.assertEqual(B.detect_wan([{"gateway": "203.0.113.1", "immediate-gw": "203.0.113.1%ether1"}]), "ether1")
        self.assertEqual(B.detect_wan([{"gateway": "pppoe-out1", "immediate-gw": "pppoe-out1"}]), "pppoe-out1")
        self.assertEqual(B.detect_wan([{"gateway": "203.0.113.1", "gateway-status": "203.0.113.1 reachable via  ether2"}]),
                         "ether2")
        self.assertEqual(B.detect_wan([{"gateway": "1.1.1.1", "disabled": "true", "immediate-gw": "x%ether9"}]), "")
        self.assertEqual(B.detect_wan([]), "")


class Sizing(unittest.TestCase):
    def test_fifty_cameras_two_nvr(self):
        s = B.nvr_sizing(50, 2)
        self.assertEqual(s["per_cam_sub"], 0.6)
        self.assertEqual(s["all_sub"], 30.0)
        self.assertEqual(s["cams_in_10"], 13)
        self.assertEqual(s["cams_in_20"], 26)
        self.assertEqual(s["recording"], 150.0)
        self.assertEqual(s["live_need"], 16.2)
        self.assertEqual(s["reserve_live"], 25)  # 16.2 / 0.8 = 20.25 -> next 5
        self.assertEqual(s["reserve"], 35)  # (16.2 + 9.6 for one clip download) / 0.8 = 32.25 -> next 5
        self.assertEqual(s["per_nvr"], 17.5)

    def test_download_time(self):
        # one hour of a 4 Mbps camera = 1.8 GB; at 10 Mbps (8 usable) about 30 minutes
        self.assertEqual(B.download_minutes(4, 60, 10), 30.0)
        self.assertEqual(B.download_minutes(4, 10, 10), 5.0)


class Chart(unittest.TestCase):
    def test_svg_is_valid_and_shows_the_block(self):
        spec = B.diagram_spec(34, 2, 17, 9)
        svg = B.diagram_svg(spec)
        root = ET.fromstring(svg)
        self.assertTrue(root.tag.endswith("svg"))
        self.assertIn("NO INTERNET", svg)
        self.assertIn("34 CCTV cameras", svg)
        self.assertIn("NVR / DVR (2)", svg)
        self.assertIn("stroke-dasharray", svg)  # the blocked arrow
        self.assertEqual(sum(1 for e in spec["edges"] if e[3] == "blocked"), 1)

    def test_edges_point_at_real_nodes(self):
        spec = B.diagram_spec()
        ids = {n[0] for n in spec["nodes"]}
        for a, b, _, _ in spec["edges"]:
            self.assertIn(a, ids)
            self.assertIn(b, ids)
        self.assertEqual(len(B.diagram_lines(spec)), len(spec["edges"]))

    def test_text_is_escaped(self):
        spec = B.diagram_spec()
        spec["nodes"][0] = ("phone", "A & B <x>", ["1 < 2"], 30, 20, 250, 70, "app")
        ET.fromstring(B.diagram_svg(spec))


if __name__ == "__main__":
    unittest.main()
