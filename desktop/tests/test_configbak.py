"""Tests for nd_configbak.py - router config backup/diff, the config-versioning feature the earlier
gap analysis flagged as missing (no way to see what changed on the router's own settings over time)."""
import unittest

import nd_configbak as CB


class AddSnapshot(unittest.TestCase):
    def test_first_snapshot_is_added(self):
        hist = []
        e = CB.add_snapshot(hist, "a=1\nb=2\n", now=100)
        self.assertIsNotNone(e)
        self.assertEqual(len(hist), 1)
        self.assertEqual(hist[0]["at"], 100)

    def test_identical_snapshot_is_skipped(self):
        hist = []
        CB.add_snapshot(hist, "a=1\n", now=100)
        e = CB.add_snapshot(hist, "a=1\n", now=200)
        self.assertIsNone(e)
        self.assertEqual(len(hist), 1)

    def test_changed_snapshot_is_added(self):
        hist = []
        CB.add_snapshot(hist, "a=1\n", now=100)
        e = CB.add_snapshot(hist, "a=2\n", now=200)
        self.assertIsNotNone(e)
        self.assertEqual(len(hist), 2)

    def test_empty_text_is_never_saved(self):
        hist = []
        self.assertIsNone(CB.add_snapshot(hist, ""))
        self.assertIsNone(CB.add_snapshot(hist, None))
        self.assertEqual(hist, [])

    def test_history_is_capped(self):
        hist = []
        for i in range(CB.MAX_SNAPSHOTS + 10):
            CB.add_snapshot(hist, f"line={i}\n", now=i)
        self.assertEqual(len(hist), CB.MAX_SNAPSHOTS)
        self.assertEqual(hist[-1]["text"], f"line={CB.MAX_SNAPSHOTS + 9}\n")


class LatestPrevious(unittest.TestCase):
    def test_empty_history(self):
        self.assertIsNone(CB.latest([]))
        self.assertIsNone(CB.previous([]))

    def test_one_entry(self):
        hist = [{"text": "a"}]
        self.assertEqual(CB.latest(hist)["text"], "a")
        self.assertIsNone(CB.previous(hist))

    def test_two_entries(self):
        hist = [{"text": "a"}, {"text": "b"}]
        self.assertEqual(CB.latest(hist)["text"], "b")
        self.assertEqual(CB.previous(hist)["text"], "a")


class DiffAndSummary(unittest.TestCase):
    def test_no_diff_when_identical(self):
        self.assertEqual(CB.diff_snapshots("a\nb\n", "a\nb\n"), [])
        self.assertEqual(CB.summarize_diff([]), "No changes since the previous backup.")

    def test_added_and_removed_lines_counted(self):
        old = "a\nb\nc\n"
        new = "a\nc\nd\n"
        diff = CB.diff_snapshots(old, new)
        self.assertTrue(any(ln.startswith("+d") for ln in diff))
        self.assertTrue(any(ln.startswith("-b") for ln in diff))
        summary = CB.summarize_diff(diff)
        self.assertIn("added", summary)
        self.assertIn("removed", summary)

    def test_a_port_forward_addition_shows_up(self):
        """The real-world case this feature exists for: someone hand-adds a firewall/NAT rule in Winbox
        with nothing else recording it."""
        old = "/ip firewall nat\n"
        new = ("/ip firewall nat\n"
               "add chain=dstnat action=dst-nat to-addresses=192.168.0.50 to-ports=80 protocol=tcp dst-port=8080\n")
        diff = CB.diff_snapshots(old, new)
        self.assertTrue(any("dst-nat" in ln and ln.startswith("+") for ln in diff))



class FakeRouter:
    def __init__(self, data, missing=()):
        self.data, self.missing = data, set(missing)

    def cmd(self, path):
        if path in self.missing:
            raise RuntimeError("no such command")
        return [dict(r) for r in self.data.get(path, [])]


NAT = "/ip/firewall/nat/print"


class SnapshotViaApi(unittest.TestCase):
    def base(self):
        return {NAT: [{".id": "*1", "chain": "srcnat", "action": "masquerade", "bytes": "10", "packets": "2"}],
                "/ppp/secret/print": [{"name": "isp", "password": "TOPSECRET", "service": "pppoe"}],
                "/ip/dhcp-server/lease/print": [
                    {"address": "192.168.0.50", "mac-address": "AA:BB:CC:00:00:01", "dynamic": "false",
                     "last-seen": "5s", "status": "bound"},
                    {"address": "192.168.0.99", "mac-address": "AA:BB:CC:00:00:02", "dynamic": "true"}]}

    def test_counters_changing_is_not_a_config_change(self):
        a = self.base()
        b = self.base()
        b[NAT][0].update(bytes="999999", packets="777")
        b["/ip/dhcp-server/lease/print"][0].update({"last-seen": "1m", "status": "waiting"})
        self.assertEqual(CB.snapshot_via_api(FakeRouter(a)), CB.snapshot_via_api(FakeRouter(b)))

    def test_passwords_are_never_stored(self):
        text = CB.snapshot_via_api(FakeRouter(self.base()))
        self.assertNotIn("TOPSECRET", text)
        self.assertIn("name=isp", text)

    def test_dynamic_rows_and_the_apps_own_rules_are_left_out(self):
        d = self.base()
        d[NAT].append({"chain": "dstnat", "action": "dst-nat", "comment": "ND: MSS clamp"})
        text = CB.snapshot_via_api(FakeRouter(d))
        self.assertNotIn("192.168.0.99", text)
        self.assertNotIn("MSS clamp", text)
        self.assertIn("192.168.0.50", text)

    def test_a_hand_made_port_forward_is_a_change(self):
        a = self.base()
        b = self.base()
        b[NAT].append({".id": "*2", "chain": "dstnat", "action": "dst-nat", "to-addresses": "192.168.0.50",
                       "dst-port": "8080", "comment": "cctv remote"})
        diff = CB.diff_snapshots(CB.snapshot_via_api(FakeRouter(a)), CB.snapshot_via_api(FakeRouter(b)))
        self.assertTrue(any(ln.startswith("+") and "dst-nat" in ln for ln in diff))

    def test_a_missing_section_is_skipped_and_nothing_readable_gives_empty(self):
        text = CB.snapshot_via_api(FakeRouter(self.base(), missing={"/ip/upnp/print"}))
        self.assertNotIn("/ip upnp", text)
        self.assertIn("/ip firewall nat", text)
        self.assertEqual(CB.snapshot_via_api(FakeRouter({}, missing={p for _, p in CB.SECTIONS})), "")


class RunBackup(unittest.TestCase):
    def test_first_then_same_then_changed_and_history_survives_on_disk(self):
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "config_backups.json")
            data = {NAT: [{"chain": "srcnat", "action": "masquerade"}]}
            r1 = CB.run_backup(FakeRouter(data), path)
            self.assertTrue(r1["ok"] and r1["first"] and not r1["changed"])
            r2 = CB.run_backup(FakeRouter(data), path)
            self.assertTrue(r2["ok"] and not r2["changed"] and not r2["first"])
            self.assertEqual(r2["count"], 1)
            data[NAT].append({"chain": "dstnat", "action": "dst-nat", "dst-port": "8080"})
            r3 = CB.run_backup(FakeRouter(data), path)
            self.assertTrue(r3["changed"])
            self.assertEqual(r3["count"], 2)
            self.assertTrue(any(ln.startswith("+") for ln in r3["diff"]))
            self.assertEqual(len(CB.load(path)), 2)

    def test_unreadable_router_is_not_ok_and_saves_nothing(self):
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "config_backups.json")
            r = CB.run_backup(FakeRouter({}, missing={p for _, p in CB.SECTIONS}), path)
            self.assertFalse(r["ok"])
            self.assertFalse(os.path.exists(path))

    def test_old_export_format_entries_are_dropped_on_load(self):
        import json
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "config_backups.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump([{"at": 1, "text": "# nov/13/2026 by RouterOS\n"}], f)
            self.assertEqual(CB.load(path), [])


if __name__ == "__main__":
    unittest.main()
