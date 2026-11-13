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


if __name__ == "__main__":
    unittest.main()
