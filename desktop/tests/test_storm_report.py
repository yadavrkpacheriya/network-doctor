"""nd_monitor.storm_report: this PC's own scan is not a storm; multicast is not a cable loop."""
import unittest

import nd_alerts as AL
import nd_monitor as M

ME, CAM, OTHER = "00:22:46:53:F7:89", "A0:00:00:01:7F:F0", "64:51:06:61:64:48"


class Report(unittest.TestCase):
    def test_this_pcs_own_burst_is_not_reported(self):
        kind, *_ = M.storm_report(375, True, [(ME, 394), (CAM, 7), (OTHER, 6)], 10, self_mac=ME.lower(), sniffing=True)
        self.assertIsNone(kind)

    def test_mostly_multicast_is_named_as_multicast_not_a_loop(self):
        kind, sev, text, data = M.storm_report(375, True, [(CAM, 70), (OTHER, 60)], 10, self_mac=ME, sniffing=True)
        self.assertEqual((kind, sev), ("mcast", "warning"))
        self.assertTrue(data["multicast"])
        r = AL.explain(text, sev)
        self.assertEqual(r["kind"], "multicast")            # advice: IGMP snooping, not "find the looped cable"
        self.assertIn(CAM, text)

    def test_real_broadcast_storm_is_still_a_storm_and_never_lists_this_pc(self):
        kind, sev, text, data = M.storm_report(1500, True, [(CAM, 9000), (ME, 300), (OTHER, 4000)], 10, ME, True)
        self.assertEqual((kind, sev), ("storm", "critical"))
        self.assertNotIn(ME, text)
        self.assertEqual(AL.explain(text, sev)["kind"], "loop")

    def test_without_the_packet_listener_it_stays_a_storm_warning(self):
        kind, sev, text, _ = M.storm_report(375, True, [], 10, ME, sniffing=False)
        self.assertEqual((kind, sev), ("storm", "warning"))


if __name__ == "__main__":
    unittest.main()
