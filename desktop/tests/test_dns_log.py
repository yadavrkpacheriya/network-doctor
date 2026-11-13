"""Router DNS log -> usage names: which device asked for which name (nd_usage.parse_dns_log / dns_log)."""
import os
import tempfile
import unittest

import nd_usage as US


class Parse(unittest.TestCase):
    def test_query_and_answer_lines(self):
        self.assertEqual(US.parse_dns_log("dns query from 192.168.0.50: #812 www.youtube.com. A"),
                         ("query", "812", "192.168.0.50", "www.youtube.com", ""))
        self.assertEqual(US.parse_dns_log("Nov 13 22:10:01 MikroTik dns done query: #812 www.youtube.com 142.250.4.93"),
                         ("answer", "812", "", "www.youtube.com", "142.250.4.93"))

    def test_other_router_lines_are_not_dns(self):
        for t in ("ether3 link down", "dhcp1 assigned 192.168.0.9 to AA:BB:CC:00:00:01", "login failure for user admin",
                  "query cache flushed"):
            self.assertIsNone(US.parse_dns_log(t))


class Store(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        self.s = US.UsageStore(os.path.join(self.d.name, "usage.db"))

    def tearDown(self):
        self.d.cleanup()

    def test_shared_address_is_named_after_what_this_device_asked_for(self):
        ip = "142.250.4.93"
        self.s.learn_names([(ip, "www.youtube.com"), (ip, "mail.google.com"), (ip, "mail.google.com")])
        self.assertTrue(self.s.name_for("192.168.0.50", ip)[1])          # shared: would be "service not named"
        self.assertTrue(self.s.dns_log("dns query from 192.168.0.50: #1 www.youtube.com. A", now=100))
        self.assertEqual(self.s.name_for("192.168.0.50", ip), ("www.youtube.com", False))
        self.assertEqual(self.s.name_for("192.168.0.51", ip)[0], "mail.google.com")   # another PC is not affected

    def test_answer_line_teaches_the_address_for_the_device_that_asked(self):
        self.s.dns_log("dns query from 192.168.0.60: #7 web.whatsapp.com. A", now=100)
        self.s.dns_log("dns done query: #7 web.whatsapp.com 157.240.1.60", now=100)
        self.assertEqual(self.s.name_for("192.168.0.60", "157.240.1.60"), ("web.whatsapp.com", False))
        self.assertEqual(self.s.dns_log_rx, 1)

    def test_non_dns_line_is_left_for_the_normal_handler(self):
        self.assertFalse(self.s.dns_log("ether3 link down"))


if __name__ == "__main__":
    unittest.main()
