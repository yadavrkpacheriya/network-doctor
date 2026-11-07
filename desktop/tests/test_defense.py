import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import nd_defense as DF


class Exemptions(unittest.TestCase):
    def test_gateway_and_own_pc_never_auto_acted(self):
        p = DF.Defense({}, gw_ip="192.168.0.1", own_ip="192.168.0.70")
        self.assertTrue(p.excluded("192.168.0.1", ""))    # the router
        self.assertTrue(p.excluded("192.168.0.70", ""))   # the Network Doctor PC itself
        self.assertFalse(p.excluded("192.168.0.99", ""))  # an ordinary device can still be acted on

    def test_backbone_only_alerted(self):
        p = DF.Defense({})
        self.assertTrue(p.guard("malware", "Network equipment (router / switch / AP)"))  # never cut a switch/AP
        self.assertTrue(p.guard("malware", "Phones / tablets"))                           # phones change IP
        self.assertFalse(p.guard("malware", "Computers / laptops"))                       # a PC may be contained


if __name__ == "__main__":
    unittest.main()
