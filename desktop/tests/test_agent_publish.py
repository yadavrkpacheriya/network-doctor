# -*- coding: utf-8 -*-
"""The PC agent auto-updates: Network Doctor publishes the embedded agent to the share, every PC pulls it.
Guards that nd_agent (what ND ships) never drifts from the real endpoint/ files, and that publish() works."""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import nd_agent  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ENDPOINT = os.path.join(ROOT, "endpoint")


class NoDrift(unittest.TestCase):
    def test_embedded_files_match_the_real_endpoint_files(self):
        """If this fails: you edited endpoint/ without regenerating. Run: python3 tools/gen_agent.py"""
        for name, embedded in nd_agent.FILES.items():
            with open(os.path.join(ENDPOINT, name), "r", encoding="utf-8", newline="") as f:
                self.assertEqual(f.read(), embedded, f"{name} drifted - run tools/gen_agent.py")

    def test_version_matches_the_ps1(self):
        with open(os.path.join(ENDPOINT, "networkdoctor-agent.ps1"), encoding="utf-8") as f:
            ps1 = f.read()
        self.assertIn('$AgentVersion = "%s"' % nd_agent.AGENT_VERSION, ps1)

    def test_agent_can_self_update_from_what_is_published(self):
        # the agent's Update-Self pulls these exact names from <share>/agent-dist/
        self.assertIn("networkdoctor-agent.ps1", nd_agent.FILES)
        self.assertIn("agent-dist", nd_agent.FILES["networkdoctor-agent.ps1"])
        self.assertIn("Update-Self", nd_agent.FILES["networkdoctor-agent.ps1"])


class Publish(unittest.TestCase):
    def test_publish_writes_version_and_files(self):
        with tempfile.TemporaryDirectory() as d:
            v = nd_agent.publish(d)
            self.assertEqual(v, nd_agent.AGENT_VERSION)
            dist = os.path.join(d, "agent-dist")
            self.assertTrue(os.path.exists(os.path.join(dist, "version.txt")))
            for name in nd_agent.FILES:
                self.assertTrue(os.path.exists(os.path.join(dist, name)), name)
            with open(os.path.join(dist, "version.txt")) as f:
                self.assertEqual(f.read().strip(), nd_agent.AGENT_VERSION)

    def test_publish_does_not_downgrade_a_newer_master(self):
        with tempfile.TemporaryDirectory() as d:
            dist = os.path.join(d, "agent-dist")
            os.makedirs(dist)
            with open(os.path.join(dist, "version.txt"), "w") as f:
                f.write("99.0.0")                       # a newer master already there
            v = nd_agent.publish(d)
            self.assertEqual(v, "99.0.0")               # left as-is, not overwritten
            self.assertFalse(os.path.exists(os.path.join(dist, "networkdoctor-agent.ps1")))

    def test_publish_is_safe_on_bad_input(self):
        self.assertIsNone(nd_agent.publish(""))
        self.assertIsNone(nd_agent.publish(None))


if __name__ == "__main__":
    unittest.main()
