"""Safe SNMP enable: random (non-public) community, LAN-only, read-only, reversible - all without a router."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import nd_snmpcfg as S  # noqa: E402


def test_community_is_random_not_public():
    a, b = S.random_community(), S.random_community()
    assert a != "public" and b != "public" and a != b and len(a) > 8


def test_set_words_are_readonly_and_lan_scoped():
    w = S.community_set_words("*1", "ndsecret", "192.168.0.0/24")
    assert "=read-access=yes" in w and "=write-access=no" in w and "=addresses=192.168.0.0/24" in w


class _Client:
    def __init__(self):
        self.talks = []
        self.snmp = [{"enabled": "false"}]
        self.comms = [{".id": "*1", "name": "public", "addresses": "0.0.0.0/0", "default": "true"}]

    def cmd(self, path, **kw):
        if path == "/snmp/print":
            return self.snmp
        if path == "/snmp/community/print":
            return self.comms
        return []

    def talk(self, words, check=True):
        self.talks.append(words)
        return []


def test_enable_is_private_lan_only_and_reversible():
    c = _Client()
    res = S.enable(c, "192.168.0.0/24")
    assert res["community"] != "public"
    # the community got renamed+scoped and SNMP enabled
    joined = [" ".join(w) for w in c.talks]
    assert any("community/set" in j and "addresses=192.168.0.0/24" in j and "public" not in j.split("name=")[1]
               for j in joined)
    assert any("/snmp/set" in j and "enabled=yes" in j for j in joined)
    # undo restores the old community name and turns SNMP back off
    undo = [" ".join(w) for w in res["undo"]]
    assert any("name=public" in j for j in undo) and any("enabled=no" in j for j in undo)


def test_status_reads_enabled_and_name():
    c = _Client()
    c.snmp = [{"enabled": "true"}]
    st = S.status(c)
    assert st["enabled"] is True and st["community"] == "public"
