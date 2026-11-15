"""force_dns_commands: redirect client DNS to the router + drop DoT, reversible - so blocks reach phones."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import nd_tools as T  # noqa: E402


def test_apply_redirects_53_and_drops_853():
    apply, undo = T.force_dns_commands()
    assert "dst-port=53 action=redirect" in apply and "protocol=udp" in apply and "protocol=tcp" in apply
    assert "dst-port=853 action=drop" in apply
    assert 'comment="ND dns-force' in apply


def test_undo_only_removes_our_rules():
    _, undo = T.force_dns_commands()
    assert "remove [find where comment~\"^ND dns-force\"]" in undo
    assert "add " not in undo   # undo adds nothing, only removes


def test_scope_applied_when_iface_list_given():
    apply, _ = T.force_dns_commands("LAN")
    assert "in-interface-list=LAN" in apply
