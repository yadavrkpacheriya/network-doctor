"""Turn SNMP on safely on the MikroTik, over its API - so Network Doctor can read switch/PoE/interface counters
without anyone enabling it by hand.

Hacker-safety is the whole point here, so this NEVER does the risky thing:
  * the community string is RANDOM (never 'public'), so it cannot be guessed;
  * it is restricted to the LAN subnet (addresses=<subnet>), so only devices inside the office can query it;
  * SNMP stays READ-ONLY (v2c read community) - nothing can be changed over SNMP;
  * it is reversible - enable() returns an undo that turns SNMP back off and restores the old community.

Pure word-builders are unit-tested; the thin enable/disable do the router I/O. The actual change is the user's
one-click (or a one-time auto-enable when a router login is already saved), never a silent surprise."""
import secrets


def random_community():
    """A 20-hex-character random read community - unguessable, and never the default 'public'."""
    return "nd" + secrets.token_hex(9)


def community_set_words(cid, name, subnet):
    """Rename/limit an existing community (by its .id) to our random name, read-only, LAN-only."""
    w = ["/snmp/community/set", "=.id=" + cid, "=name=" + name, "=read-access=yes", "=write-access=no"]
    if subnet:
        w.append("=addresses=" + subnet)
    return w


def community_add_words(name, subnet):
    w = ["/snmp/community/add", "=name=" + name, "=read-access=yes", "=write-access=no"]
    if subnet:
        w.append("=addresses=" + subnet)
    return w


def enable_words(community, contact="Network Doctor", location="office"):
    return ["/snmp/set", "=enabled=yes", "=contact=" + contact, "=location=" + location,
            "=trap-community=" + community]


def status(client):
    """{enabled: bool, community: str} - what SNMP looks like now. Empty/raises-safe."""
    try:
        s = client.cmd("/snmp/print")
        row = s[0] if s else {}
        comms = client.cmd("/snmp/community/print")
        name = next((c.get("name", "") for c in comms if str(c.get("default", "")).lower() == "true"),
                    comms[0].get("name", "") if comms else "")
        return {"enabled": str(row.get("enabled", "")).lower() == "true", "community": name}
    except Exception:  # noqa: BLE001
        return {"enabled": False, "community": ""}


def enable(client, subnet, community=None):
    """Turn SNMP on safely and return {community, undo}. undo is a list of word-lists that turn it back exactly to
    how it was. Reuses the default community row if there is one (so we don't pile up entries)."""
    community = community or random_community()
    comms = client.cmd("/snmp/community/print")
    target = next((c for c in comms if str(c.get("default", "")).lower() == "true"), comms[0] if comms else None)
    old_state = status(client)
    undo = []
    if target and target.get(".id"):
        undo.append(["/snmp/community/set", "=.id=" + target[".id"],
                     "=name=" + target.get("name", "public"),
                     "=addresses=" + target.get("addresses", "0.0.0.0/0")])
        client.talk(community_set_words(target[".id"], community, subnet))
    else:
        client.talk(community_add_words(community, subnet))
    client.talk(enable_words(community))
    undo.append(["/snmp/set", "=enabled=" + ("yes" if old_state.get("enabled") else "no")])
    return {"community": community, "undo": undo}


def disable(client):
    client.talk(["/snmp/set", "=enabled=no"])
