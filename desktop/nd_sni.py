# -*- coding: utf-8 -*-
"""Read the REAL site name a device is connecting to, from the TLS ClientHello - no guessing from the IP owner,
and no decryption.

When any PC opens an HTTPS site, the very first packet it sends (the TLS ClientHello) carries the site's domain
in PLAIN TEXT, in the SNI (Server Name Indication) field - e.g. "instagram.com", "acronis.com", "tally.erp" -
before encryption starts. Reading SNI gives the true site for every connection, even when the DNS answer was
cached (so no fresh DNS query is logged) or the router's DNS logging dropped. We never see inside the encrypted
data (that would need breaking the encryption, which we do not do) - only the name the connection itself declares.

This module is a pure byte parser: give it the TCP payload of a packet to :443 and it returns the SNI host or "".
It is deliberately strict (returns "" on anything that isn't a clean ClientHello) so it never invents a name."""


def _host_ok(h):
    # a real hostname: has a dot, letters, no spaces/control chars, not an IP-looking all-numeric label set
    if not h or "." not in h or len(h) > 253:
        return False
    for ch in h:
        o = ord(ch)
        if ch in " \t\r\n" or o < 33 or o > 126:
            return False
    if all(c.isdigit() or c == "." for c in h):   # looks like an IP, not a name
        return False
    return True


def parse_sni(payload):
    """Return the SNI hostname from a TLS ClientHello byte string, or "" if this isn't one / has no SNI.
    Never raises. Bounds-checked at every step so a truncated or malformed packet just yields ""."""
    try:
        b = payload
        n = len(b)
        # TLS record: type(1)=0x16 handshake, version(2), length(2)
        if n < 5 or b[0] != 0x16:
            return ""
        # handshake header starts at 5: msg_type(1)=0x01 ClientHello, length(3)
        p = 5
        if p + 4 > n or b[p] != 0x01:
            return ""
        p += 4
        # client_version(2) + random(32)
        p += 2 + 32
        if p + 1 > n:
            return ""
        # session_id
        sid = b[p]
        p += 1 + sid
        # cipher_suites
        if p + 2 > n:
            return ""
        cs = (b[p] << 8) | b[p + 1]
        p += 2 + cs
        # compression_methods
        if p + 1 > n:
            return ""
        cm = b[p]
        p += 1 + cm
        # extensions
        if p + 2 > n:
            return ""
        ext_total = (b[p] << 8) | b[p + 1]
        p += 2
        end = min(n, p + ext_total)
        while p + 4 <= end:
            etype = (b[p] << 8) | b[p + 1]
            elen = (b[p + 2] << 8) | b[p + 3]
            p += 4
            if etype == 0x0000:  # server_name extension
                q = p
                if q + 2 > n:
                    return ""
                # server_name_list length(2)
                q += 2
                # name_type(1) must be 0 (host_name), then name length(2)
                if q + 3 > n or b[q] != 0x00:
                    return ""
                hlen = (b[q + 1] << 8) | b[q + 2]
                q += 3
                if q + hlen > n:
                    return ""
                host = b[q:q + hlen].decode("ascii", "ignore").strip().lower()
                return host if _host_ok(host) else ""
            p += elen
        return ""
    except Exception:  # noqa: BLE001 - a bad packet must never raise
        return ""
