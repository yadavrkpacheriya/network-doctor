"""The learning brain behind Network Doctor's problem-naming and fixes.

It gets better from what it sees, with NO external ML library (nothing to install, stays tiny and fully
offline): a Naive-Bayes text model learns which words go with which kind of problem, and an ensemble - a small
"forest" of weak signals (the keyword rule, the learned text model, and the per-situation success history) -
votes on the final answer and a confidence. Deeper than a single success rate: it learns per context (the same
fix can be trusted for cameras but not for PCs, inside the network but not from the internet) and tracks how
often a problem keeps coming back, so a recurring issue is escalated to a permanent fix instead of patched again
and again.

State is a plain dict (JSON-safe), so it rides along in the app's settings and syncs to the phone like anything
else. Everything here is pure functions on that dict."""
import math
import re
import time

_TOKEN = re.compile(r"[a-z][a-z0-9]+")
# words that carry no signal about WHICH problem it is
_STOP = frozenset("the a an and or of to in on is are was for with that this it its from by be has have not now "
                  "you your at as if no but all can will one two more than then via over out up".split())


def tokens(text):
    """The meaningful words of an alert, lower-cased, stop-words and bare numbers dropped."""
    return [t for t in _TOKEN.findall((text or "").lower()) if len(t) > 2 and t not in _STOP]


def blank():
    """A fresh brain."""
    return {"v": 1, "nb": {}, "kinds": {}, "ctx": {}, "recur": {}}
    #  nb:    token -> {kind: count}         (Naive-Bayes word counts)
    #  kinds: kind  -> count                 (how often each kind has been seen)
    #  ctx:   "kind|cat|src" -> {ok, bad}    (per-situation success history)
    #  recur: signature -> [timestamps]      (how often a problem keeps coming back)


def _migrate(kb):
    """Accept an old or empty blob and return a valid brain (never raises on bad stored data)."""
    if not isinstance(kb, dict):
        return blank()
    for k, default in (("nb", {}), ("kinds", {}), ("ctx", {}), ("recur", {})):
        if not isinstance(kb.get(k), dict):
            kb[k] = default
    kb["v"] = 1
    return kb


def learn_text(kb, text, kind):
    """Teach the text model that this wording means this kind of problem."""
    if not kind:
        return
    kb["kinds"][kind] = kb["kinds"].get(kind, 0) + 1
    for t in set(tokens(text)):
        kb["nb"].setdefault(t, {})
        kb["nb"][t][kind] = kb["nb"][t].get(kind, 0) + 1


def nb_scores(kb, text):
    """Log-probability per kind for this text (higher = better fit). {} until the model has learned anything."""
    kinds = kb.get("kinds") or {}
    if not kinds:
        return {}
    total = sum(kinds.values())
    vocab = len(kb.get("nb") or {}) or 1
    toks = set(tokens(text))
    out = {}
    for k, kc in kinds.items():
        lp = math.log(kc / total)
        for t in toks:
            c = (kb["nb"].get(t) or {}).get(k, 0)
            lp += math.log((c + 1) / (kc + vocab))     # Laplace-smoothed
        out[k] = lp
    return out


def _ctx_key(kind, cat, src):
    return f"{kind}|{(cat or '-').lower()[:16]}|{'ext' if src == 'external' else 'int'}"


def ctx_conf(kb, kind, cat, src):
    """Success rate (0..1) this fix-kind has had in THIS situation before, or None when it is new here."""
    s = (kb.get("ctx") or {}).get(_ctx_key(kind, cat, src))
    if not s:
        return None
    n = s.get("ok", 0) + s.get("bad", 0)
    return s.get("ok", 0) / n if n else None


def learn_outcome(kb, text, kind, cat="", src="", ok=True):
    """Record how a fix turned out, and teach the text model the wording->kind link at the same time."""
    learn_text(kb, text, kind)
    s = kb.setdefault("ctx", {}).setdefault(_ctx_key(kind, cat, src), {"ok": 0, "bad": 0})
    s["ok" if ok else "bad"] += 1


def recurrence(kb, signature, now=None, window=7 * 86400, keep=30):
    """Note that a problem with this signature happened now; return how many times it has happened within the
    window. A rising count is how the brain knows a patch keeps failing and a permanent fix is needed."""
    now = now or time.time()
    lst = [t for t in (kb.setdefault("recur", {}).get(signature) or []) if now - t < window]
    lst.append(now)
    kb["recur"][signature] = lst[-keep:]
    return len(lst)


def recur_count(kb, signature, now=None, window=7 * 86400):
    """How many times `signature` has happened within the window - WITHOUT recording a new one. Counts only
    recent hits, so old timestamps never keep a long-solved problem looking 'recurring'."""
    now = now or time.time()
    return sum(1 for t in (kb.get("recur") or {}).get(signature, []) if now - t < window)


def decide(kb, text, recipe_kind=None, cat="", src="", sev="warning", now=None):
    """The forest vote. Combines the keyword rule (a strong prior), the learned text model, and the per-
    situation success history into one answer.

    Returns {"kind", "confidence" (0..1), "why" [human reasons], "recurring" (bool), "auto_ok" (bool)}.
    auto_ok is only true when confidence is high AND the kind is one that is safe to apply without asking."""
    kb = _migrate(kb)
    why = []
    votes = {}
    if recipe_kind:
        votes[recipe_kind] = votes.get(recipe_kind, 0) + 2.0        # the rule is trusted most
        why.append(f"rule recognised '{recipe_kind}'")
    nb = nb_scores(kb, text)
    nb_best = None
    if nb:
        nb_best = max(nb, key=nb.get)
        order = sorted(nb.values(), reverse=True)
        margin = (order[0] - order[1]) if len(order) > 1 else 2.0
        weight = 1.0 if margin > 1.0 else 0.4                       # weak when the model is unsure
        votes[nb_best] = votes.get(nb_best, 0) + weight
        if nb_best != recipe_kind:
            why.append(f"learned wording looks like '{nb_best}'")
    kind = max(votes, key=votes.get) if votes else (recipe_kind or nb_best)

    conf = 0.6 if kind == recipe_kind else 0.4
    if recipe_kind and nb_best == recipe_kind:
        conf += 0.15                                               # rule and learning agree -> surer
        why.append("rule and learning agree")
    ch = ctx_conf(kb, kind, cat, src)
    if ch is not None:
        conf = 0.4 * conf + 0.6 * ch
        why.append(f"worked {round(ch * 100)}% of the time in this situation before")
    if src == "external" or sev == "critical":
        conf *= 0.9                                                # a little more careful on the riskiest
    conf = max(0.0, min(1.0, conf))

    recurring = False
    if kind:
        n = recur_count(kb, f"{kind}|{cat}", now)
        recurring = n >= 3
        if recurring:
            why.append(f"this keeps coming back ({n}x) - a permanent fix is better than patching again")

    out = {"kind": kind, "confidence": round(conf, 3), "why": why, "recurring": recurring,
           "auto_ok": conf >= 0.8 and kind in AUTO_SAFE and src != "external"}
    rec = RECIPES.get(kind)
    if rec:
        out["recipe"] = dict(rec)           # the master brain's known fix for this kind, for the handler to run
    return out


def teach(kb, examples):
    """Teach the brain from reviewed examples: [(text, kind, ok)] - ok True means 'this wording IS this kind and
    the fix works', ok False means 'this fix did NOT work here'. This is how guidance shared back (from the daily
    report) makes the brain handle look-alike issues next time. Returns how many it learned."""
    n = 0
    for ex in examples or []:
        text, kind = ex[0], ex[1]
        ok = ex[2] if len(ex) > 2 else True
        if text and kind:
            learn_outcome(kb, text, kind, ok=ok)
            n += 1
    return n


_TEACH = re.compile(r"teach\s+kind\s*=\s*([a-z_][a-z0-9_]*)\s*:\s*(.+?)\s*$", re.I)


def parse_teach(text):
    """Pull 'TEACH kind=<kind>: <example words>' lines out of pasted guidance -> [(words, kind, True)].
    Anyone (or Claude, in a reply to the shared report) can write these; the brain then recognises look-alikes."""
    out = []
    for line in (text or "").splitlines():
        m = _TEACH.search(line)
        if m:
            out.append((m.group(2).strip(), m.group(1).lower(), True))
    return out


# the kinds safe to apply automatically at high confidence - never ones that block or expose a device, touch
# DNS, or face the internet (those always stay a reviewed, one-click action)
AUTO_SAFE = frozenset({"dhcp_conflict", "multicast", "loop", "ip_conflict", "mtu", "config_changed"})


# -- built-in networking curriculum ------------------------------------------------------------------------
# What the brain already knows before it sees anything on THIS network: the problem kinds it should recognise
# and how people (and Claude) tend to word them. Seeding this once gives the Naive-Bayes model a sensible prior,
# so a brand-new install already names "broadcast storm" or "camera tampering" correctly, then keeps learning
# the real wording of this office from there. Phrases are plain language on purpose - that is what alerts and
# pasted guidance look like. NOTE: several kinds here block, reboot, shape or quarantine a device; those are
# deliberately NOT in AUTO_SAFE above, so the brain names them but the action stays a reviewed one-click.
SEED_VERSION = 4   # bumped: added ip_conflict/dhcp_conflict/bogus_mac/random_mac curriculum + fix recipes
KNOWLEDGE = {
    # Access / joining the network
    "arp_block": ["devices cannot connect to wifi even though the password is right",
                  "unbound devices blocked after turning on mac binding",
                  "interface arp set to reply-only so only bound devices work",
                  "phones and new devices cannot get on the network after binding",
                  "some devices did not connect to wifi even after mac binding on"],
    "dhcp_full": ["dhcp pool is full no free address for new devices",
                  "new device gets no ip address, lease pool exhausted",
                  "too many static leases left no room in the pool",
                  "device stuck waiting for a dhcp address"],
    # Loop & switch health
    "broadcast_storm": ["broadcast storm flooding the network", "too many broadcast packets per second",
                        "network slow from a flood of broadcasts", "broadcast traffic spiking",
                        "broadcast spikes from an unmanaged switch loop", "mikrotik port packet rate suddenly high"],
    "mac_flapping": ["mac flapping between ports", "same mac address seen on two switch ports",
                     "mac address keeps moving ports", "duplicate mac bouncing",
                     "mac addresses rapidly switching between mikrotik ports from a loop behind an unmanaged switch"],
    "loop": ["network switching loop", "a port is looped back on itself", "loop between two switch ports",
             "cable plugged into two ports making a loop",
             "shut down or rate-limit the switch port the second a loop or storm begins"],
    "poe_overload": ["poe power budget exceeded on the switch", "too many cameras drawing poe power",
                     "switch running out of poe watts", "powered devices overloading the switch",
                     "power draw spike when all cameras switch to night-vision ir",
                     "forecast power spikes to prevent an unmanaged switch brownout"],
    # Internet & bandwidth
    "bandwidth_hog": ["one device using most of the internet", "a pc is hogging all the bandwidth",
                      "heavy download eating the whole line", "single ip saturating the internet",
                      "which pc phone or camera stream is saturating the isp link"],
    "qos": ["prioritise important traffic with qos", "shape bandwidth per device", "limit a heavy user's speed",
            "apply dynamic qos so nobody starves the line",
            "temporary mikrotik bandwidth queue to throttle heavy downloaders while protecting office pcs"],
    "app_traffic": ["classify which application is using the network", "identify app and website traffic",
                    "name the apps and sites behind the usage", "unknown traffic needs identifying",
                    "tell business traffic from mobile backups video streaming and torrents without manual ip lists"],
    # CCTV
    "camera_down": ["camera stream is dead no video", "cctv feed not live", "camera offline and not streaming",
                    "nvr shows the camera disconnected",
                    "camera feed frozen black or dropping frames even though it still answers ping"],
    "camera_tamper": ["camera tampering lens covered or moved", "cctv view blocked or spray-painted",
                      "someone turned the camera away", "camera image went black from tampering",
                      "camera lens covered blurred unplugged or physically shifted"],
    "camera_outage": ["several cameras went down together", "camera outage lines up with a switch or power loss",
                      "group of cameras offline at the same time", "whole cctv branch dropped at once",
                      "ten cameras died together because one shared unmanaged switch lost power"],
    "camera_reboot": ["reboot the frozen camera to recover it", "power cycle the cctv to bring the stream back",
                      "restart the hung camera", "bounce the camera that stopped responding",
                      "send an onvif reboot command or toggle a smart poe relay to restart a frozen camera"],
    # Employee tracking & data-leak
    "user_identity": ["map this ip to the employee using it", "which user is behind this device",
                      "identify the person on this pc", "put a name to the device on the network",
                      "link live ip and mac on the mikrotik dhcp lease table to employee names and devices"],
    "data_leak": ["large outbound upload leaving the network", "scan outbound data for a leak",
                  "possible data exfiltration out to the internet", "sensitive files being uploaded out",
                  "detect sensitive files source code or client lists leaving the office on mirrored traffic"],
    "after_hours_exfil": ["big data transfer after office hours", "upload at night when nobody is working",
                          "exfiltration outside working hours", "data leaving late at night",
                          "unusual bulk uploads or database downloads outside normal employee shift hours"],
    "quarantine": ["quarantine the device that is leaking data", "isolate the leaking pc from the network",
                   "cut off the machine that is exfiltrating", "block the offending device until checked",
                   "move a compromised or data-leaking pc or mobile into a restricted mikrotik vlan to stop it"],
    # Self-healing & reporting
    "root_cause": ["summarise the root cause of this problem", "explain why this keeps happening",
                   "give the real reason behind the issue", "root cause of the repeated fault",
                   "group dozens of raw alerts into one plain-english incident report"],
    "mikrotik_fix": ["recommend the mikrotik router fix for this", "which router config change fixes this",
                     "the routeros command that solves this", "fix this on the mikrotik",
                     "ready-to-run routeros cli commands to patch firewall gaps ip conflicts or routing bottlenecks"],
    # The small REGULAR issues the office hits again and again - the ones the fixer brain must name and (where
    # safe) solve on its own so nobody chases them by hand every day.
    "ip_conflict": ["two devices use the same ip", "ip conflict on the network", "duplicate ip address",
                    "same ip answered by two devices", "camera and pc fight over one ip every morning",
                    "ip address already in use by another device"],
    "dhcp_conflict": ["a device has a hand-typed static ip inside the router's dhcp range",
                      "static ip clashes with the dhcp pool", "manually set ip collides with dhcp",
                      "conflict by arp response for an ip the router also hands out"],
    "bogus_mac": ["cameras with a fake or cloned mac address", "duplicate non-real mac on cheap cctv",
                  "two devices show the same mac address", "cloned mac confuses the arp table",
                  "ip-mac binding knocks devices offline because of duplicated camera macs"],
    "random_mac": ["phone with a private randomized mac shows as a new device every time",
                   "randomized mac fills the lease table", "new unknown device every day from mac randomization",
                   "private wifi address keeps changing and loses the device history"],
}


# -- master brain: the fix recipe for each kind (what the "child" per-domain handlers run) -------------------
# The master brain knows not just WHAT a problem is but the proven way to end it. For the safe, regular issues
# this lets the app self-heal; the risky kinds (block / expose / reboot / quarantine / DNS) carry a recipe too
# but with auto=False, so they stay a reviewed one-click. `where` names the app action that applies it.
RECIPES = {
    "ip_conflict":   {"fix": "reserve the IP for whoever the router already leases it to (make-static); if the "
                             "other device is a camera we can log in to, switch it to automatic IP so it stops "
                             "claiming the address", "auto": True, "permanent": True, "where": "nd_ipfix.reserve"},
    "dhcp_conflict": {"fix": "make-static the hand-typed IP so the DHCP server reserves it and never hands it to "
                             "anyone else", "auto": True, "permanent": True, "where": "router.reserve"},
    "bogus_mac":     {"fix": "give every camera a unique fixed IP (reservation) so cloned MACs never share an "
                             "address; ideally move cameras onto their own switch", "auto": False,
                      "permanent": True, "where": "binding"},
    "random_mac":    {"fix": "block randomized/private MACs on the WiFi so phones present their real address, or "
                             "accept them as guests - a reviewed choice, not automatic", "auto": False,
                      "permanent": True, "where": "arpblock"},
    "loop":          {"fix": "rate-limit or shut the switch port the loop/storm is on", "auto": False,
                      "permanent": False, "where": "switchbw"},
    "dhcp_full":     {"fix": "reserve fixed gear (cameras/NVR/PCs/printers) OUT of the dynamic pool and set a "
                             "short 30m lease, so rotating phone MACs self-clear instead of filling the pool",
                      "auto": True, "permanent": True, "where": "router"},
    "camera_down":   {"fix": "restart the frozen camera (ONVIF reboot / PoE cycle) once it still answers ping",
                      "auto": False, "permanent": False, "where": "camline.reboot"},
}


def recipe(kind):
    """The master brain's known fix for a problem kind, or None. Child handlers call this to get the recipe to
    run (and whether it is safe to run without asking)."""
    r = RECIPES.get(kind)
    return dict(r) if r else None


def recurring_report(kb, now=None, window=7 * 86400, min_count=3):
    """Pattern-finder: the problem signatures that keep coming back within the window, worst first, each with
    the master brain's permanent recipe when there is one. This is what escalates a patched-again-and-again
    issue to a permanent fix. Returns [{signature, kind, count, recipe}]."""
    now = now or time.time()
    out = []
    for sig, stamps in (kb.get("recur") or {}).items():
        n = sum(1 for t in stamps if now - t < window)
        if n >= min_count:
            kind = sig.split("|", 1)[0]
            out.append({"signature": sig, "kind": kind, "count": n, "recipe": recipe(kind)})
    out.sort(key=lambda x: x["count"], reverse=True)
    return out


def seed(kb, force=False):
    """Load the built-in networking curriculum into the brain, once (idempotent, versioned). Returns how many
    phrases were taught (0 when it was already seeded at this version). Called from the app at start-up."""
    kb = _migrate(kb)
    if not force and kb.get("seeded") == SEED_VERSION:
        return 0
    n = 0
    for kind, phrases in KNOWLEDGE.items():
        for p in phrases:
            learn_text(kb, p, kind)
            n += 1
    kb["seeded"] = SEED_VERSION
    return n
