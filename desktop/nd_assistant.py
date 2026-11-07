"""Fix Assistant - turns a problem the user types in plain words ("youtube is not blocked", "internet is
slow", "a camera is open to the internet") into one of Network Doctor's built-in, tested fixes, so it can be
applied and undone with one click.

It deliberately never invents raw router commands from free text: it only routes the request to a fix the app
already ships and has tested. plan() is pure logic (no UI, no network), so it is easy to unit-test; the UI in
nd_tabs.AssistantTab calls it and applies the result through the normal router_apply / troubleshoot paths.
"""
import re

import nd_alerts as AL
import nd_tools as T

# words that name a category of sites to block/allow
_GROUP_WORDS = {
    "social": ["social", "instagram", "insta", "facebook", "fb", "twitter", "snapchat", "reddit", "tiktok",
               "threads", "pinterest"],
    "chat": ["whatsapp", "telegram", "messenger", "wechat"],
    "video": ["video", "youtube", "netflix", "prime video", "hotstar", "streaming", "stream", "twitch"],
    "shopping": ["shopping", "amazon", "flipkart", "myntra", "ajio", "shop"],
}
_BLOCK = ("block", "ban", "stop", "restrict", "disable")
_UNBLOCK = ("unblock", "allow", "permit", "re-enable", "reenable")
_SLOW = ("slow", "lag", "laggy", "buffer", "buffering", "loading", "hang", "hangs", "freez", "speed",
         "mtu", "mss", "dns", "sheets", "pages not opening", "not loading")
_SCAN = ("scan", "check my network", "any problem", "any issue", "what is wrong", "whats wrong", "find problem",
         "health", "everything ok", "check network", "problems")
_EXPOSED = ("exposed", "open to the internet", "from the internet", "port forward", "hacker",
            "reachable from outside", "accessible from outside", "open from outside")

_DOMAIN_RE = re.compile(r"\b([a-z0-9][a-z0-9-]*\.(?:com|in|net|org|co|io|tv|me|app|gg))\b")
_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


def _domains_in(low):
    return _DOMAIN_RE.findall(low)


def plan(text, net="", lip="", gw=""):
    """Map a plain-language problem to an action plan.

    Returns a dict with:
      kind: 'sites' | 'slow' | 'scan' | 'recipe' | 'none'
      understood: bool
      title, detail: plain-language summary to show the user
      and, depending on kind:
        sites : router_script, undo_script, sites
        recipe: recipe_text (hand this to the troubleshoot engine)
    """
    t = (text or "").strip()
    low = t.lower()
    if not low:
        return {"kind": "none", "understood": False, "title": "", "detail": ""}

    unblocking = any(w in low for w in _UNBLOCK)
    # "unblock" contains "block"; don't let it count as a block word
    blocking = any(w in low.replace("unblock", "  ") for w in _BLOCK)

    # 1) Block / unblock a category or a named site for the whole Wi-Fi
    if blocking or unblocking:
        groups = [g for g, words in _GROUP_WORDS.items() if any(w in low for w in words)]
        extra = _domains_in(low)
        if groups or extra:
            sites = T.sites_for(groups, extra)
            if T.normalize_sites(sites):
                apply_s, undo_s = T.site_block_commands(sites)
                named = ", ".join(groups + extra) or "those sites"
                if unblocking and not blocking:
                    return {"kind": "sites", "understood": True,
                            "title": f"Unblock {named} for everyone on the Wi-Fi",
                            "detail": "Removes the router block so these open again for all devices.",
                            "router_script": undo_s, "undo_script": apply_s, "sites": T.normalize_sites(sites)}
                return {"kind": "sites", "understood": True,
                        "title": f"Block {named} for everyone on the Wi-Fi",
                        "detail": "Blocks these on the router for every device on the network. Undo anytime.",
                        "router_script": apply_s, "undo_script": undo_s, "sites": T.normalize_sites(sites)}

    # 2) A device open to the internet (camera / NVR / DVR). Needs the specific device, so if the user named an
    #    IP hand it to the troubleshoot engine; otherwise scan and let the real exposed-device alerts carry the fix.
    if any(w in low for w in _EXPOSED) or (("camera" in low or "nvr" in low or "dvr" in low) and "internet" in low):
        m = _IP_RE.search(low)
        if m:
            return {"kind": "recipe", "understood": True,
                    "title": f"{m.group(1)} can be opened from the internet",
                    "detail": "Closes the port-forward / UPnP for this device so it can't be reached from outside.",
                    "recipe_text": f"{m.group(1)} can be opened from the internet"}
        return {"kind": "scan", "understood": True,
                "title": "Find devices open to the internet",
                "detail": "Runs a scan and lists any device (camera, NVR, PC) reachable from the internet, each "
                          "with a one-click 'close internet access' fix."}

    # 3) Slow / speed / MTU / DNS - the Slow-website tool measures and fixes this
    if any(w in low for w in _SLOW):
        return {"kind": "slow", "understood": True,
                "title": "Find and fix what is slowing the network",
                "detail": "Runs the slow-website test (speed, MTU/MSS, DNS, router load) and applies the fix it "
                          "finds - for example an MSS clamp for pages that hang, or faster DNS."}

    # 3) Generic 'check my network for problems'
    if any(w in low for w in _SCAN):
        return {"kind": "scan", "understood": True,
                "title": "Scan the network and list problems",
                "detail": "Runs a full scan and shows every issue found, each with a one-click fix."}

    # 4) Anything else - let the troubleshoot engine read the sentence (torrents, exposure, conflicts, loops...)
    r = AL.recipe(t, "warning", lip, gw, net)
    if r.get("kind") != "other":
        return {"kind": "recipe", "understood": True, "title": r["title"], "detail": r["why"], "recipe_text": t}

    return {"kind": "none", "understood": False,
            "title": "I could not match that to a built-in fix",
            "detail": "Try naming the problem, e.g. 'block youtube', 'internet is slow', "
                      "'a camera is open to the internet', or run a full scan.",
            "recipe_text": t}


# A few ready-made examples the UI can show as tappable chips.
EXAMPLES = [
    "Block YouTube and Instagram on the Wi-Fi",
    "Internet is slow and pages hang",
    "A camera is open to the internet",
    "Check my network for problems",
    "Block social media for everyone",
]
