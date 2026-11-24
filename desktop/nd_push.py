"""Background push to the phone via ntfy.sh - so an approval buzzes the phone even when the app is closed.

How it works (no Firebase, no account): the PC and phone share ONE secret topic name (random, stored in
settings on first use and shown to the user to enter on the phone). The PC POSTs a notification to
https://ntfy.sh/<topic>; the phone's ntfy subscription (the ntfy app, or the in-app subscriber) receives it
in the background. Tapping it opens Network Doctor's approval screen (the Approve/Reject still goes through the
PC's /api, which we already have). Rakesh, 24 Nov: "full background push needed."

This module is pure/testable: build_payload() makes the request parts; send() does the actual POST (injectable
opener for tests). A topic is a shared secret - anyone who knows it can send/read, so it is long and random.
"""

import json
import secrets
import urllib.request

NTFY_BASE = "https://ntfy.sh"
TOPIC_PREFIX = "nd-"          # Network Doctor topics


def new_topic():
    """A fresh random, hard-to-guess topic name (the shared secret). ~80 bits of entropy."""
    return TOPIC_PREFIX + secrets.token_urlsafe(12).replace("_", "").replace("-", "").lower()[:16]


def topic_url(topic, base=NTFY_BASE):
    return base.rstrip("/") + "/" + topic.strip().lstrip("/")


def build_payload(topic, title, message, *, priority="high", tag="warning", click=None, base=NTFY_BASE):
    """The (url, data_bytes, headers) for one push. priority high => the phone makes a sound/vibrate. `click`
    is a URL/deep-link opened when the notification is tapped."""
    headers = {
        "Title": _ascii(title)[:120],
        "Priority": priority,
        "Tags": tag,
    }
    if click:
        headers["Click"] = click
    return topic_url(topic, base), _ascii(message)[:1500].encode("utf-8"), headers


def _ascii(s):
    # ntfy headers must be latin-1 safe; keep the body/title plain so a stray unicode char can't drop the push.
    return (s or "").encode("ascii", "replace").decode("ascii")


def send(topic, title, message, *, priority="high", tag="warning", click=None, base=NTFY_BASE,
         timeout=8, opener=None):
    """POST one notification. Returns True on success. Never raises - push is best-effort, a failure must not
    break the app. `opener` (for tests) is a urlopen-like callable."""
    if not topic:
        return False
    url, data, headers = build_payload(topic, title, message, priority=priority, tag=tag, click=click, base=base)
    req = urllib.request.Request(url, data=data, method="POST",
                                 headers={"User-Agent": "NetworkDoctor", **headers})
    send_fn = opener or urllib.request.urlopen
    try:
        r = send_fn(req, timeout=timeout)
        code = getattr(r, "status", None) or getattr(r, "code", 200)
        try:
            r.close()
        except Exception:  # noqa: BLE001
            pass
        return 200 <= int(code) < 300
    except Exception:  # noqa: BLE001 - network error, proxy, offline: just report failure
        return False


def approval_push(topic, count, first_title, *, base=NTFY_BASE, click=None, opener=None):
    """Convenience: one push summarising pending approvals. count = how many are waiting."""
    if not topic or count <= 0:
        return False
    if count == 1:
        title = "Network Doctor: a fix needs your approval"
        msg = first_title or "Open the app to Approve or Reject."
    else:
        title = "Network Doctor: %d fixes need your approval" % count
        msg = "%s (+%d more). Open the app to review." % (first_title or "", count - 1)
    return send(topic, title, msg, priority="high", tag="warning", click=click, base=base, opener=opener)
