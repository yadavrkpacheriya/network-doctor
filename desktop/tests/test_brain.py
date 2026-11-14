"""The learning brain: text model, ensemble vote, per-context memory, recurrence - all dependency-free."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import nd_brain as B  # noqa: E402


def test_tokens_drop_stopwords_and_numbers():
    t = B.tokens("Router 192.168.0.1 keeps dropping for a few seconds")
    assert "router" in t and "dropping" in t and "seconds" in t
    assert "the" not in t and "192" not in t and "for" not in t


def test_text_model_learns_and_classifies():
    kb = B.blank()
    for _ in range(3):
        B.learn_text(kb, "broadcast storm flooding the network too many packets", "storm")
        B.learn_text(kb, "two devices answer for the same ip address conflict", "ip_conflict")
    s = B.nb_scores(kb, "a broadcast storm is flooding everything")
    assert max(s, key=s.get) == "storm"
    s2 = B.nb_scores(kb, "same ip address used by two devices")
    assert max(s2, key=s2.get) == "ip_conflict"


def test_per_context_success_is_separate():
    kb = B.blank()
    # the same kind works for cameras, fails for PCs
    for _ in range(4):
        B.learn_outcome(kb, "camera stopped answering", "device_down", cat="Cameras", ok=True)
    B.learn_outcome(kb, "pc stopped answering", "device_down", cat="Computers", ok=False)
    assert B.ctx_conf(kb, "device_down", "Cameras", "") == 1.0
    assert B.ctx_conf(kb, "device_down", "Computers", "") == 0.0
    assert B.ctx_conf(kb, "device_down", "Printers", "") is None      # new situation: unknown


def test_decide_blends_rule_and_history():
    kb = B.blank()
    # history: dhcp_conflict fixes have a perfect record inside the network
    for _ in range(5):
        B.learn_outcome(kb, "two dhcp servers handing out addresses", "dhcp_conflict", src="internal", ok=True)
    d = B.decide(kb, "another dhcp server is handing out addresses", recipe_kind="dhcp_conflict", src="internal")
    assert d["kind"] == "dhcp_conflict" and d["confidence"] >= 0.8 and d["auto_ok"] is True
    assert any("worked" in w for w in d["why"])


def test_decide_external_and_critical_are_cautious_never_auto():
    kb = B.blank()
    d = B.decide(kb, "failed logins from a public ip", recipe_kind="bruteforce", src="external", sev="critical")
    assert d["kind"] == "bruteforce" and d["auto_ok"] is False      # internet-facing never auto-applies


def test_decide_without_rule_uses_learned_model():
    kb = B.blank()
    for _ in range(4):
        B.learn_outcome(kb, "network loop two switch ports joined broadcast", "loop", ok=True)
    d = B.decide(kb, "a switch loop is flooding broadcasts", recipe_kind=None)
    assert d["kind"] == "loop"


def test_recurrence_flags_a_repeating_problem():
    kb = B.blank()
    sig = "gw_flap|"
    for _ in range(3):
        B.recurrence(kb, sig, now=1000)
    d = B.decide(kb, "router keeps dropping", recipe_kind="gw_flap", cat="")
    assert d["recurring"] is True and any("keeps coming back" in w for w in d["why"])


def test_migrate_handles_garbage_state():
    assert B.decide("not a dict", "some alert text", recipe_kind="x")["kind"] == "x"
    kb = {"nb": None, "kinds": None}
    d = B.decide(kb, "something", recipe_kind="loop")
    assert d["kind"] == "loop"


def test_seed_teaches_curriculum_once_and_recognises_it():
    kb = B.blank()
    n = B.seed(kb)
    assert n > 0
    # every curriculum kind is now known
    for kind in B.KNOWLEDGE:
        assert kind in kb["kinds"]
    # seeding is idempotent at the same version
    assert B.seed(kb) == 0
    # and the brain now names a problem it has only ever seen in the curriculum
    d = B.decide(kb, "the switch keeps flooding broadcast packets and the network is slow")
    assert d["kind"] == "broadcast_storm"
    d2 = B.decide(kb, "someone covered the cctv lens and the view went black")
    assert d2["kind"] == "camera_tamper"


def test_seeded_blocking_kinds_never_auto_apply():
    kb = B.blank()
    B.seed(kb)
    # kinds that block / reboot / shape / quarantine must NEVER be auto-safe, however confident
    for kind in ("quarantine", "camera_reboot", "qos", "poe_overload", "mikrotik_fix"):
        assert kind not in B.AUTO_SAFE
        d = B.decide(kb, "x", recipe_kind=kind, cat="cam", src="int", sev="warning")
        assert d["auto_ok"] is False
