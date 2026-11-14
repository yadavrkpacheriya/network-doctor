"""Daily report + teach-the-brain round trip."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import nd_report as R  # noqa: E402
import nd_brain as B  # noqa: E402


def test_daily_report_sections():
    problems = [{"text": "Broadcast storm 375/s", "sev": "critical", "kind": "storm", "count": 4},
                {"text": "Two DHCP servers", "sev": "warning", "kind": "dhcp_conflict", "count": 1},
                {"text": "Weird thing nobody understands", "sev": "warning", "kind": "", "count": 1}]
    fixes = [{"title": "Blocked the rogue DHCP", "kind": "dhcp_conflict", "status": "ok"},
             {"title": "Tried X", "kind": "storm", "status": "undone", "note": "a new issue appeared"}]
    missing = ["No router login saved (Setup > Router)."]
    md = R.build_daily("2026-11-14", problems, fixes, missing)
    assert "# Network Doctor - daily report, 2026-11-14" in md
    assert "Blocked the rogue DHCP" in md                          # fixed section
    assert "Tried X" in md and "a new issue appeared" in md        # undone
    assert "SERIOUS" in md and "Broadcast storm" in md             # still open (storm fix was undone)
    assert "could not work these out" in md and "Weird thing" in md  # unknown -> teach
    assert "TEACH kind=" in md and "No router login" in md


def test_was_fixed_logic():
    probs = [{"text": "x", "kind": "loop"}]
    assert R._was_fixed(probs[0], [{"kind": "loop", "status": "ok"}])
    assert not R._was_fixed(probs[0], [{"kind": "loop", "status": "undone"}])
    assert not R._was_fixed({"kind": ""}, [])


def test_teach_round_trip_makes_brain_recognise_lookalikes():
    kb = B.blank()
    # the report had an unknown problem; Claude replies with a TEACH line; the brain learns it
    guidance = "Here is how: TEACH kind=gw_flap: router disappears for a few seconds arp poisoning every hour"
    learned = B.teach(kb, B.parse_teach(guidance))
    assert learned == 1
    # now a LOOK-ALIKE wording is classified as gw_flap by the learned model
    d = B.decide(kb, "the gateway keeps disappearing for some seconds, arp poisoning", recipe_kind=None)
    assert d["kind"] == "gw_flap"


def test_recently_learned_and_section():
    import nd_brain as BR
    kb = BR.blank()
    BR.seed(kb)  # brain now knows "broadcast_storm" etc.
    unknowns = [{"text": "switch flooding broadcast packets slowing everything", "day": "2026-11-10"},
                {"text": "something totally unrecognisable zzzqqq", "day": "2026-11-10"}]
    learned = R.recently_learned(kb, unknowns)
    kinds = {l["kind"] for l in learned}
    assert "broadcast_storm" in kinds
    assert all("zzzqqq" not in l["text"] for l in learned)  # the gibberish stays unknown
    md = R.build_daily("2026-11-11", [], [], [], brain=kb, learned=learned)
    assert "Recently taught" in md and "broadcast_storm" in md
