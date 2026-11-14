"""PoE watch: watt maths, budget thresholds, night-vision prediction, missing-PoE handling - all without a router."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import nd_poe as P  # noqa: E402


def test_num_tolerates_units_and_blanks():
    assert P._num("54.2V") == 54.2
    assert P._num("") == 0.0 and P._num(None) == 0.0
    assert P._num("320mA") == 320.0


def test_port_watts_prefers_power_then_volts_amps():
    assert P.port_watts({"poe-out-power": "7.5"}) == 7.5
    # 54V * 0.3A = 16.2W
    assert abs(P.port_watts({"poe-out-voltage": "54", "poe-out-current": "300"}) - 16.2) < 0.01


def test_summarize_totals_only_powered_ports():
    ports = [{"name": "ether2", "poe-out": "auto-on"}, {"name": "ether3", "poe-out": "auto-on"}]
    mon = [{"name": "ether2", "poe-out-status": "powered-on", "poe-out-power": "10"},
           {"name": "ether3", "poe-out-status": "short-circuit", "poe-out-power": "0"}]
    s = P.summarize(ports, mon, budget_w=50)
    assert s["poe_capable"] and s["powered"] == 1 and s["total_w"] == 10.0 and s["percent"] == 20


def test_assess_warns_and_crits_on_budget():
    assert P.assess(P.summarize([{"poe-out": "auto-on"}],
                                [{"poe-out-status": "powered-on", "poe-out-power": "42"}], 50)) ["sev"] == "warning"
    assert P.assess(P.summarize([{"poe-out": "auto-on"}],
                                [{"poe-out-status": "powered-on", "poe-out-power": "48"}], 50))["sev"] == "critical"


def test_assess_predicts_night_vision_brownout():
    s = P.summarize([{"poe-out": "auto-on"}], [{"poe-out-status": "powered-on", "poe-out-power": "40"}], 50)
    a = P.assess(s, ir_headroom_w=10)   # 40 now, 50 with IR -> 100% of budget
    assert a and a["kind"] == "poe_overload" and "night-vision" in a["text"]


def test_non_poe_router_is_quiet():
    s = P.summarize([], [], budget_w=50)
    assert s["poe_capable"] is False
    assert P.assess(s) is None


class _FakeClient:
    def __init__(self, ports, mon):
        self._ports, self._mon = ports, mon

    def cmd(self, path, **kw):
        if path.endswith("/print"):
            return self._ports
        return self._mon


def test_read_does_router_io_and_returns_alert():
    c = _FakeClient([{"name": "ether2", "poe-out": "auto-on"}],
                    [{"name": "ether2", "poe-out-status": "powered-on", "poe-out-power": "48"}])
    s, alert = P.read(c, budget_w=50)
    assert s["total_w"] == 48.0 and alert and alert["sev"] == "critical"


def test_read_handles_router_without_poe_menu():
    class Boom:
        def cmd(self, *a, **k):
            raise RuntimeError("no such command")
    s, alert = P.read(Boom(), budget_w=50)
    assert s["poe_capable"] is False and alert is None
