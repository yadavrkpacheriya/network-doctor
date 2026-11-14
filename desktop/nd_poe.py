"""PoE (Power-over-Ethernet) watch for the MikroTik router.

Reads the router's own PoE-out ports (voltage / current / power per port), adds the watts up, and warns BEFORE the
switch runs out of power - the overload that browns-out cameras, especially the evening spike when every camera
turns its infra-red night-vision on at once. Pure functions over the rows the RouterOS API returns, so it tests
without a router and never touches anything (read-only: /interface/ethernet/poe/... print + monitoring).

Reality check for small routers: a MikroTik hEX and most non-PoE models have NO PoE-out ports, so there is simply
nothing to read and status() says so - the cameras are powered by separate PoE switches/injectors that have no
API. This module lights up on a router that DOES feed PoE (e.g. a hEX PoE, an RB960/hAP with PoE-out, a CRS switch
with PoE), and the brain kind it raises ("poe_overload") stays a reviewed one-click, never an automatic action."""


def _num(v):
    """A RouterOS value to float, tolerant of '' / None / units stuck on the end."""
    if v is None:
        return 0.0
    s = str(v).strip()
    out = ""
    for ch in s:
        if ch.isdigit() or ch in ".-":
            out += ch
        else:
            break
    try:
        return float(out) if out not in ("", "-", ".", "-.") else 0.0
    except ValueError:
        return 0.0


def port_watts(mon_row):
    """Watts a monitoring row reports: prefer poe-out-power, else volts*amps (mA -> A)."""
    p = _num(mon_row.get("poe-out-power"))
    if p > 0:
        return p
    return _num(mon_row.get("poe-out-voltage")) * (_num(mon_row.get("poe-out-current")) / 1000.0)


def summarize(poe_ports, monitor_rows, budget_w=0.0):
    """poe_ports: rows from /interface/ethernet/poe/print (each has 'name', maybe 'poe-out'). monitor_rows: rows
    from .../poe/monitoring (each has the live volts/amps/power and 'name'). budget_w: the switch/injector power
    budget in watts (0 = unknown). Returns a plain dict - no I/O here so it is easy to test."""
    on = [p for p in (poe_ports or []) if str(p.get("poe-out", "")).startswith("auto")
          or str(p.get("poe-out", "")) == "forced-on"]
    live = []
    total = 0.0
    for m in monitor_rows or []:
        if str(m.get("poe-out-status", "")) in ("powered-on", "waiting-for-load"):
            w = port_watts(m)
            total += w
            live.append({"name": m.get("name", "?"), "watts": round(w, 1),
                         "status": m.get("poe-out-status", "")})
    pct = round(total / budget_w * 100) if budget_w else None
    return {"poe_capable": bool(poe_ports), "ports_on": len(on), "powered": len(live),
            "total_w": round(total, 1), "budget_w": budget_w or 0.0, "percent": pct,
            "ports": sorted(live, key=lambda x: -x["watts"])}


def assess(summary, warn_pct=80, crit_pct=95, ir_headroom_w=0.0):
    """Turn a summary into an alert, or None. warn/crit are % of the budget. ir_headroom_w: extra watts to assume
    the cameras will pull when night-vision IR kicks in (predicts the evening brown-out before it happens)."""
    if not summary.get("poe_capable"):
        return None
    budget = summary.get("budget_w") or 0.0
    total = summary.get("total_w") or 0.0
    if not budget:
        return None  # cannot judge load without a budget; status is still shown in the UI
    projected = total + max(0.0, ir_headroom_w)
    now_pct = total / budget * 100
    proj_pct = projected / budget * 100
    if now_pct >= crit_pct:
        return {"kind": "poe_overload", "sev": "critical",
                "text": f"PoE load {total:.0f}W of {budget:.0f}W ({now_pct:.0f}%) - over the safe limit; a camera "
                        f"may lose power. Move some cameras to another injector/switch."}
    if proj_pct >= crit_pct and ir_headroom_w:
        return {"kind": "poe_overload", "sev": "warning",
                "text": f"PoE load {total:.0f}W now, but ~{projected:.0f}W of {budget:.0f}W ({proj_pct:.0f}%) once "
                        f"cameras switch to night-vision - likely to brown-out this evening. Spread the cameras."}
    if now_pct >= warn_pct:
        return {"kind": "poe_overload", "sev": "warning",
                "text": f"PoE load {total:.0f}W of {budget:.0f}W ({now_pct:.0f}%) - getting close to the limit."}
    return None


def read(client, budget_w=0.0, ir_headroom_w=0.0):
    """Do the router I/O and return (summary, alert_or_None). client is an nd_routeros.RouterOS. Any router error
    is turned into a 'not capable' summary rather than raised, so a missing-PoE router is handled quietly."""
    try:
        ports = client.cmd("/interface/ethernet/poe/print")
    except Exception:  # noqa: BLE001 - no PoE menu on this model, or unreachable
        return summarize([], [], budget_w), None
    mon = []
    if ports:
        try:
            mon = client.cmd("/interface/ethernet/poe/monitoring", numbers="all", once="")
        except Exception:  # noqa: BLE001
            mon = []
    s = summarize(ports, mon, budget_w)
    return s, assess(s, ir_headroom_w=ir_headroom_w)
