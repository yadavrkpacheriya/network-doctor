"""The daily report: what went wrong on the network today, what Network Doctor fixed, what is still open, and
what it could not work out on its own. Plain Markdown so it is easy to read and easy to share back - the
"Needs a human / teach the brain" section is written so it can be pasted to Claude, who replies with
`TEACH kind=...: ...` lines that the brain then learns from (nd_brain.parse_teach)."""
import time


def _fmt_count(n, one, many=None):
    return f"{n} {one}" if n == 1 else f"{n} {many or one + 's'}"


def recently_learned(brain, unknowns, margin=1.0):
    """Of the problems a past report could NOT name, which can the brain now name (because it was taught since)?
    unknowns: [{text, day}]. A problem counts as recognised only when its wording shares learned words with one
    kind AND that kind clearly out-scores the rest (Naive-Bayes margin) - so a real teaching shows up but random
    gibberish does not. Returns [{text, kind, day}]. This closes the loop: an unknown you shared and I sent TEACH
    lines for shows up as 'now handled' and drops off the unknown list. Pure read; the caller prunes the list."""
    import nd_brain as BR
    kb = BR._migrate(brain)
    nb = kb.get("nb") or {}
    out = []
    for u in unknowns or []:
        t = u.get("text", "")
        if not t or not any(tok in nb for tok in BR.tokens(t)):
            continue  # no learned word in common -> still genuinely unknown
        sc = BR.nb_scores(kb, t)
        if not sc:
            continue
        order = sorted(sc.values(), reverse=True)
        if len(order) < 2 or (order[0] - order[1]) >= margin:
            out.append({"text": t, "kind": max(sc, key=sc.get), "day": u.get("day", "")})
    return out


def build_daily(day, problems, fixes, missing, brain=None, net_summary="", learned=None):
    """day: 'YYYY-MM-DD'. problems: [{text, sev, kind, count, source}]. fixes: [{title, kind, status, note}]
    (status: 'ok' / 'undone' / 'applied'). missing: [str] setup gaps. brain: the nd_brain dict (for per-kind
    confidence). learned: [{text, kind, day}] problems once unknown that the brain can now name. Returns a
    Markdown string."""
    import nd_brain as BR
    out = [f"# Network Doctor - daily report, {day}"]
    if net_summary:
        out.append(net_summary)
    crit = [p for p in problems if p.get("sev") == "critical"]
    out.append("")
    out.append(f"**Summary:** {_fmt_count(len(problems), 'problem')} seen"
               + (f" ({len(crit)} serious)" if crit else "")
               + f", {_fmt_count(len([f for f in fixes if f.get('status') == 'ok']), 'fix')} that held, "
               + f"{_fmt_count(len([p for p in problems if not _was_fixed(p, fixes)]), 'issue')} still open.")

    # ---- fixed
    done = [f for f in fixes if f.get("status") == "ok"]
    out.append("\n## Fixed automatically")
    if done:
        for f in done:
            conf = ""
            if brain is not None:
                ch = BR.ctx_conf(brain, f.get("kind", ""), f.get("cat", ""), f.get("src", ""))
                if ch is not None:
                    conf = f"  (brain {round(ch * 100)}% sure here)"
            out.append(f"- {f.get('title', '?')}{conf}")
    else:
        out.append("- Nothing needed an automatic fix today.")

    # ---- undone / failed
    undone = [f for f in fixes if f.get("status") == "undone"]
    if undone:
        out.append("\n## Tried but rolled back (did not help)")
        for f in undone:
            out.append(f"- {f.get('title', '?')} - {f.get('note', 'undone')}")

    # ---- still open
    openp = [p for p in problems if not _was_fixed(p, fixes)]
    out.append("\n## Still open (not fixed)")
    if openp:
        for p in sorted(openp, key=lambda p: -_rank(p.get("sev"))):
            tag = "**SERIOUS** " if p.get("sev") == "critical" else ""
            cnt = f" (x{p['count']})" if p.get("count", 1) > 1 else ""
            out.append(f"- {tag}{p.get('text', '?')}{cnt}")
    else:
        out.append("- None - everything was handled.")

    # ---- recently taught -> now recognised (the loop closing)
    if learned:
        out.append("\n## Recently taught - now recognised")
        out.append("Problems earlier reports could not name, that the brain now handles after being taught:")
        for l in learned:
            out.append(f"- {l.get('text', '?')}  ->  now named **{l.get('kind', '?')}**")

    # ---- unknown / needs teaching
    unknown = [p for p in problems if not p.get("kind")]
    if unknown:
        out.append("\n## Network Doctor could not work these out on its own")
        out.append("Share this section with Claude. Reply with lines like "
                   "`TEACH kind=<a known kind>: <the key words of the problem>` and paste them into "
                   "Setup > Teach the brain, so it recognises look-alike issues next time.")
        for p in unknown:
            out.append(f"- {p.get('text', '?')}")

    # ---- missing / setup gaps
    if missing:
        out.append("\n## What is missing (would let it do more)")
        for m in missing:
            out.append(f"- {m}")

    out.append("\n---\n_Generated by Network Doctor. All of this is also in the health log._")
    return "\n".join(out)


def _rank(sev):
    return {"critical": 3, "warning": 2, "info": 1}.get(sev, 0)


def _was_fixed(problem, fixes):
    k = problem.get("kind")
    return bool(k) and any(f.get("kind") == k and f.get("status") == "ok" for f in fixes)


def default_name(day=None):
    return f"network-report-{day or time.strftime('%Y-%m-%d')}.md"
