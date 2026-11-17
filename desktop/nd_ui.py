# -*- coding: utf-8 -*-
"""Network Doctor - small shared look for every page: a how-to strip, status cards, gauges, bar / line charts,
fix list and a full-page tile grid with switches. Plain Tk (no extra packages). Everything here only DRAWS what
it is given; the checks and fixes live in the other nd_*.py modules."""

import tkinter as tk
from tkinter import ttk

FONT = "Segoe UI"
# level -> (strong colour, soft background)
LEVEL = {"ok": ("#16a34a", "#ecfdf3"), "warn": ("#d97706", "#fffaeb"), "bad": ("#dc2626", "#fef3f2"),
         "info": ("#2563eb", "#eff6ff"), "": ("#475467", "#f2f4f7")}
MUTE = "#667085"
TRACK = "#e4e7ec"


def lv(level):
    return LEVEL.get(level, LEVEL[""])


def level_of(sev):
    """'critical'/'warning'/'ok' (the app's words) -> card level"""
    return {"critical": "bad", "warning": "warn", "ok": "ok", "BAD": "bad", "WARN": "warn", "OK": "ok"}.get(sev, "")


# ------------------------------------------------------------------ how-to strip
class HowTo(tk.Frame):
    """Coloured title + one compact strip: what it is / use it when / numbered how-to. '?' hides or shows it."""

    def __init__(self, parent, color, title, what="", when="", steps=()):
        super().__init__(parent, bg="white")
        head = tk.Frame(self, bg=color)
        head.pack(fill="x")
        tk.Label(head, text=title, bg=color, fg="white", font=(FONT, 12, "bold"), anchor="w", padx=10, pady=5
                 ).pack(side="left", fill="x", expand=True)
        self.body = tk.Frame(self, bg="#f8fafc", highlightbackground="#e4e7ec", highlightthickness=1)
        self.shown = True
        tk.Button(head, text="? how to use", bg=color, fg="white", relief="flat", bd=0, activebackground=color,
                  activeforeground="white", cursor="hand2", command=self.toggle).pack(side="right", padx=8)
        row = tk.Frame(self.body, bg="#f8fafc")
        row.pack(fill="x", padx=10, pady=(6, 2))
        if what:
            self._chip(row, "WHAT", what)
        if when:
            self._chip(row, "USE WHEN", when)
        if steps:
            r2 = tk.Frame(self.body, bg="#f8fafc")
            r2.pack(fill="x", padx=10, pady=(0, 6))
            tk.Label(r2, text="HOW", bg="#f8fafc", fg=lv("info")[0], font=(FONT, 8, "bold"), width=9, anchor="w"
                     ).pack(side="left", anchor="n")
            tk.Label(r2, text="   ".join(f"{i}. {s}" for i, s in enumerate(steps, 1)), bg="#f8fafc", fg="#344054",
                     font=(FONT, 9), justify="left", anchor="w", wraplength=1000).pack(side="left", fill="x")
        self.body.pack(fill="x")

    @staticmethod
    def _chip(row, label, text):
        f = tk.Frame(row, bg="#f8fafc")
        f.pack(fill="x", pady=1)
        tk.Label(f, text=label, bg="#f8fafc", fg=lv("info")[0], font=(FONT, 8, "bold"), width=9, anchor="w"
                 ).pack(side="left", anchor="n")
        tk.Label(f, text=text, bg="#f8fafc", fg="#344054", font=(FONT, 9), justify="left", anchor="w",
                 wraplength=1000).pack(side="left", fill="x")

    def toggle(self):
        self.shown = not self.shown
        (self.body.pack(fill="x") if self.shown else self.body.pack_forget())


# ------------------------------------------------------------------ cards
class Card(tk.Frame):
    """Big value + small title + one-line note, coloured by level (ok / warn / bad / info)."""

    def __init__(self, parent, title, value, note="", level="", width=190):
        strong, soft = lv(level)
        super().__init__(parent, bg=soft, highlightbackground=strong, highlightthickness=1, width=width)
        tk.Label(self, text=title.upper(), bg=soft, fg=MUTE, font=(FONT, 8, "bold"), anchor="w").pack(
            fill="x", padx=10, pady=(7, 0))
        tk.Label(self, text=str(value), bg=soft, fg=strong, font=(FONT, 17, "bold"), anchor="w").pack(fill="x", padx=10)
        if note:
            tk.Label(self, text=note, bg=soft, fg="#344054", font=(FONT, 9), anchor="w", justify="left",
                     wraplength=width - 20).pack(fill="x", padx=10, pady=(0, 7))
        else:
            tk.Frame(self, bg=soft, height=7).pack()


class Panel(tk.Frame):
    """The visual result area of a page. clear() empties it, row() adds a line of cards/charts."""

    def __init__(self, parent):
        super().__init__(parent, bg="white")

    def clear(self):
        for w in self.winfo_children():
            w.destroy()

    def row(self, pady=(4, 2)):
        r = tk.Frame(self, bg="white")
        r.pack(fill="x", pady=pady)
        return r

    def cards(self, items):
        """items = [(title, value, note, level)]"""
        r = self.row()
        for i, (t, v, n, l) in enumerate(items):
            Card(r, t, v, n, l).pack(side="left", padx=(0 if i == 0 else 8, 0), fill="y")
        return r

    def verdict(self, text, level, fixes=()):
        """Big one-line result, then numbered fixes right below it."""
        strong, soft = lv(level)
        box = tk.Frame(self, bg=soft, highlightbackground=strong, highlightthickness=1)
        box.pack(fill="x", pady=(6, 2))
        tk.Label(box, text=text, bg=soft, fg=strong, font=(FONT, 12, "bold"), anchor="w", justify="left",
                 wraplength=1000).pack(fill="x", padx=10, pady=(7, 3 if fixes else 7))
        if fixes:
            tk.Label(box, text="WHAT TO DO", bg=soft, fg=MUTE, font=(FONT, 8, "bold"), anchor="w").pack(fill="x", padx=10)
            for i, (fix, why) in enumerate(fixes, 1):
                r = tk.Frame(box, bg=soft)
                r.pack(fill="x", padx=10, pady=1)
                tk.Label(r, text=f"{i}", bg=strong, fg="white", font=(FONT, 9, "bold"), width=2).pack(side="left")
                tk.Label(r, text=" " + fix + (f"   [{why}]" if why else ""), bg=soft, fg="#101828", font=(FONT, 10, "bold"),
                         anchor="w", justify="left", wraplength=940).pack(side="left")
            tk.Frame(box, bg=soft, height=6).pack()
        return box


# ------------------------------------------------------------------ charts
class Gauge(tk.Canvas):
    """Half-circle dial. set(value, maximum, unit, caption, level)."""

    def __init__(self, parent, size=170):
        super().__init__(parent, width=size, height=int(size * 0.66), bg="white", highlightthickness=0)
        self.size = size

    def set(self, value, maximum, unit="", caption="", level=""):
        self.delete("all")
        s = self.size
        pad = 14
        box = (pad, pad, s - pad, s - pad)
        self.create_arc(*box, start=0, extent=180, style="arc", width=14, outline=TRACK)
        frac = 0 if not maximum or value is None else max(0.0, min(1.0, value / maximum))
        if frac > 0:
            self.create_arc(*box, start=180, extent=-180 * frac, style="arc", width=14, outline=lv(level)[0])
        txt = "-" if value is None else (f"{value:.0f}" if value >= 10 else f"{value:.1f}")
        self.create_text(s / 2, s / 2 - 18, text=txt, font=(FONT, 20, "bold"), fill=lv(level)[0])
        self.create_text(s / 2, s / 2 + 2, text=unit, font=(FONT, 9), fill=MUTE)
        self.create_text(s / 2, s / 2 + 22, text=caption, font=(FONT, 9, "bold"), fill="#344054")


class Bars(tk.Canvas):
    """Horizontal bars. set([(label, value, level, text)], title). Good for channel use, usage per app, errors."""

    def __init__(self, parent, width=420, row_h=20):
        super().__init__(parent, width=width, height=40, bg="white", highlightthickness=0)
        self.w, self.row_h = width, row_h

    def set(self, items, title="", maximum=None):
        self.delete("all")
        top = 20 if title else 4
        self.configure(height=top + max(1, len(items)) * self.row_h + 4)
        if title:
            self.create_text(2, 9, text=title, anchor="w", font=(FONT, 9, "bold"), fill="#344054")
        mx = maximum or max([v for _, v, _, _ in items if v] or [1])
        label_w, val_w = 64, 64
        bar_w = self.w - label_w - val_w
        for i, (label, v, level, text) in enumerate(items):
            y = top + i * self.row_h
            self.create_text(label_w - 6, y + self.row_h / 2, text=str(label), anchor="e", font=(FONT, 9), fill="#344054")
            self.create_rectangle(label_w, y + 3, label_w + bar_w, y + self.row_h - 3, fill="#f2f4f7", outline="")
            if v:
                self.create_rectangle(label_w, y + 3, label_w + max(3, bar_w * min(1.0, v / mx)), y + self.row_h - 3,
                                      fill=lv(level)[0], outline="")
            self.create_text(label_w + bar_w + 6, y + self.row_h / 2, text=text if text is not None else str(v),
                             anchor="w", font=(FONT, 9), fill=MUTE)


class Lines(tk.Canvas):
    """Small line chart of one or more series (None = lost, drawn as a red tick on the bottom). The slow-down
    check uses it to show latency and lost pings over the whole test."""

    def __init__(self, parent, width=460, height=150):
        super().__init__(parent, width=width, height=height, bg="white", highlightthickness=1,
                         highlightbackground=TRACK)
        self.w, self.h = width, height

    def set(self, series, title="", unit="ms"):
        """series = [(name, values, level)]"""
        self.delete("all")
        l, r, t, b = 40, 8, 22, 18
        vals = [v for _, vs, _ in series for v in vs if v is not None]
        self.create_text(6, 10, text=title, anchor="w", font=(FONT, 9, "bold"), fill="#344054")
        if not vals:
            self.create_text(self.w / 2, self.h / 2, text="no replies", fill="#b42318", font=(FONT, 10, "bold"))
            return
        hi = max(max(vals) * 1.1, 5.0)
        pw, ph = self.w - l - r, self.h - t - b
        for k in (0, 0.5, 1):
            y = t + ph * (1 - k)
            self.create_line(l, y, l + pw, y, fill="#f2f4f7")
            self.create_text(l - 4, y, text=f"{hi * k:.0f}", anchor="e", font=(FONT, 8), fill=MUTE)
        self.create_text(l + pw, 10, text=unit, anchor="e", font=(FONT, 8), fill=MUTE)
        for name, vs, level in series:
            n = len(vs)
            if n < 2:
                continue
            pts, run = [], []
            for i, v in enumerate(vs):
                x = l + pw * i / (n - 1)
                if v is None:
                    self.create_line(x, t + ph - 8, x, t + ph, fill="#dc2626", width=2)
                    if len(run) >= 4:
                        pts.append(run)
                    run = []
                else:
                    run += [x, t + ph * (1 - v / hi)]
            if len(run) >= 4:
                pts.append(run)
            for seg in pts:
                self.create_line(*seg, fill=lv(level)[0], width=2)
        x = l
        for name, _, level in series:
            self.create_line(x, self.h - 8, x + 14, self.h - 8, fill=lv(level)[0], width=3)
            self.create_text(x + 18, self.h - 8, text=name, anchor="w", font=(FONT, 8), fill="#344054")
            x += 28 + 7 * len(name)
        if any(None in vs for _, vs, _ in series):
            self.create_line(x, self.h - 12, x, self.h - 4, fill="#dc2626", width=2)
            self.create_text(x + 6, self.h - 8, text="lost", anchor="w", font=(FONT, 8), fill="#344054")


# ------------------------------------------------------------------ tile grid with switches (sites / apps)
class Tiles(tk.Frame):
    """Full-page grid of compact tiles. Each tile = name, small note, optional usage bar and an on/off switch that
    drives a tk.BooleanVar the page already uses. set(items) where item = dict(title, sub, var, usage=0..1,
    usage_text, on_text, off_text). Search box on top; wraps to the window width."""

    TILE_W = 232

    def __init__(self, parent, on_text="BLOCKED", off_text="allowed", on_level="bad", hint="", height=300):
        super().__init__(parent, bg="white")
        self.on_text, self.off_text, self.on_level = on_text, off_text, on_level
        top = tk.Frame(self, bg="white")
        top.pack(fill="x")
        tk.Label(top, text="Search", bg="white", fg=MUTE, font=(FONT, 9)).pack(side="left")
        self.q = tk.StringVar()
        e = ttk.Entry(top, textvariable=self.q, width=26)
        e.pack(side="left", padx=6)
        self.q.trace_add("write", lambda *_: self._layout())
        self.count = tk.Label(top, text="", bg="white", fg=MUTE, font=(FONT, 9))
        self.count.pack(side="left", padx=8)
        if hint:
            tk.Label(top, text=hint, bg="white", fg=MUTE, font=(FONT, 9)).pack(side="right")
        body = tk.Frame(self, bg="white")
        body.pack(fill="both", expand=True, pady=(4, 0))
        self.cv = tk.Canvas(body, bg="white", highlightthickness=0, height=height)
        ys = ttk.Scrollbar(body, orient="vertical", command=self.cv.yview)
        self.cv.configure(yscrollcommand=ys.set)
        self.cv.pack(side="left", fill="both", expand=True)
        ys.pack(side="right", fill="y")
        self.inner = tk.Frame(self.cv, bg="white")
        self.win = self.cv.create_window(0, 0, window=self.inner, anchor="nw")
        self.cv.bind("<Configure>", self._on_size)
        self.inner.bind("<Configure>", lambda e: self.cv.configure(scrollregion=self.cv.bbox("all")))
        for w in (self.cv, self.inner):
            w.bind("<Enter>", lambda e: self.cv.bind_all("<MouseWheel>", self._wheel))
            w.bind("<Leave>", lambda e: self.cv.unbind_all("<MouseWheel>"))
        self.items, self.tiles, self._cols, self._maxh, self._top = [], [], 0, height, top

    def _fit(self):
        """Grow to the tiles that are shown (up to the given height); scroll only when there are more."""
        try:
            self.cv.configure(height=max(60, min(self._maxh, self.inner.winfo_reqheight())))
        except tk.TclError:
            pass

    def _wheel(self, e):
        self.cv.yview_scroll(-1 if e.delta > 0 else 1, "units")

    def _on_size(self, e):
        self.cv.itemconfigure(self.win, width=e.width)
        cols = max(1, e.width // self.TILE_W)
        if cols != self._cols:
            self._layout()

    def set(self, items):
        for t in self.tiles:
            t[0].destroy()
        self.items, self.tiles = items, []
        (self._top.pack_forget() if len(items) <= 6 else self._top.pack(fill="x", before=self._top.master.winfo_children()[1]))
        for it in items:
            self.tiles.append((self._make(it), it))
        self._layout()

    def _make(self, it):
        var = it["var"]
        t = tk.Frame(self.inner, bg="white", highlightthickness=1, highlightbackground=TRACK, cursor="hand2")
        name = tk.Label(t, text=it["title"], bg="white", fg="#101828", font=(FONT, 10, "bold"), anchor="w")
        name.pack(fill="x", padx=8, pady=(6, 0))
        sub = tk.Label(t, text=it.get("sub", ""), bg="white", fg=MUTE, font=(FONT, 8), anchor="w", justify="left",
                       wraplength=self.TILE_W - 24)
        sub.pack(fill="x", padx=8)
        use = None
        if it.get("usage") is not None:
            use = tk.Canvas(t, width=self.TILE_W - 24, height=12, bg="white", highlightthickness=0)
            use.pack(padx=8, pady=(3, 0))
            use.create_rectangle(0, 3, self.TILE_W - 24, 9, fill="#f2f4f7", outline="")
            use.create_rectangle(0, 3, max(2, (self.TILE_W - 24) * min(1.0, it["usage"])), 9, fill=lv("info")[0], outline="")
            tk.Label(t, text=it.get("usage_text", ""), bg="white", fg=MUTE, font=(FONT, 8), anchor="w").pack(fill="x", padx=8)
        sw = tk.Label(t, font=(FONT, 9, "bold"), pady=2)
        sw.pack(fill="x", padx=8, pady=(4, 7))

        def paint(*_):
            on = bool(var.get())
            strong, soft = lv(self.on_level if on else "")
            sw.configure(text=("  " + (it.get("on_text") or self.on_text)) if on else ("  " + (it.get("off_text") or self.off_text)),
                         bg=strong if on else "#f2f4f7", fg="white" if on else MUTE, anchor="w")
            t.configure(highlightbackground=strong if on else TRACK)
        var.trace_add("write", paint)
        paint()

        def flip(_e=None):
            var.set(not var.get())
        for w in [t] + list(t.winfo_children()):
            w.bind("<Button-1>", flip)
        return t

    def _layout(self):
        q = self.q.get().strip().lower()
        w = max(self.cv.winfo_width(), self.TILE_W)
        cols = max(1, w // self.TILE_W)
        self._cols = cols
        shown = 0
        for t, it in self.tiles:
            t.grid_forget()
        for t, it in self.tiles:
            if q and q not in (it["title"] + " " + it.get("sub", "")).lower():
                continue
            t.grid(row=shown // cols, column=shown % cols, padx=4, pady=4, sticky="nsew")
            shown += 1
        for c in range(cols):
            self.inner.columnconfigure(c, weight=1, uniform="tile")
        self.after_idle(self._fit)
        on = sum(1 for _, it in self.tiles if it["var"].get())
        self.count.configure(text=f"{shown} shown  -  {on} {self.on_text.lower()}")
