#!/usr/bin/env python3
"""
report.py — on-demand executive metrics report (Lens #3).

Reads the findings.db campaign store and produces an executive pack that answers
how the brand is being targeted, how the threat is trending, and how noise is
triaged into a short action list. Renders matplotlib PNGs (slide-paste-ready)
AND a single self-contained report.html, plus CSV aggregates.

The chart set (all scoped to confirmed threats by default; see --scope):
  * trend         — campaigns live per period (month reads a 13-month history)
  * channel_trend — paid ads vs SEO poisoning over time
  * engine_device — donut, two blues for Bing / two oranges for Google
  * longevity     — longest-lived threats, coloured by attack type
  * query, top    — search-term breakdown and most-seen impersonating hosts
  * funnel        — triage funnel figures as funnel.csv, for a Microsoft funnel
                    graphic (PowerPoint SmartArt / Excel / Power BI); NOT drawn

All matplotlib use is confined to this file — the live monitor never imports it.
Aggregation lives in report_data.py (pure, unit-tested).

Examples:
    ./bin/python report.py --period month                 # exec pack, ./reports/
    ./bin/python report.py --scope unreviewed             # the analyst work queue
    ./bin/python report.py --start-date 2026-06-25 --engine bing
    ./bin/python report.py --summary                      # census + KPIs, no files
    ./bin/python report.py --brand "Acme Corp" --format html

Honesty rules (from report_data.py) survive the visuals: partial edge periods
are marked not dropped, the donut names how many cases lacked a device, the
three-state census prints at every scope, and exposure spans are labelled
"observed while monitoring", never time-to-takedown.
"""

import argparse
import base64
import csv
import io
import os
from datetime import date, datetime, timezone
from pathlib import Path

import matplotlib
matplotlib.use("Agg")  # headless: render to files, no display
import matplotlib.pyplot as plt
from matplotlib.patches import Patch
from matplotlib.ticker import MaxNLocator

import report_data as rd

import fi_registry

DEFAULT_DB    = os.getenv("FINDINGS_DB", "/path/to/project/findings.db")
DEFAULT_BRAND = os.getenv("BRAND_NAME", "Monitored Brand")
TRIAGE_FILE   = os.getenv("TRIAGE_FILE", "/path/to/project/triaged_domains.json")
FI_REGISTRY_FILE = os.getenv("FI_REGISTRY_FILE")

# --scope reads as a plural noun ("threats"); the stored state is singular
# ("threat"). Mapped explicitly rather than by string surgery, so a renamed
# state fails loudly here instead of silently selecting an empty population.
SCOPE_TO_STATE = {
    "threats":    fi_registry.THREAT,
    "legitimate": fi_registry.LEGITIMATE,
    "unreviewed": fi_registry.UNREVIEWED,
}


def load_triaged_hosts() -> set[str]:
    """Canonical triaged hosts, so analyst-benign domains are excluded from the
    threat report (the store keeps every historical flag). Empty on any error."""
    import json
    from domainmatch import host_of
    try:
        data = json.loads(Path(TRIAGE_FILE).read_text(encoding="utf-8"))
    except Exception:
        return set()
    return {h for h in (host_of(d) for d in data.get("triaged_domains", [])) if h}

# Executive chart palette. One accent (red) reserved for threat, one hue family
# per engine (blues = Bing, oranges = Google), traffic-light green for benign.
# Chosen, not defaulted — restrained so the data carries the page.
INK    = "#111827"   # primary text
MUTED  = "#6b7280"   # captions / secondary text
FAINT  = "#9ca3af"   # tertiary / footnotes
GRID   = "#eceef1"   # hairline gridlines
THREAT = "#d1344b"   # the single accent — threats / infringement
SLATE  = "#4a6076"   # neutral aggregate (trend total, dedup)
PAID   = "#2f6df6"   # paid ads / sponsored
SEO    = "#e8883a"   # SEO poisoning / organic
BOTH   = "#7a5bb0"   # reached both ways
GREEN  = "#3f9c6d"   # benign / legitimate
BING_D, BING_M = "#22508f", "#7ea8d8"   # two blues  — Bing desktop / mobile
GOOG_D, GOOG_M = "#cf6a1f", "#f0aa6b"   # two oranges — Google desktop / mobile
NODATA = "#d7dce1"   # not recorded

plt.rcParams.update({
    "font.family": "DejaVu Sans", "font.size": 11, "text.color": INK,
    "axes.edgecolor": FAINT, "axes.labelcolor": MUTED,
    "xtick.color": MUTED, "ytick.color": MUTED,
    "figure.dpi": 160, "savefig.dpi": 160,
})


def effective_window(k, start_date, end_date) -> tuple[str, str]:
    """The span the report actually covers, as ISO dates.

    Requested bounds win where given, but are clamped to the dates the data
    actually spans, so a wide --start-date cannot caption a chart with months of
    coverage that were never monitored. With no bounds given (the common case)
    this is the data span, so every chart still gets a truthful timeframe.
    """
    lo, hi = k["earliest_date"], k["latest_date"]
    return (max(start_date, lo) if start_date else lo,
            min(end_date, hi) if end_date else hi)


def window_label(start_iso: str, end_iso: str) -> str:
    """'Jun 18 – Jul 16, 2026' — the timeframe caption every chart carries, so a
    PNG pasted into a deck still says what period it covers."""
    s, e = date.fromisoformat(start_iso), date.fromisoformat(end_iso)
    left = f"{s.strftime('%b')} {s.day}" + (f", {s.year}" if s.year != e.year else "")
    return f"{left} – {e.strftime('%b')} {e.day}, {e.year}"


def _frame(ax, left=False):
    """Strip chartjunk: drop top/right (and usually left) spines to a hairline."""
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    ax.spines["left"].set_visible(left)
    ax.spines["left"].set_color(FAINT)
    ax.spines["bottom"].set_color(FAINT)
    ax.tick_params(length=0)


def _titles(ax, title, subtitle="", window="", size=15):
    """Left-aligned bold finding, muted sub-caption, faint data-window line —
    stacked with enough top padding that they never crowd."""
    ax.set_title(title, loc="left", fontsize=size, fontweight="bold", color=INK,
                 pad=26 + 14 * bool(subtitle or window))
    if window:
        ax.annotate(window, (0, 1.0), xycoords="axes fraction", xytext=(0, 10),
                    textcoords="offset points", ha="left", va="bottom",
                    fontsize=9, color=FAINT)
    if subtitle:
        ax.annotate(subtitle, (0, 1.0), xycoords="axes fraction",
                    xytext=(0, 24 if window else 10), textcoords="offset points",
                    ha="left", va="bottom", fontsize=10.5, color=MUTED)


def _footnote(ax, text):
    ax.annotate(text, (0, 0), xycoords="axes fraction", xytext=(0, -42),
                textcoords="offset points", fontsize=8.5, color=FAINT)


def _png(fig) -> bytes:
    buf = io.BytesIO()
    fig.savefig(buf, format="png", bbox_inches="tight", facecolor="white",
                pad_inches=0.3)
    plt.close(fig)
    return buf.getvalue()


# --------------------------------------------------------------------------- #
# Charts — each returns PNG bytes
# --------------------------------------------------------------------------- #

def _span_label(start_iso: str, end_iso: str) -> str:
    """'Jun 22–28' / 'Jun 29–Jul 5' — a week bucket's real covered span."""
    s, e = date.fromisoformat(start_iso), date.fromisoformat(end_iso)
    if (s.month, s.year) == (e.month, e.year):
        return f"{s.strftime('%b')} {s.day}–{e.day}"
    return f"{s.strftime('%b')} {s.day}–{e.strftime('%b')} {e.day}"


def _xlabels(series, period):
    """Month → 'Jul 26' (reads a 13-month trend without crowding); week → span."""
    if period == "month":
        return [date.fromisoformat(r["bucket"] + "-01").strftime("%b %y") for r in series]
    return [_span_label(r["start"], r["end"]) for r in series]


def chart_trend(series, period, window="") -> bytes:
    """Neutral single line of campaigns live per period, value-labelled, with a
    counted axis. Partial edge periods get a hollow marker — carried, not
    dropped, so a short month cannot read as the threat receding."""
    x = list(range(len(series)))
    active = [r["active"] for r in series]
    fig, ax = plt.subplots(figsize=(9.6, 4.6))
    ax.grid(axis="y", color=GRID, lw=1, zorder=0)
    ax.plot(x, active, color=SLATE, lw=2.3, zorder=3)
    for xi, y, r in zip(x, active, series):
        partial = r["onset"] or r["partial"]
        ax.plot([xi], [y], marker="o", ms=6.5, zorder=4,
                mfc="white" if partial else SLATE, mec=SLATE, mew=2)
        ax.annotate(f"{y}", (xi, y), textcoords="offset points", xytext=(0, 11),
                    ha="center", fontsize=9.5, fontweight="bold", color=INK)
    ax.set_ylim(0, (max(active) or 1) * 1.28)
    ax.yaxis.set_major_locator(MaxNLocator(integer=True, nbins=5))
    ax.set_ylabel("active campaigns", fontsize=10)
    ax.set_xticks(x)
    ax.set_xticklabels(_xlabels(series, period), fontsize=8.5)
    _frame(ax, left=True)
    period_word = "week" if period == "week" else "month"
    _titles(ax, "Impersonation campaigns over time",
            subtitle=f"brand-impersonation campaigns live per {period_word}", window=window)
    if any(r["onset"] or r["partial"] for r in series):
        _footnote(ax, "Hollow points are partial periods — fewer days measured, not fewer attacks.")
    return _png(fig)


def chart_channel_trend(rows, period, window="") -> bytes:
    """Paid ads vs SEO poisoning per period, direct-labelled. When the two series
    finish on the same value the labels are spread to a minimum gap with a short
    leader, so they never overprint — robust to any data."""
    x = list(range(len(rows)))
    paid = [r["paid"] for r in rows]
    seo  = [r["seo"] for r in rows]
    fig, ax = plt.subplots(figsize=(9.6, 4.6))
    ax.grid(axis="y", color=GRID, lw=1, zorder=0)
    for ys, color in ((paid, PAID), (seo, SEO)):
        ax.plot(x, ys, color=color, lw=2.3, marker="o", ms=4.5, mfc="white",
                mec=color, mew=1.8, zorder=3)
    ends = sorted([("Paid ads", PAID, paid[-1]), ("SEO poisoning", SEO, seo[-1])],
                  key=lambda e: -e[2])
    span = max(paid + seo) or 1
    min_sep = 0.075 * span
    if ends[0][2] - ends[1][2] < min_sep:
        mid = (ends[0][2] + ends[1][2]) / 2
        label_ys = [mid + min_sep / 2, mid - min_sep / 2]
    else:
        label_ys = [ends[0][2], ends[1][2]]
    for (name, color, py), ly in zip(ends, label_ys):
        if abs(ly - py) > 0.02 * span:
            ax.plot([x[-1], x[-1]], [py, ly], color=color, lw=0.9, alpha=0.55, zorder=2)
        ax.annotate(f"  {name}", (x[-1], ly), va="center", ha="left",
                    fontsize=10.5, fontweight="bold", color=color, zorder=4)
    ax.set_ylim(0, span * 1.28)
    ax.set_xlim(-0.3, len(rows) - 1 + len(rows) * 0.16)
    ax.yaxis.set_major_locator(MaxNLocator(integer=True, nbins=5))
    ax.set_ylabel("active campaigns", fontsize=10)
    ax.set_xticks(x)
    ax.set_xticklabels(_xlabels(rows, period), fontsize=8.5)
    _frame(ax, left=True)
    _titles(ax, "Paid ads and SEO poisoning need different takedowns",
            subtitle="active campaigns per period, by how they reached customers", window=window)
    return _png(fig)


def chart_engine_device(cases, window="") -> bytes:
    """Donut of threat sightings by engine and device: two blues for Bing, two
    oranges for Google. Cases with no device recorded are omitted and counted in
    the sub-caption rather than silently dropped."""
    import math
    segs = [
        ("Bing · Desktop",   BING_D, sum(1 for c in cases if c["engine"] == "bing" and "desktop" in c["devices"])),
        ("Bing · Mobile",    BING_M, sum(1 for c in cases if c["engine"] == "bing" and "mobile" in c["devices"])),
        ("Google · Desktop", GOOG_D, sum(1 for c in cases if c["engine"] == "google" and "desktop" in c["devices"])),
        ("Google · Mobile",  GOOG_M, sum(1 for c in cases if c["engine"] == "google" and "mobile" in c["devices"])),
    ]
    segs = [s for s in segs if s[2] > 0]
    omitted = sum(1 for c in cases if c["engine"] not in ("google", "bing") or not c["devices"])
    total = sum(s[2] for s in segs)
    fig, ax = plt.subplots(figsize=(8.4, 5.0))
    if total == 0:
        ax.text(0.5, 0.5, "no device-attributed threats", ha="center", va="center",
                color=MUTED, fontsize=12)
        ax.axis("off")
        _titles(ax, "Where the threats show up: engine and device", window=window)
        return _png(fig)
    wedges, _ = ax.pie([s[2] for s in segs], colors=[s[1] for s in segs],
                       startangle=90, counterclock=False,
                       wedgeprops=dict(width=0.42, edgecolor="white", linewidth=2))
    ax.text(0, 0.08, f"{total}", ha="center", va="center", fontsize=26, fontweight="bold", color=INK)
    ax.text(0, -0.16, "threat sightings", ha="center", va="center", fontsize=10.5, color=MUTED)
    for w, (lab, _c, v) in zip(wedges, segs):
        ang = math.radians((w.theta2 + w.theta1) / 2)
        xx, yy = math.cos(ang), math.sin(ang)
        ax.annotate(f"{lab}\n{v} ({v / total * 100:.0f}%)", (xx * 0.98, yy * 0.98),
                    xytext=(xx * 1.3, yy * 1.22), ha="left" if xx >= 0 else "right",
                    va="center", fontsize=10, color=INK, fontweight="bold",
                    arrowprops=dict(arrowstyle="-", color=FAINT, lw=1))
    ax.set(aspect="equal")
    sub = "share of confirmed-threat sightings, by search engine and device"
    if omitted:
        sub += f"  ·  {omitted} with no device recorded, omitted"
    _titles(ax, "Where the threats show up: engine and device", subtitle=sub, window=window)
    return _png(fig)


# Attack-type colours for the longevity bars, keyed on a case's channel set.
def _channel_color(channels):
    s = set(channels or [])
    if s == {"sponsored_ad"}:
        return PAID, "Paid ad"
    if s == {"organic"}:
        return SEO, "SEO poisoning"
    if {"sponsored_ad", "organic"} <= s:
        return BOTH, "Both"
    return NODATA, "Not recorded"


def chart_longevity(cases, window="", n=10) -> bytes:
    """Ranked horizontal bars of the longest-lived threats, coloured by attack
    type — so an exec sees at a glance what stayed live longest and whether it
    was paid or SEO."""
    ranked = sorted(cases, key=lambda c: -c["active_window"])[:n][::-1]
    if not ranked:
        fig, ax = plt.subplots(figsize=(9.6, 3))
        ax.text(0.5, 0.5, "no threats to rank", ha="center", color=MUTED)
        ax.axis("off")
        return _png(fig)
    colors = [_channel_color(c["channels"])[0] for c in ranked]
    days = [c["active_window"] for c in ranked]
    fig, ax = plt.subplots(figsize=(9.6, 0.5 * len(ranked) + 1.9))
    ax.barh(range(len(ranked)), days, color=colors, height=0.64, zorder=3)
    for i, d in enumerate(days):
        ax.annotate(f"{d} days", (d, i), xytext=(7, 0), textcoords="offset points",
                    va="center", fontsize=9.5, fontweight="bold", color=INK)
    ax.set_yticks(range(len(ranked)))
    ax.set_yticklabels([c["host"] for c in ranked], fontsize=9.5, color=INK)
    ax.set_xlim(0, (max(days) or 1) * 1.16)
    ax.set_xticks([])
    ax.set_xlabel("days live (first-seen to last-seen)", fontsize=10)
    _frame(ax)
    ax.spines["bottom"].set_visible(False)
    present = [Patch(facecolor=col, label=lab) for col, lab in
               [(PAID, "Paid ad"), (SEO, "SEO poisoning"), (BOTH, "Both")] if col in colors]
    if present:
        ax.legend(handles=present, loc="lower right", frameon=False, fontsize=9.5, ncol=3)
    _titles(ax, "The longest-lived threats — and how they reached customers",
            subtitle="top campaigns by days live, coloured by attack type", window=window)
    _footnote(ax, "Days live is exposure observed while monitoring — a minimum, not a time-to-takedown.")
    return _png(fig)


def chart_bar(items, title, color=SLATE, subtitle="", window="") -> bytes:
    """Simple vertical bar with value labels — used for the search-term breakdown."""
    fig, ax = plt.subplots(figsize=(6.6, 3.9))
    labels = [i["label"] for i in items]
    counts = [i["count"] for i in items]
    x = range(len(labels))
    ax.bar(x, counts, color=color, zorder=3)
    for xi, c in zip(x, counts):
        ax.annotate(str(c), (xi, c), textcoords="offset points",
                    xytext=(0, 4), ha="center", fontsize=9.5, fontweight="bold", color=INK)
    ax.set_ylim(0, (max(counts) or 1) * 1.2)
    ax.yaxis.set_major_locator(MaxNLocator(integer=True, nbins=5))
    ax.set_xticks(list(x))
    ax.set_xticklabels(labels, rotation=18, ha="right", fontsize=9)
    ax.grid(axis="y", color=GRID, lw=1, zorder=0)
    _frame(ax, left=True)
    _titles(ax, title, subtitle=subtitle, window=window)
    return _png(fig)


def chart_top_domains(rows, brand, window="") -> bytes:
    """Horizontal bars of the most-seen impersonating hosts, in the threat accent."""
    fig, ax = plt.subplots(figsize=(9.6, max(3, 0.5 * len(rows) + 1.4)))
    labels = [f'{r["host"]}  ({r["engine"]})' for r in rows][::-1]
    vals   = [r["times_seen"] for r in rows][::-1]
    y = range(len(labels))
    ax.barh(y, vals, color=THREAT, height=0.64, zorder=3)
    for yi, v in zip(y, vals):
        ax.annotate(str(v), (v, yi), textcoords="offset points",
                    xytext=(6, 0), va="center", fontsize=9.5, fontweight="bold", color=INK)
    ax.set_yticks(list(y))
    ax.set_yticklabels(labels, fontsize=9.5, color=INK)
    ax.set_xlim(0, (max(vals) or 1) * 1.14)
    ax.set_xticks([])
    ax.set_xlabel("number of times detected", fontsize=10)
    _frame(ax)
    ax.spines["bottom"].set_visible(False)
    _titles(ax, f"Websites impersonating {brand}",
            subtitle="ranked by how often the fraudulent result was seen", window=window)
    return _png(fig)


def funnel_stages(review, raw_sightings) -> list[dict]:
    """The triage-funnel rows the analyst pastes into a Microsoft funnel graphic
    (PowerPoint SmartArt / Excel / Power BI). Kept as data, not a drawn chart —
    the funnel picture is supplied from Microsoft, we supply the numbers."""
    return [
        {"stage": "All findings surfaced", "count": review["total"],
         "note": f"grouped from {raw_sightings:,} raw sightings"},
        {"stage": "Legitimate institutions", "count": review["legitimate"],
         "note": "shown for our terms · benign · no action"},
        {"stage": "Real impersonation campaigns", "count": review["threats"],
         "note": "confirmed threats — actioned"},
        {"stage": "Still under review", "count": review["unreviewed"],
         "note": "not yet cleared, not counted as threats"},
    ]


# --------------------------------------------------------------------------- #
# HTML assembly
# --------------------------------------------------------------------------- #

def _img(png: bytes) -> str:
    b64 = base64.b64encode(png).decode()
    return f'<img src="data:image/png;base64,{b64}" style="max-width:100%;height:auto;">'


def _tile(value, label, accent=INK, tag="", tagcolor="") -> str:
    chip = (f'<span class="pill" style="background:{tagcolor}1f;color:{tagcolor}">{tag}</span>'
            if tag else "")
    return (f'<div class="tile"><div class="tv" style="color:{accent}">{value}</div>'
            f'<div class="tl">{label}</div>{chip}</div>')


def build_html(brand, k, imgs, top_rows, window_note, window="",
               review=None, scope="threats", funnel=None) -> str:
    gen = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # Census first: every finding split three ways, so a scoped "N threats" is
    # always read against what it was separated from.
    census = ""
    if review:
        census = (
            '<div class="tiles">'
            + _tile(review["threats"], "Confirmed threats", THREAT, "action", THREAT)
            + _tile(review["legitimate"], "Known institutions", MUTED, "excluded", MUTED)
            + _tile(review["unreviewed"], "Awaiting review", MUTED, "queue", MUTED)
            + '</div>'
            + f'<p class="note">Every one of the {review["total"]} findings falls in exactly one of '
              f'these. <b>Confirmed threats</b> use our name and land off our domains. '
              f'<b>Known institutions</b> are real, licensed firms appearing for our generic terms — '
              f'excluded from the figures below, each vetted and recorded by name. '
              f'<b>Awaiting review</b> is a work queue, not an all-clear: a genuine fake that left '
              f'our name out of its title would sit here, so it is shown rather than folded away.'
            + (f' <b>{review["conflicts"]} conflict(s)</b> — on the registry yet using our name — '
               f'stay counted as threats until reviewed.' if review["conflicts"] else "")
            + '</p>'
        )

    tiles = "".join([
        _tile(k["distinct"], "Campaigns in scope"),
        _tile(k.get("sponsored", 0), "Paid ads"),
        _tile(k.get("organic", 0), "SEO-poisoned pages"),
        _tile(k["persistent"], "Ongoing — escalate", THREAT),
        _tile(k["recently_active"], "Active in last 7 days", THREAT),
        _tile(f"{k['max_window']}d", "Longest exposure"),
    ])
    rows = "".join(
        f"<tr><td>{r['host']}</td><td>{r['engine']}</td><td class='n'>{r['times_seen']}</td>"
        f"<td>{r['first']}</td><td>{r['last']}</td><td class='n'>{r['active_window']}d</td></tr>"
        for r in top_rows
    )
    funnel_rows = ""
    if funnel:
        chips = {"All findings surfaced": SLATE, "Legitimate institutions": GREEN,
                 "Real impersonation campaigns": THREAT, "Still under review": FAINT}
        body = "".join(
            f"<tr class='{'foot' if s['stage']=='Still under review' else ''}'>"
            f"<td><span class='chip' style='background:{chips.get(s['stage'], SLATE)}'></span>"
            f"{s['stage']}</td><td class='n'>{s['count']}</td><td>{s['note']}</td></tr>"
            for s in funnel)
        funnel_rows = (
            '<table class="funnel"><thead><tr><th>Stage</th><th class="n">Count</th>'
            '<th>What it is</th></tr></thead><tbody>' + body + '</tbody></table>')

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{brand} — Brand Ad Threat Report</title>
<style>
 :root{{--ink:{INK};--muted:{MUTED};--faint:{FAINT};--line:#e6e9ee;--paper:#f6f7f9;
   --panel:#fff;--threat:{THREAT};--accent:{PAID}}}
 *{{box-sizing:border-box}}
 body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
   color:var(--ink);margin:0;background:var(--paper);line-height:1.55}}
 .wrap{{max-width:1060px;margin:0 auto;padding:40px 24px 80px}}
 h1{{font-size:26px;font-weight:800;letter-spacing:-.02em;margin:0 0 4px}}
 h2{{font-size:13px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;
   color:var(--muted);margin:52px 0 16px;padding-bottom:10px;border-bottom:1px solid var(--line)}}
 .sub{{color:var(--muted);font-size:13px;margin-bottom:26px}}
 .tiles{{display:flex;flex-wrap:wrap;gap:12px;margin-bottom:6px}}
 .tile{{flex:1 1 148px;background:var(--panel);border:1px solid var(--line);
   border-radius:12px;padding:15px 17px;box-shadow:0 1px 2px rgba(20,28,38,.04)}}
 .tv{{font-size:28px;font-weight:800;letter-spacing:-.02em;line-height:1;
   font-variant-numeric:tabular-nums}}
 .tl{{font-size:12px;color:var(--muted);margin-top:7px}}
 .pill{{display:inline-block;font-size:10px;font-weight:700;letter-spacing:.05em;
   text-transform:uppercase;padding:2px 8px;border-radius:20px;margin-top:9px}}
 .note{{color:var(--muted);font-size:13px;max-width:74ch;margin:14px 0 0}}
 .charts{{display:flex;flex-wrap:wrap;gap:18px;align-items:flex-start}}
 .card{{background:var(--panel);border:1px solid var(--line);border-radius:14px;
   padding:14px;box-shadow:0 1px 2px rgba(20,28,38,.04);flex:1 1 440px}}
 .card img{{width:100%;height:auto;display:block;border-radius:6px}}
 table{{border-collapse:collapse;width:100%;font-size:13px;background:var(--panel)}}
 th,td{{text-align:left;padding:9px 12px;border-bottom:1px solid var(--line)}}
 th{{color:var(--faint);font-size:11px;text-transform:uppercase;letter-spacing:.06em}}
 td.n,th.n{{text-align:right;font-variant-numeric:tabular-nums}}
 .funnel td.n{{font-weight:800;font-size:16px}}
 .funnel tr.foot td{{color:var(--muted);border-bottom:none}}
 .funnel td:last-child{{color:var(--muted)}}
 .chip{{display:inline-block;width:11px;height:11px;border-radius:3px;margin-right:9px;
   vertical-align:middle}}
 .wide{{overflow-x:auto}}
 footer{{color:var(--faint);font-size:12px;margin-top:52px;padding-top:18px;
   border-top:1px solid var(--line);line-height:1.7}}
</style></head><body><div class="wrap">
 <h1>{brand} — Brand Ad Threat Report</h1>
 <div class="sub">Data window {window} &middot; scope: {scope} &middot; generated {gen}</div>
 {census}
 <div class="tiles">{tiles}</div>

 <h2>Impersonation over time</h2>
 <div class="charts">
   <div class="card">{_img(imgs['trend'])}</div>
   <div class="card">{_img(imgs['channel_trend'])}</div>
 </div>
 <p class="note">The left chart is how many campaigns were live each period. The right splits them by
   how they reached customers: <b>paid ads</b> are billed advertiser accounts the engine can suspend
   outright, while <b>SEO poisoning</b> is a page that climbed the rankings and must be taken down at
   the registrar or host — slower, one request per provider. Partial edge periods are marked, never
   dropped: a short period means fewer days measured, not fewer attacks.</p>

 <h2>Where {brand} is being targeted</h2>
 <div class="charts">
   <div class="card">{_img(imgs['engine_device'])}</div>
   <div class="card">{_img(imgs['query'])}</div>
 </div>

 <h2>Longest-lived threats</h2>
 <div class="card" style="flex:1 1 100%">{_img(imgs['longevity'])}</div>
 <h3 style="font-size:14px;margin:22px 0 10px">Most-seen impersonating websites</h3>
 <div class="charts">
   <div class="card">{_img(imgs['top'])}</div>
   <div class="card wide"><table><thead><tr><th>Website</th><th>Engine</th>
     <th class="n">Seen</th><th>First</th><th>Last</th><th class="n">Ran</th></tr></thead>
     <tbody>{rows}</tbody></table></div>
 </div>

 <h2>From noise to action</h2>
 <p class="note" style="margin-bottom:16px">How generic-term noise narrows to a short action list.
   Build the funnel graphic from these figures in a Microsoft funnel chart (PowerPoint SmartArt,
   Excel or Power BI) — <code>report.py</code> also writes them to <code>funnel.csv</code>. The
   bands count campaigns; the {funnel[0]['note'].split('from ')[-1] if funnel else 'raw sightings'}
   are shown as context so the dedup story survives too.</p>
 <div class="card" style="flex:1 1 100%;padding:6px 4px">{funnel_rows}</div>

 <footer>
   {window_note}<br>
   Exposure spans are the time between a campaign's first and last sighting while monitoring was
   running &mdash; a minimum, not a time-to-takedown (Serim tracks detection, not remediation).<br>
   Source: findings.db &middot; report.py.
 </footer>
</div></body></html>"""


# --------------------------------------------------------------------------- #
# CSV + summary
# --------------------------------------------------------------------------- #

def write_csv(path: Path, header: list[str], rows: list[list]):
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)


def print_summary(brand, k, series, group_items, group_dim, window="",
                  review=None, scope="threats"):
    print(f"\n{brand} — Brand Ad Threat Report")
    print(f"  window: {window}")
    if review:
        # The census comes first and always covers every case, so the scoped
        # numbers below can never be mistaken for the whole picture.
        print(f"  review states      : {review['threats']} threat, "
              f"{review['legitimate']} known institution, "
              f"{review['unreviewed']} unreviewed  (of {review['total']})")
        if review["unreviewed"]:
            print(f"                       {review['unreviewed']} case(s) await "
                  f"adjudication — not counted as threats, not cleared either")
        if review["conflicts"]:
            print(f"                       {review['conflicts']} registry conflict(s) "
                  f"— on the FI registry yet claiming a brand term")
        print(f"  scope of figures   : {scope}")
    print(f"  distinct campaigns : {k['distinct']}   (raw sightings {k['raw']}, "
          f"{k['dedup_ratio']}x dedup)")
    # Channel counts can overlap (one host reached both ways), so they need not
    # sum to distinct.
    print(f"  by channel         : {k.get('sponsored', 0)} sponsored ad, "
          f"{k.get('organic', 0)} organic (SEO poisoning)")
    print(f"  BRAND INFRINGEMENT : {k.get('infringing', 0)}   "
          f"(title claims a brand term, lands off-brand)")
    print(f"  persistent (esc.)  : {k['persistent']}")
    print(f"  active window      : avg {k['avg_window']}d, max {k['max_window']}d "
          f"(observed, not MTTR)")
    print(f"  active last 7 days : {k['recently_active']}")
    print(f"  engines abused     : {', '.join(k['engines']) or '—'}")
    print(f"\n  breakdown by {group_dim}:")
    for i in group_items:
        print(f"    {i['count']:4d}  {i['label']}")
    print(f"\n  new campaigns per period:")
    for r in series:
        tag = "  (ramp-up)" if r["onset"] else ""
        print(f"    {r['bucket']}: new {r['new']:3d}  active {r['active']:3d}{tag}")
    print()


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def main():
    ap = argparse.ArgumentParser(description="Manager metrics report from findings.db")
    ap.add_argument("--db", default=DEFAULT_DB)
    ap.add_argument("--brand", default=DEFAULT_BRAND, help="brand name for titles")
    ap.add_argument("--start-date", dest="start_date",
                    help="YYYY-MM-DD lower bound of the reporting window")
    ap.add_argument("--end-date", dest="end_date",
                    help="YYYY-MM-DD upper bound of the reporting window")
    ap.add_argument("--period", choices=["week", "month"], default="month",
                    help="trend granularity (default: month, the executive view; "
                         "week gives finer detail for operational review)")
    ap.add_argument("--group-by", choices=["engine", "query", "host", "device", "channel"],
                    default="engine", dest="group_by")
    ap.add_argument("--engine", choices=["google", "bing"])
    ap.add_argument("--device", choices=["desktop", "mobile"])
    ap.add_argument("--channel", choices=["sponsored_ad", "organic"],
                    help="only paid ads, or only poisoned organic results")
    ap.add_argument("--scope", choices=["threats", "unreviewed", "legitimate", "all"],
                    default="threats",
                    help="which review state the charts and KPIs cover. "
                         "threats (default) = claims a brand term and lands off-brand; "
                         "legitimate = on the known-FI registry; "
                         "unreviewed = neither, the analyst work queue; "
                         "all = every case. The three-state census is printed "
                         "whatever the scope, so nothing is silently dropped.")
    ap.add_argument("--infringing-only", action="store_true", dest="infringing_only",
                    help="deprecated alias for --scope threats")
    ap.add_argument("--top", type=int, default=10)
    ap.add_argument("--out", default="/path/to/project/reports")
    ap.add_argument("--format", choices=["html", "png", "csv", "all"], default="all")
    ap.add_argument("--summary", action="store_true",
                    help="print KPIs to stdout and exit (no files)")
    ap.add_argument("--include-triaged", action="store_true",
                    help="include analyst-triaged benign domains (excluded by default)")
    ap.add_argument("--fi-registry", dest="fi_registry", default=FI_REGISTRY_FILE,
                    help="known-legitimate FI registry JSON (default: $FI_REGISTRY_FILE)")
    args = ap.parse_args()

    if not os.path.exists(args.db):
        print(f"No findings store at {args.db}. Run backfill_findings.py first.")
        return

    # --infringing-only predates --scope and means the same thing. Kept working
    # so existing runbooks and cron entries do not break.
    scope = "threats" if args.infringing_only else args.scope

    exclude = set() if args.include_triaged else load_triaged_hosts()
    fi_hosts = fi_registry.load_hosts(args.fi_registry)
    # Load the FULL population first: the three-state census is the denominator
    # that makes a scoped threat count honest, so it must be computed before any
    # scoping. load_cases annotates review_state; it never drops on it.
    all_cases = rd.load_cases(args.db, args.start_date, args.end_date, args.engine,
                              args.device, exclude_hosts=exclude, channel=args.channel,
                              fi_hosts=fi_hosts)
    review = rd.review_summary(all_cases)
    cases  = all_cases if scope == "all" else rd.by_state(all_cases, SCOPE_TO_STATE[scope])

    if exclude:
        print(f"(excluding {len(exclude)} triaged benign host(s); --include-triaged to keep)")
    print(
        f"Review states across {review['total']} case(s): "
        f"{review['threats']} threat, {review['legitimate']} known institution, "
        f"{review['unreviewed']} unreviewed"
        + (f"  [{len(fi_hosts)} institution(s) registered]" if fi_hosts else
           "  [no FI registry loaded — every non-infringing case stays unreviewed]")
    )
    if review["conflicts"]:
        print(f"  WARNING: {review['conflicts']} case(s) are on the FI registry AND claim a "
              f"brand term. Counted as threats — review for a compromised domain or a "
              f"brandmatch false positive.")
    print(f"Reporting scope: {scope} ({len(cases)} case(s)).")

    if not cases:
        print("No cases match the given filters.")
        return

    k              = rd.kpis(cases)
    series         = rd.trend(cases, args.period)
    channel_series = rd.channel_trend(cases, args.period)
    group          = rd.breakdown(cases, args.group_by,
                                  complete_data_only=(args.group_by == "device"))
    top            = rd.top_domains(cases, args.top)
    win            = window_label(*effective_window(k, args.start_date, args.end_date))
    # The triage funnel spans the WHOLE population, not the scoped subset — it is
    # the how-we-got-here overview, so it is built from the census regardless of
    # --scope. Raw sightings summed across every finding.
    raw_all = sum(c["raw"] for c in all_cases)
    funnel  = funnel_stages(review, raw_all)

    if args.summary:
        print_summary(args.brand, k, series, group, args.group_by, win,
                      review=review, scope=scope)
        return

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    # Query is multi-valued: a campaign targeting two terms counts in each bar,
    # so the bars can total more than the campaign count. Say so on the chart
    # rather than letting the sum look like an arithmetic error.
    q_items = rd.breakdown(cases, "query")
    q_note  = ("campaigns targeting more than one term count in each bar"
               if sum(i["count"] for i in q_items) > k["distinct"] else "")

    if args.format in ("png", "all", "html"):
        imgs = {
            "trend":         chart_trend(series, args.period, window=win),
            "channel_trend": chart_channel_trend(channel_series, args.period, window=win),
            "engine_device": chart_engine_device(cases, window=win),
            "longevity":     chart_longevity(cases, window=win, n=args.top),
            "query":         chart_bar(q_items, "Campaigns by search term targeted",
                                       subtitle=q_note, window=win),
            "top":           chart_top_domains(top, args.brand, window=win),
        }

    if args.format in ("png", "all"):
        for name, png in imgs.items():
            (out / f"{name}.png").write_bytes(png)
        print(f"PNG charts written to {out}/")

    if args.format in ("html", "all"):
        window_note = (f"Figures cover the {len(cases)} case(s) in scope '{scope}'. "
                       "Device donut omits cases with no device recorded (counted in its caption).")
        html = build_html(args.brand, k, imgs, top, window_note, win,
                          review=review, scope=scope, funnel=funnel)
        (out / "report.html").write_text(html, encoding="utf-8")
        print(f"HTML dashboard: {out/'report.html'}")

    if args.format in ("csv", "all"):
        write_csv(out / "trend.csv",
                  ["bucket", "start", "end", "new", "carried", "active", "onset", "partial"],
                  [[r["bucket"], r["start"], r["end"], r["new"], r["carried"],
                    r["active"], r["onset"], r["partial"]] for r in series])
        write_csv(out / "channel_trend.csv",
                  ["bucket", "start", "end", "paid", "seo", "onset", "partial"],
                  [[r["bucket"], r["start"], r["end"], r["paid"], r["seo"],
                    r["onset"], r["partial"]] for r in channel_series])
        write_csv(out / "funnel.csv", ["stage", "count", "note"],
                  [[s["stage"], s["count"], s["note"]] for s in funnel])
        write_csv(out / f"by_{args.group_by}.csv", [args.group_by, "campaigns"],
                  [[i["label"], i["count"]] for i in group])
        write_csv(out / "top_domains.csv",
                  ["host", "engine", "times_seen", "first_seen", "last_seen", "active_window_days"],
                  [[r["host"], r["engine"], r["times_seen"], r["first"], r["last"], r["active_window"]]
                   for r in top])
        write_csv(out / "kpis.csv", ["metric", "value"],
                  [["scope", scope]]
                  + [[f"review_{m}", review[m]] for m in
                     ("threats", "legitimate", "unreviewed", "conflicts", "total")]
                  + [[m, k[m]] for m in ("distinct", "raw", "dedup_ratio", "persistent",
                                         "avg_window", "max_window", "recently_active")])
        write_csv(out / "review_queue.csv",
                  ["host", "engine", "times_seen", "first_seen", "last_seen"],
                  [[c["host"], c["engine"], c["times_seen"],
                    c["first"].isoformat(), c["last"].isoformat()]
                   for c in sorted(rd.by_state(all_cases, fi_registry.UNREVIEWED),
                                   key=lambda c: (-c["times_seen"], c["host"] or ""))])
        print(f"CSV aggregates written to {out}/")


if __name__ == "__main__":
    main()
