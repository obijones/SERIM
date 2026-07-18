#!/usr/bin/env python3
"""
report.py — on-demand manager metrics report (Lens #3).

Reads the findings.db campaign store and produces an executive pack that answers
three questions: how the brand is being targeted, attack volume over time, and
the value detection adds. Renders matplotlib PNGs (slide-paste-ready) AND a
single self-contained report.html that embeds them plus KPI tiles.

All matplotlib use is confined to this file — the live monitor never imports it.
Aggregation lives in report_data.py (pure, unit-tested).

Examples:
    ./bin/python report.py                       # full pack, weekly trend, ./reports/
    ./bin/python report.py --period month
    ./bin/python report.py --start-date 2026-06-25 --engine bing
    ./bin/python report.py --summary             # KPIs to stdout, no files
    ./bin/python report.py --brand "Acme Corp" --format html

Honesty rules (from report_data.py) are surfaced in the report: the first trend
period is annotated as monitoring ramp-up, the device breakdown is scoped to the
complete-data window, and the active span is labeled "observed active window",
never time-to-takedown.
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

import report_data as rd

DEFAULT_DB    = os.getenv("FINDINGS_DB", "/path/to/project/findings.db")
DEFAULT_BRAND = os.getenv("BRAND_NAME", "Monitored Brand")
TRIAGE_FILE   = os.getenv("TRIAGE_FILE", "/path/to/project/triaged_domains.json")


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

# Calm, colorblind-safe palette — one accent (red) reserved for threat emphasis.
C_PRIMARY = "#2563eb"  # blue   — newly detected this period
C_CARRIED = "#93c5fd"  # pale blue — same campaigns, carried over from earlier
C_SECOND  = "#64748b"  # slate  — secondary series / annotations
C_THREAT  = "#dc2626"  # red    — persistent / threat emphasis
C_GRID    = "#e5e7eb"
C_MUTED   = "#94a3b8"  # light  — data-window caption


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


def _style(ax, title, subtitle="", xlabel="", ylabel="", window=""):
    # One line of top padding per caption present, so the title, the sub-caption
    # and the data window never crowd each other.
    ax.set_title(title, fontsize=13, fontweight="bold", loc="left",
                 pad={0: 12, 1: 32, 2: 46}[bool(subtitle) + bool(window)])
    offset = 10
    if window:
        ax.annotate(window, xy=(0, 1), xycoords="axes fraction",
                    xytext=(0, offset), textcoords="offset points",
                    ha="left", va="bottom", fontsize=8, color=C_MUTED)
        offset += 13
    if subtitle:
        ax.annotate(subtitle, xy=(0, 1), xycoords="axes fraction",
                    xytext=(0, offset), textcoords="offset points",
                    ha="left", va="bottom", fontsize=9, color=C_SECOND)
    if xlabel:
        ax.set_xlabel(xlabel, fontsize=10)
    if ylabel:
        ax.set_ylabel(ylabel, fontsize=10)
    ax.grid(axis="y", color=C_GRID, linewidth=0.8)
    ax.set_axisbelow(True)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)


def _png(fig) -> bytes:
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=120, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    return buf.getvalue()


# --------------------------------------------------------------------------- #
# Charts — each returns PNG bytes
# --------------------------------------------------------------------------- #

def _span_label(start_iso: str, end_iso: str) -> str:
    """'Jun 22–28' / 'Jun 29–Jul 5' — a bucket's real covered span. Executives
    cannot decode "2026-W26", and the ISO key also hides that an edge bucket is
    short: "Jun 18–21" says so on its face."""
    s, e = date.fromisoformat(start_iso), date.fromisoformat(end_iso)
    if (s.month, s.year) == (e.month, e.year):
        return f"{s.strftime('%b')} {s.day}–{e.day}"
    return f"{s.strftime('%b')} {s.day}–{e.strftime('%b')} {e.day}"


def chart_trend(series, period, window="") -> bytes:
    fig, ax = plt.subplots(figsize=(9, 4.4))
    labels  = [_span_label(r["start"], r["end"]) for r in series]
    new     = [r["new"] for r in series]
    carried = [r["carried"] for r in series]
    x = list(range(len(labels)))

    # Stacked, not overlaid: "still active" CONTAINS "newly detected", so the two
    # are a part and its whole. The old line-over-bars implied they were rival
    # series to compare, and full bar height is what "how bad is it now" means.
    bot = ax.bar(x, new, color=C_PRIMARY, label="Newly detected this period")
    top = ax.bar(x, carried, bottom=new, color=C_CARRIED,
                 label="Still active from earlier")

    # An incomplete bucket has fewer DAYS, not fewer attacks. Hatch both segments
    # so a short edge period can never be misread as the threat receding.
    for i, r in enumerate(series):
        if r["onset"] or r["partial"]:
            for seg in (bot[i], top[i]):
                seg.set_hatch("///")
                seg.set_edgecolor("white")
                seg.set_linewidth(0)

    for i, r in enumerate(series):
        note = ("monitoring\njust started" if r["onset"]
                else "period cut short\nby report date" if r["partial"] else "")
        if note:
            ax.annotate(note, (i, r["active"]), textcoords="offset points",
                        xytext=(0, 6), ha="center", fontsize=7.5, color=C_SECOND)

    # Explicit swatches: matplotlib would hand back the first bar of each stack
    # as the legend handle, and that bar is hatched, which would wrongly imply
    # the hatch belongs to the series rather than marking an incomplete period.
    handles = [Patch(facecolor=C_PRIMARY), Patch(facecolor=C_CARRIED)]
    labs    = ["Newly detected this period", "Still active from earlier"]
    if any(r["onset"] or r["partial"] for r in series):
        handles.append(Patch(facecolor="white", edgecolor=C_SECOND, hatch="///"))
        labs.append("incomplete period — fewer days, not fewer attacks")
    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=9)
    ax.set_ylim(top=max(r["active"] for r in series) * 1.32)
    period_word = "week" if period == "week" else "month"
    _style(ax, f"Fraudulent ads over time (by {period_word})",
           ylabel="number of scam campaigns", window=window)
    ax.legend(handles, labs, frameon=False, fontsize=8.5, loc="upper left",
              ncol=2, columnspacing=1.2)
    return _png(fig)


# Executives do not know what "sponsored_ad" or "organic" mean as raw values.
# Say what actually happened to the customer.
PLAIN_LABEL = {
    "sponsored_ad": "Paid ads\n(criminal bought the spot)",
    "organic":      "Poisoned results\n(fake page climbed the rankings)",
    "unknown":      "Not recorded",
}


def chart_bar(items, title, color=C_PRIMARY, subtitle="", window="") -> bytes:
    fig, ax = plt.subplots(figsize=(5.2, 3.6))
    labels = [PLAIN_LABEL.get(i["label"]) or
              (i["label"].title() if i["label"] in ("google", "bing", "desktop", "mobile")
               else i["label"]) for i in items]
    counts = [i["count"] for i in items]
    x = range(len(labels))
    ax.bar(x, counts, color=color)
    for xi, c in zip(x, counts):
        ax.annotate(str(c), (xi, c), textcoords="offset points",
                    xytext=(0, 3), ha="center", fontsize=9)
    ax.set_xticks(list(x))
    ax.set_xticklabels(labels, rotation=20, ha="right", fontsize=9)
    _style(ax, title, subtitle=subtitle, ylabel="number of scam campaigns",
           window=window)
    return _png(fig)


def chart_top_domains(rows, brand, window="") -> bytes:
    fig, ax = plt.subplots(figsize=(9, max(3, 0.5 * len(rows) + 1)))
    labels = [f'{r["host"]}  ({r["engine"]})' for r in rows][::-1]
    vals   = [r["times_seen"] for r in rows][::-1]
    y = range(len(labels))
    ax.barh(y, vals, color=C_THREAT)
    for yi, v in zip(y, vals):
        ax.annotate(str(v), (v, yi), textcoords="offset points",
                    xytext=(4, 0), va="center", fontsize=9)
    ax.set_yticks(list(y))
    ax.set_yticklabels(labels, fontsize=9)
    _style(ax, f"Websites impersonating {brand}",
           subtitle="ranked by how often the fraudulent ad was seen",
           xlabel="number of times detected", window=window)
    return _png(fig)


def chart_dedup(k, window="") -> bytes:
    # A tall bar collapsing to a short one, in a threat report, reads as "we
    # removed 413 scams". Nothing was removed: the 495 sightings ARE the 82
    # campaigns, counted repeatedly. The caption has to say that outright.
    fig, ax = plt.subplots(figsize=(5.2, 3.6))
    ax.bar(["Total ad sightings", "Unique scam campaigns"], [k["raw"], k["distinct"]],
           color=[C_SECOND, C_PRIMARY])
    for xi, v in enumerate([k["raw"], k["distinct"]]):
        ax.annotate(str(v), (xi, v), textcoords="offset points",
                    xytext=(0, 3), ha="center", fontsize=10, fontweight="bold")
    _style(ax, "Cutting through repeat sightings",
           subtitle=f"the same {k['distinct']} campaigns, seen {k['raw']} times "
                    f"— {k['dedup_ratio']}x fewer to review, none removed yet",
           ylabel="count", window=window)
    return _png(fig)


# --------------------------------------------------------------------------- #
# HTML assembly
# --------------------------------------------------------------------------- #

def _img(png: bytes) -> str:
    b64 = base64.b64encode(png).decode()
    return f'<img src="data:image/png;base64,{b64}" style="max-width:100%;height:auto;">'


def _tile(value, label, accent=C_PRIMARY) -> str:
    return (f'<div class="tile"><div class="tv" style="color:{accent}">{value}</div>'
            f'<div class="tl">{label}</div></div>')


def build_html(brand, k, imgs, top_rows, window_note, window="") -> str:
    gen = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    tiles = "".join([
        _tile(k["distinct"], "Unique scam campaigns"),
        _tile(k.get("infringing", 0), "Impersonating us by name", C_THREAT),
        _tile(k.get("sponsored", 0), "Paid ads bought by criminals"),
        _tile(k.get("organic", 0), "Fake pages ranking in results"),
        _tile(k["persistent"], "Ongoing — needs escalation", C_THREAT),
        _tile(k["recently_active"], "Active in last 7 days", C_THREAT),
    ])
    rows = "".join(
        f"<tr><td>{r['host']}</td><td>{r['engine']}</td><td>{r['times_seen']}</td>"
        f"<td>{r['first']}</td><td>{r['last']}</td><td>{r['active_window']}d</td></tr>"
        for r in top_rows
    )
    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>{brand} — Brand Ad Threat Report</title>
<style>
 body{{font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
   color:#0f172a;margin:0;background:#f8fafc}}
 .wrap{{max-width:1040px;margin:0 auto;padding:28px}}
 h1{{font-size:22px;margin:0 0 4px}} h2{{font-size:16px;margin:28px 0 10px;
   border-bottom:2px solid {C_PRIMARY};padding-bottom:4px}}
 .sub{{color:#64748b;font-size:13px;margin-bottom:18px}}
 .tiles{{display:flex;flex-wrap:wrap;gap:12px}}
 .tile{{flex:1 1 150px;background:#fff;border:1px solid #e2e8f0;border-radius:10px;
   padding:14px 16px}}
 .tv{{font-size:26px;font-weight:700}} .tl{{font-size:12px;color:#64748b;margin-top:2px}}
 .charts{{display:flex;flex-wrap:wrap;gap:16px;align-items:flex-start}}
 .card{{background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:12px}}
 table{{border-collapse:collapse;width:100%;font-size:13px;background:#fff}}
 th,td{{text-align:left;padding:7px 10px;border-bottom:1px solid #eef2f7}}
 th{{color:#475569;font-size:12px;text-transform:uppercase;letter-spacing:.03em}}
 .note{{color:#64748b;font-size:12px;margin-top:8px;font-style:italic}}
 footer{{color:#94a3b8;font-size:11px;margin-top:32px;line-height:1.6}}
</style></head><body><div class="wrap">
 <h1>{brand} — Brand Ad Threat Report</h1>
 <div class="sub">Data window {window} &middot; generated {gen}</div>
 <div class="tiles">{tiles}</div>

 <h2>Fraudulent ads over time</h2>
 <div class="card">{_img(imgs['trend'])}</div>
 <div class="note">Each bar is the campaigns live that period: newly detected (dark blue) plus those
   still running from earlier (pale blue) — so the full bar height is how many were live at once.
   <b>Hatched periods are incomplete</b> and cannot be compared to the full ones: the first is
   monitoring starting up, and the last is cut short by the report date, so its shorter bar means
   fewer days measured, not fewer attacks. The count of newly detected ads also depends on how
   often the monitor runs.</div>

 <h2>How {brand} is being targeted</h2>
 <div class="charts">
   <div class="card">{_img(imgs['channel'])}</div>
   <div class="card">{_img(imgs['engine'])}</div>
   <div class="card">{_img(imgs['query'])}</div>
   <div class="card">{_img(imgs['device'])}</div>
 </div>
 <div class="note">Criminals reach our customers two different ways, and each needs a different
   response. Some <b>buy an ad</b> so their fake page sits above our real one — those go to the
   search engine's brand-protection team, and because the advertiser is a billed, verified account
   the engine can suspend the account outright, so one report can remove every ad it runs. Others
   build a fake page that <b>climbs the normal search rankings</b>; no ad was ever bought, so the
   engine has nothing to pull and will not de-rank on trademark grounds alone — the page has to be
   taken down at the company that registered the domain or that hosts it, one request per provider,
   which is slower and often needs several hops. <b>"Not recorded"</b> is not a third method: it is
   a data gap, and those campaigns cannot be routed to either process until the channel is recovered
   from the raw sighting.</div>
 <h3 style="font-size:14px;margin:18px 0 8px">Websites impersonating {brand}</h3>
 <div class="card">{_img(imgs['top'])}</div>
 <table><thead><tr><th>Website</th><th>Search engine</th><th>Times detected</th>
   <th>First seen</th><th>Last seen</th><th>How long it ran</th></tr></thead>
   <tbody>{rows}</tbody></table>

 <h2>The value of this monitoring</h2>
 <div class="charts"><div class="card">{_img(imgs['dedup'])}</div>
   <div class="card" style="flex:1 1 320px">
     <p style="font-size:14px;line-height:1.6;margin:6px 0">
     <b>{k['distinct']}</b> separate scam campaigns impersonating {brand} were caught and
     tracked. The same fraudulent ads were seen <b>{k['raw']}</b> times in total, so grouping
     repeat sightings left just <b>{k['dedup_ratio']}x</b> fewer items to review.
     <b>{k['persistent']}</b> of these were ongoing campaigns that kept running and warrant
     escalation, and the longest-running scam stayed live for <b>{k['max_window']} days</b>
     &mdash; visibility that did not exist before this monitoring.</p>
   </div></div>

 <footer>
   {window_note}<br>
   "How long it ran" is the time between the first and last time each scam was seen while
   monitoring was running &mdash; a minimum, not a measure of how quickly it was taken down.<br>
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


def print_summary(brand, k, series, group_items, group_dim, window=""):
    print(f"\n{brand} — Brand Ad Threat Report")
    print(f"  window: {window}")
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
    ap.add_argument("--period", choices=["week", "month"], default="week")
    ap.add_argument("--group-by", choices=["engine", "query", "host", "device", "channel"],
                    default="engine", dest="group_by")
    ap.add_argument("--engine", choices=["google", "bing"])
    ap.add_argument("--device", choices=["desktop", "mobile"])
    ap.add_argument("--channel", choices=["sponsored_ad", "organic"],
                    help="only paid ads, or only poisoned organic results")
    ap.add_argument("--infringing-only", action="store_true", dest="infringing_only",
                    help="only results whose title claims the brand but land off-brand")
    ap.add_argument("--top", type=int, default=10)
    ap.add_argument("--out", default="/path/to/project/reports")
    ap.add_argument("--format", choices=["html", "png", "csv", "all"], default="all")
    ap.add_argument("--summary", action="store_true",
                    help="print KPIs to stdout and exit (no files)")
    ap.add_argument("--include-triaged", action="store_true",
                    help="include analyst-triaged benign domains (excluded by default)")
    args = ap.parse_args()

    if not os.path.exists(args.db):
        print(f"No findings store at {args.db}. Run backfill_findings.py first.")
        return

    exclude = set() if args.include_triaged else load_triaged_hosts()
    cases = rd.load_cases(args.db, args.start_date, args.end_date, args.engine, args.device,
                          exclude_hosts=exclude, channel=args.channel,
                          infringing_only=args.infringing_only)
    if not cases:
        print("No cases match the given filters.")
        return
    if exclude:
        print(f"(excluding {len(exclude)} triaged benign host(s); --include-triaged to keep)")

    k       = rd.kpis(cases)
    series  = rd.trend(cases, args.period)
    # complete_data_only exists to keep an "unknown" slice from swamping the
    # DEVICE chart. Applying it to engine too gated an engine count on device
    # presence, silently dropping campaigns and leaving by_engine.csv disagreeing
    # with engine.png (which asks for the full population).
    group   = rd.breakdown(cases, args.group_by,
                           complete_data_only=(args.group_by == "device"))
    top     = rd.top_domains(cases, args.top)
    win     = window_label(*effective_window(k, args.start_date, args.end_date))

    if args.summary:
        print_summary(args.brand, k, series, group, args.group_by, win)
        return

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    # Device chart scope. n_campaigns is a CAMPAIGN count; the bars sum higher
    # because a campaign seen on both devices counts in each. Both numbers go in
    # the chart's own subtitle — the PNG gets pasted into decks without the
    # footer, so it has to reconcile its own bars.
    dev_complete = rd.breakdown(cases, "device", complete_data_only=True)
    n_campaigns = rd.count_complete_data(cases)
    n_bars      = sum(i["count"] for i in dev_complete)
    both        = n_bars - n_campaigns
    chart_note  = f"the {n_campaigns} campaigns with a device recorded"
    window_note = (f"Device breakdown covers the {n_campaigns} campaigns where both search "
                   f"engine and device were recorded (older records pre-date the device field).")
    if both > 0:
        chart_note  += f" — {both} ran on both, so bars total {n_bars}"
        window_note += (f" The {both} campaigns seen on both desktop and mobile count once in "
                        f"each bar, so the bars total {n_bars}, not {n_campaigns}.")

    # Query is multi-valued: a campaign targeting two terms counts in each bar,
    # so the bars can total more than the campaign count. Say so on the chart
    # rather than letting the sum look like an arithmetic error.
    q_items = rd.breakdown(cases, "query")
    q_note  = ("campaigns targeting more than one term count in each bar"
               if sum(i["count"] for i in q_items) > k["distinct"] else "")

    if args.format in ("png", "all", "html"):
        imgs = {
            "trend":  chart_trend(series, args.period, window=win),
            "engine": chart_bar(rd.breakdown(cases, "engine", complete_data_only=False),
                                "Fraudulent ads by search engine", window=win),
            "query":  chart_bar(q_items, "Fraudulent ads by search term targeted",
                                subtitle=q_note, window=win),
            "device": chart_bar(dev_complete,
                                "Fraudulent ads by device (desktop vs. mobile)",
                                subtitle=chart_note, window=win),
            "channel": chart_bar(
                rd.breakdown(cases, "channel"),
                "How the fake pages reached customers",
                subtitle="each needs a different kind of takedown",
                color=C_THREAT, window=win),
            "top":    chart_top_domains(top, args.brand, window=win),
            "dedup":  chart_dedup(k, window=win),
        }

    if args.format in ("png", "all"):
        for name, png in imgs.items():
            (out / f"{name}.png").write_bytes(png)
        print(f"PNG charts written to {out}/")

    if args.format in ("html", "all"):
        html = build_html(args.brand, k, imgs, top, window_note, win)
        (out / "report.html").write_text(html, encoding="utf-8")
        print(f"HTML dashboard: {out/'report.html'}")

    if args.format in ("csv", "all"):
        write_csv(out / "trend.csv",
                  ["bucket", "start", "end", "new", "carried", "active", "onset", "partial"],
                  [[r["bucket"], r["start"], r["end"], r["new"], r["carried"],
                    r["active"], r["onset"], r["partial"]] for r in series])
        write_csv(out / f"by_{args.group_by}.csv", [args.group_by, "campaigns"],
                  [[i["label"], i["count"]] for i in group])
        write_csv(out / "top_domains.csv",
                  ["host", "engine", "times_seen", "first_seen", "last_seen", "active_window_days"],
                  [[r["host"], r["engine"], r["times_seen"], r["first"], r["last"], r["active_window"]]
                   for r in top])
        write_csv(out / "kpis.csv", ["metric", "value"],
                  [[m, k[m]] for m in ("distinct", "raw", "dedup_ratio", "persistent",
                                       "avg_window", "max_window", "recently_active")])
        print(f"CSV aggregates written to {out}/")


if __name__ == "__main__":
    main()
