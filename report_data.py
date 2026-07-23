"""
report_data.py — pure aggregation for the manager metrics report (Lens #3).

Reads the findings.db campaign store and produces the numbers behind every
chart. No matplotlib, no I/O beyond the SQLite read, so it is unit-testable
offline against a temp DB (tests/test_report.py) — the rendering lives in
report.py.

Design notes / honesty rules encoded here (not cosmetic — they keep the exec
charts from lying):
  - The FIRST period in any trend is the monitoring onset/ramp-up; it is
    flagged (onset=True) so the renderer can annotate/exclude it. Early volume
    reflects coverage coming online, not a real attack surge.
  - Any bucket the data only partly covers is flagged (partial=True) — at BOTH
    ends. A trailing bucket cut short by the report date has fewer days, not
    fewer attacks, and must never be read as a decline.
  - Device/engine are missing on older records (pre-dating those fields).
    breakdown() reports an explicit "unknown" bucket; device breakdown is
    scoped to the complete-data window via complete_data_only=True.
  - The active span is reported as "observed active window" (last_seen -
    first_seen), a monitoring-bounded lower bound — never "time to takedown".
"""

from __future__ import annotations

import json
import sqlite3
from datetime import date, timedelta

# Kept in sync with findings_store.PERSISTENT_MIN_RUNS; imported lazily so this
# module has zero hard dependency on the store beyond the DB schema.
try:
    from findings_store import PERSISTENT_MIN_RUNS
except Exception:  # pragma: no cover
    PERSISTENT_MIN_RUNS = 3

RECENT_DAYS = 7  # "recently active" = last seen within this many days of latest data


def _col(row, name):
    """Tolerant column read — a store predating the channel migration lacks these."""
    try:
        return row[name]
    except (IndexError, KeyError):
        return None


def _d(ts: str | None) -> date | None:
    if not ts:
        return None
    try:
        return date.fromisoformat(ts[:10])
    except ValueError:
        return None


def load_cases(
    db_path: str,
    since: str | None = None,
    until: str | None = None,
    engine: str | None = None,
    device: str | None = None,
    exclude_hosts: set[str] | None = None,
    channel: str | None = None,
    infringing_only: bool = False,
    fi_hosts: set[str] | None = None,
) -> list[dict]:
    """
    Loads normalized case rows from findings.db with optional filters.
    since/until are inclusive YYYY-MM-DD bounds applied to last_seen/first_seen
    (a case is included if its active window overlaps the window).

    exclude_hosts: analyst-adjudicated benign hosts (the triage list) to drop,
    matched exact-host — the store records every historical flag, including
    domains later triaged benign, which must not appear as "threats" in a
    manager report. Matching mirrors the monitor's exact-host triage semantics.

    fi_hosts: the known-legitimate FI registry (fi_registry.load_hosts). Cases
    are ANNOTATED with a review_state, never dropped — scoping is the caller's
    decision, so a report can still show what it excluded. The state is computed
    here at read time rather than read from a stored column, so adding an
    institution to the registry retroactively cleans historical metrics; the
    rule itself lives in fi_registry so the alert email applies the same one.
    """
    from domainmatch import host_in  # local import: keep this module import-light
    import fi_registry

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM findings").fetchall()
    conn.close()

    exclude_hosts = exclude_hosts or set()
    fi_hosts = fi_hosts or set()
    since_d, until_d = _d(since), _d(until)
    cases = []
    for r in rows:
        first, last = _d(r["first_seen"]), _d(r["last_seen"])
        if first is None or last is None:
            continue
        if exclude_hosts and host_in(r["primary_host"], exclude_hosts, exact=True):
            continue
        # window overlap filter
        if since_d and last < since_d:
            continue
        if until_d and first > until_d:
            continue
        eng = r["engine"] if r["engine"] in ("google", "bing") else "unknown"
        devices = json.loads(r["devices_seen"] or "[]")
        queries = json.loads(r["queries_seen"] or "[]")
        channels = json.loads(_col(r, "channels_seen") or "[]")
        infringing = bool(_col(r, "infringing"))
        if engine and eng != engine:
            continue
        if device and device not in devices:
            continue
        if channel and channel not in channels:
            continue
        if infringing_only and not infringing:
            continue
        host = r["primary_host"]
        cases.append({
            "fingerprint":   r["fingerprint"],
            "engine":        eng,
            "host":          host,
            "review_state":  fi_registry.review_state(infringing, host, fi_hosts),
            "conflict":      fi_registry.is_conflict(infringing, host, fi_hosts),
            "first":         first,
            "last":          last,
            "times_seen":    r["times_seen"] or 0,
            "raw":           r["raw_detections"] or 0,
            "devices":       devices,
            "queries":       queries,
            "channels":      channels,
            "infringing":    infringing,
            "active_window": (last - first).days,
        })
    return cases


def by_state(cases: list[dict], state: str) -> list[dict]:
    """The subset of cases in one review state (fi_registry.THREAT/…)."""
    return [c for c in cases if c.get("review_state") == state]


def review_summary(cases: list[dict]) -> dict:
    """
    The three-state census, plus registry conflicts.

    Call this on the UNSCOPED population — it is the denominator that makes a
    scoped threat count honest. `unreviewed` is reported as a work queue, not
    rolled into either of the other two: it holds legitimate businesses nobody
    has adjudicated yet AND any threat the title heuristic missed, so hiding it
    would hide the recall gap. threats + legitimate + unreviewed == total.
    """
    import fi_registry

    counts = {s: 0 for s in fi_registry.STATES}
    for c in cases:
        st = c.get("review_state", fi_registry.UNREVIEWED)
        counts[st] = counts.get(st, 0) + 1
    return {
        "threats":     counts[fi_registry.THREAT],
        "legitimate":  counts[fi_registry.LEGITIMATE],
        "unreviewed":  counts[fi_registry.UNREVIEWED],
        "total":       len(cases),
        # Infringing AND on the registry — stays counted as a threat, but needs
        # a human: either brandmatch mis-fired, or a real institution's domain
        # has been compromised.
        "conflicts":   sum(1 for c in cases if c.get("conflict")),
    }


def bucket_key(d: date, period: str) -> str:
    if period == "month":
        return f"{d.year:04d}-{d.month:02d}"
    y, w, _ = d.isocalendar()
    return f"{y:04d}-W{w:02d}"


def bucket_bounds(key: str, period: str) -> tuple[date, date]:
    """The nominal calendar span a bucket key covers (ignoring data coverage)."""
    if period == "month":
        y, m = int(key[:4]), int(key[5:7])
        nxt = date(y + (m == 12), (m % 12) + 1, 1)
        return date(y, m, 1), nxt - timedelta(days=1)
    y, w = int(key[:4]), int(key[6:8])
    return date.fromisocalendar(y, w, 1), date.fromisocalendar(y, w, 7)


def _buckets_spanning(d1: date, d2: date, period: str) -> list[str]:
    keys, seen, cur = [], set(), d1
    while cur <= d2:
        k = bucket_key(cur, period)
        if k not in seen:
            seen.add(k)
            keys.append(k)
        cur += timedelta(days=1)
    return keys


def trend(cases: list[dict], period: str = "week") -> list[dict]:
    """
    Per-period series: new campaigns (by first_seen) and active campaigns
    (window overlaps the bucket). The earliest bucket is flagged onset=True.

    'active' CONTAINS 'new' — a campaign new in a period is also active in it —
    so 'carried' (active - new) is the count still running from earlier periods,
    and new + carried == active. They stack; they are not independent series.

    'start'/'end' are the bucket's real covered span, clipped to the data, so a
    label can name actual dates instead of an ISO key. 'partial' marks a bucket
    the data only partly covers, at either end.

    Returns rows ordered chronologically:
    {bucket, start, end, new, active, carried, onset, partial}.
    """
    if not cases:
        return []
    lo = min(c["first"] for c in cases)
    hi = max(c["last"] for c in cases)
    all_buckets = _buckets_spanning(lo, hi, period)

    new_counts = {b: 0 for b in all_buckets}
    active_counts = {b: 0 for b in all_buckets}
    for c in cases:
        new_counts[bucket_key(c["first"], period)] += 1
        for b in _buckets_spanning(c["first"], c["last"], period):
            active_counts[b] += 1

    rows = []
    for i, b in enumerate(all_buckets):
        b_start, b_end = bucket_bounds(b, period)
        rows.append({
            "bucket":  b,
            "start":   max(b_start, lo).isoformat(),
            "end":     min(b_end, hi).isoformat(),
            "new":     new_counts[b],
            "active":  active_counts[b],
            "carried": active_counts[b] - new_counts[b],
            "onset":   (i == 0),
            "partial": b_start < lo or b_end > hi,
        })
    return rows


def _has_complete_data(c: dict) -> bool:
    """Both engine and device known — the scope the device chart reports on."""
    return c["engine"] in ("google", "bing") and bool(c["devices"])


def count_complete_data(cases: list[dict]) -> int:
    """How many CAMPAIGNS have both engine and device recorded.

    Deliberately distinct from the device breakdown's bar total: a campaign seen
    on both desktop and mobile is one campaign here but counts in each bar, so
    the bars sum higher. Callers labelling the device chart must use this for any
    "N campaigns" claim.
    """
    return sum(1 for c in cases if _has_complete_data(c))


def breakdown(cases: list[dict], dimension: str,
              complete_data_only: bool = False) -> list[dict]:
    """
    Case counts by a dimension: 'engine', 'query', 'host', or 'device'.
    For multi-valued attributes (device, query) a case counts toward each value.
    'engine'/'host' include an explicit 'unknown' where data is missing.
    complete_data_only restricts device/engine to cases having BOTH, so the
    device chart is not dominated by an "unknown" slice.
    """
    counts: dict[str, int] = {}

    def bump(k):
        counts[k] = counts.get(k, 0) + 1

    for c in cases:
        if complete_data_only and not _has_complete_data(c):
            continue
        if dimension == "engine":
            bump(c["engine"])
        elif dimension == "host":
            bump(c["host"] or "unknown")
        elif dimension == "device":
            if c["devices"]:
                for d in c["devices"]:
                    bump(d)
            else:
                bump("unknown")
        elif dimension == "query":
            if c["queries"]:
                for q in c["queries"]:
                    bump(q)
            else:
                bump("unknown")
        elif dimension == "channel":
            if c.get("channels"):
                for ch in c["channels"]:
                    bump(ch)
            else:
                bump("unknown")
        else:
            raise ValueError(f"unknown dimension: {dimension}")

    return sorted(
        [{"label": k, "count": v} for k, v in counts.items()],
        key=lambda x: (-x["count"], x["label"]),
    )


def top_domains(cases: list[dict], n: int = 10) -> list[dict]:
    ranked = sorted(cases, key=lambda c: (-c["times_seen"], -c["raw"], c["host"] or ""))
    return [
        {"host": c["host"], "engine": c["engine"], "times_seen": c["times_seen"],
         "first": c["first"].isoformat(), "last": c["last"].isoformat(),
         "active_window": c["active_window"]}
        for c in ranked[:n]
    ]


def kpis(cases: list[dict]) -> dict:
    """Headline numbers: threat-exposure + operational-efficiency."""
    if not cases:
        return {"distinct": 0, "raw": 0, "dedup_ratio": 0.0, "persistent": 0,
                "avg_window": 0.0, "max_window": 0, "recently_active": 0,
                "engines": [], "queries": [],
                "sponsored": 0, "organic": 0, "infringing": 0}
    distinct = len(cases)
    raw = sum(c["raw"] for c in cases)
    windows = [c["active_window"] for c in cases]
    latest = max(c["last"] for c in cases)
    engines = sorted({c["engine"] for c in cases if c["engine"] in ("google", "bing")})
    queries = sorted({q for c in cases for q in c["queries"]})
    return {
        "distinct":        distinct,
        "raw":             raw,
        "dedup_ratio":     round(raw / distinct, 1) if distinct else 0.0,
        "persistent":      sum(1 for c in cases if c["times_seen"] >= PERSISTENT_MIN_RUNS),
        "avg_window":      round(sum(windows) / distinct, 1),
        "max_window":      max(windows),
        "recently_active": sum(1 for c in cases if (latest - c["last"]).days <= RECENT_DAYS),
        "engines":         engines,
        "queries":         queries,
        # Channel split. "sponsored" and "organic" are not exclusive — one host
        # can be reached both ways — so they need not sum to `distinct`.
        "sponsored":       sum(1 for c in cases if "sponsored_ad" in c.get("channels", [])),
        "organic":         sum(1 for c in cases if "organic" in c.get("channels", [])),
        "infringing":      sum(1 for c in cases if c.get("infringing")),
        "latest_date":     latest.isoformat(),
        "earliest_date":   min(c["first"] for c in cases).isoformat(),
    }
