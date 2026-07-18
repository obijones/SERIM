"""
Regression tests for report_data.py — the pure aggregation behind the Lens #3
report. Offline: builds a temp findings.db, no matplotlib. Run with `pytest`.
"""

import json
import os
import sqlite3
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import report_data as rd
import findings_store as fs


@pytest.fixture
def db(tmp_path):
    path = str(tmp_path / "findings.db")
    conn = fs.connect(path)

    def add(fp, engine, host, first, last, times, raw, devices, queries):
        conn.execute(
            "INSERT INTO findings (fingerprint, engine, primary_host, first_seen, "
            "last_seen, times_seen, raw_detections, devices_seen, queries_seen, status) "
            "VALUES (?,?,?,?,?,?,?,?,?, 'open')",
            (fp, engine, host, first, last, times, raw,
             json.dumps(devices), json.dumps(queries)),
        )

    # A: persistent, multi-device, spans two ISO weeks
    add("bing:a.com", "bing", "a.com", "2026-06-23T10:00:00Z", "2026-07-02T10:00:00Z",
        5, 40, ["desktop", "mobile"], ["contoso account login"])
    # B: one-off new campaign, later week
    add("google:b.com", "google", "b.com", "2026-07-01T10:00:00Z", "2026-07-01T10:00:00Z",
        1, 1, ["desktop"], ["contoso online portal"])
    # C: old-format record — no engine, no device (the "unknown" case)
    add("unknown:c.com", None, "c.com", "2026-06-24T10:00:00Z", "2026-06-24T10:00:00Z",
        2, 3, [], [])
    conn.commit()
    conn.close()
    return path


def test_load_and_kpis(db):
    cases = rd.load_cases(db)
    assert len(cases) == 3
    k = rd.kpis(cases)
    assert k["distinct"] == 3
    assert k["raw"] == 44
    assert k["dedup_ratio"] == round(44 / 3, 1)
    assert k["persistent"] == 1               # only A has times_seen >= 3
    assert k["max_window"] == 9               # A: 06-23 -> 07-02
    assert set(k["engines"]) == {"bing", "google"}


def test_trend_flags_onset_and_counts_active(db):
    cases = rd.load_cases(db)
    series = rd.trend(cases, "week")
    assert series[0]["onset"] is True         # first bucket is ramp-up
    assert sum(r["new"] for r in series) == 3  # every case is "new" once
    # A spans multiple weeks -> counted active in more than one bucket
    active_buckets = [r for r in series if r["active"] > 0]
    assert len(active_buckets) >= 2


def test_trend_stacks_and_flags_partial_buckets(db):
    series = rd.trend(rd.load_cases(db), "week")
    # active CONTAINS new, so the two stack: new + carried == active everywhere.
    assert all(r["new"] + r["carried"] == r["active"] for r in series)
    assert all(r["carried"] >= 0 for r in series)
    # Both edges are flagged when the data starts/ends mid-bucket, not just the
    # first — a trailing short bucket must never read as a decline.
    assert series[0]["partial"] is True
    assert series[-1]["partial"] is True
    # start/end are clipped to the data, so a label can name real dates.
    assert series[0]["start"] == min(c["first"] for c in rd.load_cases(db)).isoformat()
    assert series[-1]["end"] == max(c["last"] for c in rd.load_cases(db)).isoformat()


def test_count_complete_data_is_campaigns_not_bar_total(db):
    cases = rd.load_cases(db)
    # A ran on desktop+mobile, B on desktop, C has no device -> 2 campaigns,
    # but the device bars total 3. The "N campaigns" label must use the former.
    assert rd.count_complete_data(cases) == 2
    assert sum(i["count"] for i in
               rd.breakdown(cases, "device", complete_data_only=True)) == 3


def test_engine_breakdown_has_unknown(db):
    cases = rd.load_cases(db)
    full = {i["label"]: i["count"] for i in rd.breakdown(cases, "engine")}
    assert full.get("unknown") == 1           # the old-format record surfaces
    # complete-data-only drops the unknown-engine case
    scoped = {i["label"]: i["count"] for i in
              rd.breakdown(cases, "engine", complete_data_only=True)}
    assert "unknown" not in scoped


def test_device_breakdown_complete_data_only(db):
    cases = rd.load_cases(db)
    scoped = {i["label"]: i["count"] for i in
              rd.breakdown(cases, "device", complete_data_only=True)}
    # A (desktop+mobile) and B (desktop) count; C (no device) excluded
    assert scoped == {"desktop": 2, "mobile": 1}


def test_filters(db):
    assert len(rd.load_cases(db, engine="bing")) == 1
    assert len(rd.load_cases(db, device="mobile")) == 1
    # window filter: exclude everything before July -> only B remains as "first in window"
    since_july = rd.load_cases(db, since="2026-07-03")
    assert all(c["last"].isoformat() >= "2026-07-03" for c in since_july)


def test_top_domains_ordered_by_persistence(db):
    top = rd.top_domains(rd.load_cases(db), n=10)
    assert top[0]["host"] == "a.com"          # highest times_seen first
    assert top[0]["active_window"] == 9


def test_empty_kpis_do_not_crash():
    k = rd.kpis([])
    assert k["distinct"] == 0 and k["dedup_ratio"] == 0.0
    assert rd.trend([], "week") == []
