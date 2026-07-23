"""
Regression tests for findings_store.py — dedup, case identity, first/last-seen.

Offline: uses a temp SQLite DB, no browser, no network. Run with `pytest tests/`.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import findings_store as fs


@pytest.fixture
def conn(tmp_path):
    c = fs.connect(str(tmp_path / "findings.db"))
    yield c
    c.close()


def ad(engine="google", dest=None, disp=None, device="desktop", query="contoso account login",
       headline="Contoso Account - Log In"):
    return {"engine": engine, "destination_url": dest, "display_url": disp,
            "device": device, "query": query, "headline": headline}


# --------------------------------------------------------------------------- #
# fingerprint identity
# --------------------------------------------------------------------------- #

def test_destination_is_primary_key():
    fp, engine, host = fs.fingerprint_of(ad(dest="https://phish-example-1.com/x/login",
                                            disp="phish-example-1.com › x"))
    assert fp == "google:phish-example-1.com"
    assert host == "phish-example-1.com"


def test_falls_back_to_display_when_destination_missing():
    fp, _, host = fs.fingerprint_of(ad(dest=None, disp="https://contoso-login.com › blog"))
    assert host == "contoso-login.com"
    assert fp == "google:contoso-login.com"


def test_resolve_and_no_resolve_map_to_same_case():
    # Same campaign: one run resolved the destination, another didn't. Both
    # must land in one case (display host == destination host here).
    a = fs.fingerprint_of(ad(dest="https://phish-example-1.com/x", disp="phish-example-1.com › x"))[0]
    b = fs.fingerprint_of(ad(dest=None, disp="https://phish-example-1.com › x"))[0]
    assert a == b


def test_different_destinations_are_distinct_cases():
    # One display domain fanning out to two landing pages = two takedown targets.
    a = fs.fingerprint_of(ad(dest="https://phish-example-2.info", disp="phish-example-2.info"))[0]
    b = fs.fingerprint_of(ad(dest="https://phish-example-3.top", disp="phish-example-2.info"))[0]
    assert a != b


# --------------------------------------------------------------------------- #
# first / last seen and run counting
# --------------------------------------------------------------------------- #

def test_new_case(conn):
    rec = fs.record_observation(conn, [ad(dest="https://a.com")], "2026-07-01T10:00:00Z")
    assert rec["is_new"] is True
    assert rec["times_seen"] == 1
    assert rec["first_seen"] == rec["last_seen"] == "2026-07-01T10:00:00Z"
    assert rec["status"] == "NEW"


def test_recurring_advances_last_seen_keeps_first(conn):
    fs.record_observation(conn, [ad(dest="https://a.com")], "2026-07-01T10:00:00Z")
    rec = fs.record_observation(conn, [ad(dest="https://a.com")], "2026-07-03T10:00:00Z")
    assert rec["is_new"] is False
    assert rec["times_seen"] == 2
    assert rec["first_seen"] == "2026-07-01T10:00:00Z"   # unchanged
    assert rec["last_seen"]  == "2026-07-03T10:00:00Z"   # advanced
    assert rec["age_days"] == 2


def test_same_run_does_not_double_count(conn):
    # Same fingerprint recorded twice under one run_ts -> still one run.
    fs.record_observation(conn, [ad(dest="https://a.com")], "2026-07-01T10:00:00Z")
    rec = fs.record_observation(conn, [ad(dest="https://a.com")], "2026-07-01T10:00:00Z")
    assert rec["times_seen"] == 1


def test_reappearance_after_quiet_stays_same_case(conn):
    # Resurfaces days later — keeps first_seen, advances last_seen (same case).
    fs.record_observation(conn, [ad(dest="https://a.com")], "2026-06-20T10:00:00Z")
    fs.record_observation(conn, [ad(dest="https://a.com")], "2026-06-21T10:00:00Z")
    rec = fs.record_observation(conn, [ad(dest="https://a.com")], "2026-07-01T10:00:00Z")
    assert rec["first_seen"] == "2026-06-20T10:00:00Z"
    assert rec["times_seen"] == 3


def test_persistent_status_and_attribute_merge(conn):
    # 3 runs across >=2 days -> PERSISTENT; devices accumulate across runs.
    fs.record_observation(conn, [ad(dest="https://a.com", device="desktop")], "2026-07-01T10:00:00Z")
    fs.record_observation(conn, [ad(dest="https://a.com", device="mobile")],  "2026-07-02T10:00:00Z")
    rec = fs.record_observation(conn, [ad(dest="https://a.com", device="mobile")], "2026-07-04T10:00:00Z")
    assert rec["status"] == "PERSISTENT"
    assert rec["devices_seen"] == ["desktop", "mobile"]


# --------------------------------------------------------------------------- #
# enrich_flagged — within-run dedup + in-place annotation
# --------------------------------------------------------------------------- #

def test_enrich_collapses_and_annotates(conn):
    flagged = [
        ad(dest="https://a.com", device="desktop"),
        ad(dest="https://a.com", device="mobile"),   # same case, different device
        ad(dest="https://b.com", device="desktop"),
    ]
    cases = fs.enrich_flagged(conn, flagged, "2026-07-01T10:00:00Z")
    assert len(cases) == 2                       # 3 detections -> 2 distinct cases
    assert flagged[0]["fingerprint"] == flagged[1]["fingerprint"]
    assert flagged[0]["times_seen"] == 1
    assert flagged[0]["is_new"] is True
    # the collapsed case saw both devices this run
    assert cases[flagged[0]["fingerprint"]]["devices_seen"] == ["desktop", "mobile"]
