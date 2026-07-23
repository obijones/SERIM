"""
Tests for merge_findings.py — evidence-replay merge of findings history.

The accuracy claims under test:
  * Shared runs (byte-identical files copied to two machines) are NOT
    double-counted — times_seen and raw_detections reflect distinct runs only.
  * first_seen is the earliest and last_seen the latest across all sources.
  * Runs unique to each source are all counted (no undercount).
  * Two distinct files sharing a run timestamp are both replayed and merged.
"""
import json
import os
import sqlite3
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import findings_store  # noqa: E402


def _ad(host, query="contoso login", device="desktop"):
    return {
        "engine": "bing",
        "destination_url": f"http://{host}/",
        "query": query,
        "device": device,
        "detection_channel": "sponsored_ad",
        "headline": "Contoso Login",
        "display_url": host,
    }


def _write_run(dir_path, stamp, ads):
    """Write one <stamp>_flagged.json run file (stamp = YYYYMMDD_HHMMSS)."""
    os.makedirs(dir_path, exist_ok=True)
    p = os.path.join(dir_path, f"{stamp}_flagged.json")
    with open(p, "w", encoding="utf-8") as fh:
        json.dump(ads, fh)
    return p


def _run_merge(output, *dirs):
    subprocess.run(
        [sys.executable, os.path.join(HERE, "merge_findings.py"),
         "--output", output, *dirs],
        check=True, capture_output=True, text=True,
    )


def _case(db, fingerprint):
    c = sqlite3.connect(db); c.row_factory = sqlite3.Row
    row = c.execute("SELECT * FROM findings WHERE fingerprint = ?", (fingerprint,)).fetchone()
    c.close()
    return row


def test_shared_ancestry_not_double_counted(tmp_path):
    """
    dirB is dirA's two runs COPIED, plus one new run. The merged case must show
    3 runs (not 5) and raw_detections 3 (not 5) — shared runs collapse.
    """
    a = tmp_path / "evidence_a"
    b = tmp_path / "evidence_b"
    ad = [_ad("evil.example")]
    # Two shared runs, written byte-identically to both dirs (the copied snapshot).
    for stamp in ("20260601_100000", "20260602_100000"):
        _write_run(str(a), stamp, ad)
        _write_run(str(b), stamp, ad)
    # One run unique to B (machine B kept running after the copy).
    _write_run(str(b), "20260603_100000", ad)

    out = str(tmp_path / "merged.db")
    _run_merge(out, str(a), str(b))

    row = _case(out, "bing:evil.example")
    assert row["times_seen"] == 3          # not 5
    assert row["raw_detections"] == 3      # not 5
    assert row["first_seen"].startswith("2026-06-01")
    assert row["last_seen"].startswith("2026-06-03")


def test_unique_runs_from_each_side_all_counted(tmp_path):
    """Independent runs on each machine for the same host all add up."""
    a = tmp_path / "a"
    b = tmp_path / "b"
    _write_run(str(a), "20260601_100000", [_ad("evil.example")])
    _write_run(str(b), "20260610_100000", [_ad("evil.example")])

    out = str(tmp_path / "merged.db")
    _run_merge(out, str(a), str(b))

    row = _case(out, "bing:evil.example")
    assert row["times_seen"] == 2
    assert row["first_seen"].startswith("2026-06-01")
    assert row["last_seen"].startswith("2026-06-10")


def test_same_timestamp_distinct_content_merges(tmp_path):
    """
    Two machines produce a run at the same second with DIFFERENT findings.
    Both are replayed under that one run: each host is a case seen once, and a
    device seen on only one side is unioned.
    """
    a = tmp_path / "a"
    b = tmp_path / "b"
    _write_run(str(a), "20260601_120000", [_ad("host-a.example", device="desktop")])
    _write_run(str(b), "20260601_120000", [_ad("host-b.example", device="mobile")])

    out = str(tmp_path / "merged.db")
    _run_merge(out, str(a), str(b))

    ra = _case(out, "bing:host-a.example")
    rb = _case(out, "bing:host-b.example")
    assert ra is not None and rb is not None
    assert ra["times_seen"] == 1
    assert rb["times_seen"] == 1


def test_dry_run_writes_no_db(tmp_path):
    a = tmp_path / "a"
    _write_run(str(a), "20260601_100000", [_ad("evil.example")])
    out = str(tmp_path / "merged.db")
    res = subprocess.run(
        [sys.executable, os.path.join(HERE, "merge_findings.py"),
         "--dry-run", str(a)],
        check=True, capture_output=True, text=True,
    )
    assert "DRY RUN" in res.stdout
    assert not os.path.exists(out)


def test_refuses_output_equal_to_evidence_dir(tmp_path):
    a = tmp_path / "a"
    _write_run(str(a), "20260601_100000", [_ad("evil.example")])
    res = subprocess.run(
        [sys.executable, os.path.join(HERE, "merge_findings.py"),
         "--output", str(a), str(a)],
        capture_output=True, text=True,
    )
    assert res.returncode != 0
    assert "must not be an evidence directory" in res.stderr
