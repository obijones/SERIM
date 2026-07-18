#!/usr/bin/env python3
"""
backfill_findings.py — seed the campaign store from historical evidence.

Without this, a fresh findings.db shows first_seen = today for every campaign,
so the new-vs-running signal delivers nothing until days of live runs accrue.
The existing evidence/*_flagged.json files ARE the persistence history: replay
them, in chronological order, through the same record_observation() the live
monitor uses. After this, e.g. phish-example-1.com correctly reads first_seen
2026-06-26 on the very first live run.

Each *_flagged.json file is treated as one run; its run timestamp is taken from
the filename prefix (YYYYMMDD_HHMMSS), which is unique per run and sorts
chronologically. Within a file, records are grouped by fingerprint so a case
seen several times in one run counts as a single run observation.

Usage:
    python backfill_findings.py                 # seed an empty store
    python backfill_findings.py --force         # rebuild from scratch
    python backfill_findings.py --db /path/findings.db --evidence /path/evidence
"""

import argparse
import glob
import json
import os
import re
from pathlib import Path

import findings_store

DEFAULT_DB       = os.getenv("FINDINGS_DB", "/path/to/project/findings.db")
DEFAULT_EVIDENCE = os.getenv("EVIDENCE_DIR", "/path/to/project/evidence")

# evidence filenames look like 20260709_233533_flagged.json
_FNAME_TS = re.compile(r"(\d{8})_(\d{6})")


def run_ts_from_filename(path: str) -> str | None:
    """20260709_233533_flagged.json -> 2026-07-09T23:35:33Z, else None."""
    m = _FNAME_TS.search(os.path.basename(path))
    if not m:
        return None
    d, t = m.group(1), m.group(2)
    return f"{d[0:4]}-{d[4:6]}-{d[6:8]}T{t[0:2]}:{t[2:4]}:{t[4:6]}Z"


def load_records(path: str) -> list[dict]:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as e:
        print(f"  skip {os.path.basename(path)}: unreadable ({e})")
        return []
    ads = data if isinstance(data, list) else data.get("ads", [data])
    return [a for a in ads if isinstance(a, dict)]


def main() -> None:
    ap = argparse.ArgumentParser(description="Seed the campaign store from historical evidence.")
    ap.add_argument("--db", default=DEFAULT_DB)
    ap.add_argument("--evidence", default=DEFAULT_EVIDENCE)
    ap.add_argument("--force", action="store_true",
                    help="delete an existing store and rebuild from scratch")
    args = ap.parse_args()

    if os.path.exists(args.db):
        if args.force:
            os.remove(args.db)
            print(f"Removed existing store {args.db} (--force)")
        else:
            # Refuse to double-count into a populated store.
            conn = findings_store.connect(args.db)
            n = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
            conn.close()
            if n:
                print(f"Store {args.db} already holds {n} case(s). "
                      "Re-run with --force to rebuild from scratch. Aborting.")
                return

    files = sorted(glob.glob(os.path.join(args.evidence, "*_flagged.json")),
                   key=lambda p: run_ts_from_filename(p) or os.path.basename(p))
    if not files:
        print(f"No *_flagged.json files under {args.evidence} — nothing to backfill.")
        return

    conn = findings_store.connect(args.db)
    files_used = records_seen = 0
    for path in files:
        run_ts = run_ts_from_filename(path)
        if run_ts is None:
            print(f"  skip {os.path.basename(path)}: no timestamp in filename")
            continue
        records = load_records(path)
        if not records:
            continue
        findings_store.enrich_flagged(conn, records, run_ts)
        files_used   += 1
        records_seen += len(records)

    total_cases = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
    top = conn.execute(
        "SELECT primary_host, engine, times_seen, first_seen, last_seen "
        "FROM findings ORDER BY times_seen DESC LIMIT 5"
    ).fetchall()
    conn.close()

    print(f"\nBackfill complete: {records_seen} record(s) from {files_used} run file(s) "
          f"-> {total_cases} distinct case(s) in {args.db}\n")
    print("Top recurring campaigns:")
    for r in top:
        print(f"  {r['engine']}:{r['primary_host']:38s} "
              f"seen in {r['times_seen']:3d} run(s)  "
              f"first={r['first_seen'][:10]} last={r['last_seen'][:10]}")


if __name__ == "__main__":
    main()
