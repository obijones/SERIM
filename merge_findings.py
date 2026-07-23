#!/usr/bin/env python3
"""
merge_findings.py — merge campaign history from multiple machines by replaying
their COMBINED evidence into a single fresh findings DB. This is the most
accurate way to combine findings.db files.

Why replay instead of a row-level DB merge
------------------------------------------
findings.db rows are AGGREGATES (times_seen, raw_detections, seen-sets). When
two DBs share ancestry — e.g. one started as a copy of the other — summing those
aggregates double-counts every shared run, and taking the max undercounts runs
unique to each side. Neither can recover the truth from aggregates alone.

The evidence *_flagged.json files ARE the ground-truth per-run events: each file
is one run, keyed by its filename timestamp (YYYYMMDD_HHMMSS). Replaying their
union through the same record_observation() the live monitor uses reconstructs
exact run counts, earliest first_seen, latest last_seen, sticky attribution, and
correct de-duplication of shared runs.

What makes this maximally accurate
----------------------------------
  * Every *_flagged.json across ALL given directories is considered — unlike
    copying files into one folder, where two same-named files silently overwrite
    and one machine's run is lost.
  * Byte-identical files (the same run copied to two machines) are de-duplicated
    by content hash, so a shared run's detections are not counted twice.
  * Distinct files that happen to share a run timestamp are BOTH replayed; the
    store treats them as one run (times_seen counted once) while unioning their
    detections / devices / queries — the correct outcome for two machines
    observing the same run-second.
  * Files are replayed in chronological (run-timestamp) order, so first_seen and
    last_seen land correctly.

Requires the *_flagged.json files to be retained. Runs whose evidence was pruned
cannot be reconstructed — see --dry-run to check coverage before committing.

Usage:
    python merge_findings.py --output merged.db  EVIDENCE_DIR_A  EVIDENCE_DIR_B [...]
    python merge_findings.py --output merged.db --force  dirA dirB   # overwrite output
    python merge_findings.py --dry-run  dirA dirB                    # report only, no write
"""
import argparse
import glob
import hashlib
import os
import sys
from pathlib import Path

import findings_store
# Reuse the exact run-timestamp parsing and record loading the backfill uses, so
# a merge counts runs identically to how the DBs were originally built.
from backfill_findings import run_ts_from_filename, load_records


def _sha256(path: str) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def collect_runs(evidence_dirs: list[str]) -> tuple[list[tuple[str, str]], dict]:
    """
    Gather every *_flagged.json across the given directories, de-duplicating
    byte-identical files (the same run copied to more than one machine).

    Returns (runs, stats) where runs is a list of (run_ts, path) sorted
    chronologically, and stats records what was found/skipped for reporting.
    """
    stats = {
        "dirs_missing":   [],
        "files_seen":     0,
        "dup_skipped":    0,   # byte-identical copies collapsed
        "no_timestamp":   0,   # filename lacked YYYYMMDD_HHMMSS
        "distinct_files": 0,
    }
    # De-dup key is (run timestamp, content hash): the SAME run copied to two
    # machines shares both. Two runs at different times with identical findings
    # (same ad seen on two days) differ in timestamp and are kept as two runs.
    # Two files at the same run-second with different findings differ in hash and
    # are both kept — the store merges them under that one run.
    seen_keys: set[tuple[str, str]] = set()
    runs: list[tuple[str, str]] = []

    for d in evidence_dirs:
        if not os.path.isdir(d):
            stats["dirs_missing"].append(d)
            continue
        for path in sorted(glob.glob(os.path.join(d, "*_flagged.json"))):
            stats["files_seen"] += 1
            run_ts = run_ts_from_filename(path)
            if run_ts is None:
                stats["no_timestamp"] += 1
                print(f"  skip {os.path.basename(path)}: no timestamp in filename")
                continue
            key = (run_ts, _sha256(path))
            if key in seen_keys:
                stats["dup_skipped"] += 1        # identical run already taken
                continue
            seen_keys.add(key)
            runs.append((run_ts, path))

    # Chronological order; path as a stable tiebreak for same-timestamp files.
    runs.sort(key=lambda rp: (rp[0], rp[1]))
    stats["distinct_files"] = len(runs)
    return runs, stats


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Merge findings history by replaying combined evidence into a fresh DB.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("evidence_dirs", nargs="+",
                    help="One or more evidence directories (each holding *_flagged.json).")
    ap.add_argument("--output",
                    help="Path for the fresh merged findings DB. Required unless --dry-run.")
    ap.add_argument("--force", action="store_true",
                    help="Overwrite --output if it already exists.")
    ap.add_argument("--dry-run", action="store_true",
                    help="Report coverage (files, duplicates, date range) without writing a DB.")
    args = ap.parse_args()

    if not args.dry_run and not args.output:
        ap.error("--output is required unless --dry-run is given.")

    # Guard: never let --output be one of the evidence directories.
    if args.output:
        out_abs = os.path.abspath(args.output)
        for d in args.evidence_dirs:
            if os.path.abspath(d) == out_abs:
                ap.error(f"--output {args.output} must not be an evidence directory.")

    runs, stats = collect_runs(args.evidence_dirs)

    for d in stats["dirs_missing"]:
        print(f"  WARNING: not a directory, skipped: {d}")

    print(
        f"\nScanned {len(args.evidence_dirs)} dir(s): {stats['files_seen']} file(s) seen, "
        f"{stats['dup_skipped']} identical copy(ies) collapsed, "
        f"{stats['no_timestamp']} without a timestamp.\n"
        f"{stats['distinct_files']} distinct run file(s) to replay."
    )
    if not runs:
        print("Nothing to replay — no usable *_flagged.json found.")
        return
    print(f"Run range: {runs[0][0]}  ->  {runs[-1][0]}")

    if args.dry_run:
        print("\n[DRY RUN] No DB written. Re-run with --output to build the merged DB.")
        return

    if os.path.exists(args.output):
        if args.force:
            os.remove(args.output)
            print(f"Removed existing {args.output} (--force)")
        else:
            print(f"Refusing to overwrite existing {args.output}. Use --force. Aborting.")
            return

    conn = findings_store.connect(args.output)
    records_seen = files_used = 0
    for run_ts, path in runs:
        records = load_records(path)
        if not records:
            continue
        findings_store.enrich_flagged(conn, records, run_ts)
        files_used   += 1
        records_seen += len(records)

    total_cases = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
    top = conn.execute(
        "SELECT primary_host, engine, times_seen, first_seen, last_seen "
        "FROM findings ORDER BY times_seen DESC LIMIT 10"
    ).fetchall()
    conn.close()

    print(
        f"\nMerge complete: {records_seen} record(s) from {files_used} run file(s) "
        f"-> {total_cases} distinct case(s) in {args.output}\n"
    )
    print("Top recurring campaigns:")
    for r in top:
        print(f"  {r['engine']}:{r['primary_host']:38s} "
              f"seen in {r['times_seen']:3d} run(s)  "
              f"first={r['first_seen'][:10]} last={r['last_seen'][:10]}")


if __name__ == "__main__":
    main()
