#!/usr/bin/env python
"""
backfill_channels.py — one-time (idempotent) classification of HISTORICAL cases.

Why this exists
---------------
Every finding recorded before the channel split is stored without one, so the
manager report counts SEO-poisoned organic results as "sponsored ad campaigns".
Measured on the current store, that overstates distinct campaigns by 38% and ad
sightings by 54%, and makes Bing look like a far bigger PAID-ads problem than it
is (53 of its 66 cases were never ads at all).

It also cannot be fixed from the stored JSON alone. Historical organic records
were extracted from a sub-node of the result rather than the result container,
so their headline is "N/A" — and the brand-infringement rule reads the headline.
The only place the real title still exists is the captured DOM snapshot.

So we replay the saved SERP DOMs through the SAME extraction path the live
monitor now uses, and write the channel + infringement verdict back onto the
matching cases.

What it does NOT do
-------------------
It does not touch fingerprints, first_seen, last_seen, times_seen, or
raw_detections. Case identity and history are preserved exactly — only the
descriptive columns are (re)computed. Safe to re-run.

Usage
-----
    ./bin/python backfill_channels.py              # classify, write, report
    ./bin/python backfill_channels.py --dry-run    # report only, write nothing
    ./bin/python backfill_channels.py --db X --evidence Y
"""
from __future__ import annotations

import argparse
import asyncio
import collections
import glob
import json
import os
import sqlite3
import sys

from playwright.async_api import async_playwright

import brandmatch
import serp_monitor as C
import findings_store
import url_resolve

DEFAULT_DB = "/path/to/project/findings.db"
DEFAULT_EVIDENCE = "/path/to/project/evidence"


async def classify_snapshot(page, path: str, engine_key: str) -> list[dict]:
    """Replay one saved SERP and return a verdict per result container."""
    html = open(path, encoding="utf-8", errors="replace").read()
    await page.set_content(html)

    engine = C.SEARCH_ENGINES[engine_key]
    blocks = []
    for sel in engine["ad_selectors"]:
        blocks = await page.query_selector_all(sel)
        if blocks:
            break

    out, seen = [], []
    for el in blocks:
        if not await C.is_valid_ad(el):
            continue
        el = await C.resolve_container(el, engine_key)

        dup = False
        for other in seen:
            try:
                if await el.evaluate("(e, o) => e === o", other):
                    dup = True
                    break
            except Exception:
                pass
        if dup:
            continue
        seen.append(el)

        channel = await C.detect_channel(el, engine_key)
        fields = await C.extract_ad_fields(el, engine_key)
        host, _ = url_resolve.suppression_host(
            display_url=fields["display_url"],
            link_href=fields["link_href"],
            link_dtld=fields["link_dtld"],
        )
        if not host:
            continue
        verdict = brandmatch.assess(
            fields["headline"], host, C.BRAND_TERMS, C.ALLOWLIST_DOMAINS)
        out.append({
            "engine": engine_key, "host": host, "channel": channel,
            "headline": fields["headline"],
            "claims_brand": verdict["claims_brand"],
            "infringing": verdict["infringing"],
        })
    return out


async def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db", default=DEFAULT_DB)
    ap.add_argument("--evidence", default=DEFAULT_EVIDENCE)
    ap.add_argument("--dry-run", action="store_true",
                    help="classify and report, but write nothing")
    args = ap.parse_args()

    # Work from the evidence RECORDS, not from the snapshots alone.
    #
    # A case's identity (primary_host) comes from the post-click landing host.
    # Replaying a DOM only yields the PRE-click host, and on Google those two
    # diverge whenever the advertiser is cloaking (48 of 103 records) — so
    # keying the replay straight to the store misses exactly the interesting
    # cases. Instead: for each stored record we already know its true host AND
    # which SERP it came from; we replay that SERP, then match the record to its
    # own result container by host, taking the record's several host spellings
    # into account.
    records = []
    for f in sorted(glob.glob(os.path.join(args.evidence, "*_flagged.json"))):
        try:
            records.extend(json.load(open(f)))
        except Exception:
            continue
    if not records:
        print(f"No flagged records under {args.evidence}", file=sys.stderr)
        return 1

    by_snap: dict[str, list[dict]] = {}
    for r in records:
        d = r.get("dom_snapshot")
        if d and os.path.exists(d) and r.get("engine") in ("google", "bing"):
            by_snap.setdefault(d, []).append(r)

    # (engine, host) -> accumulated verdict
    acc: dict[tuple[str, str], dict] = {}

    def bump(engine, host, channel, claims, infringing, headline):
        cur = acc.setdefault((engine, host),
                             {"channels": set(), "claims_brand": False,
                              "infringing": False, "headline": None})
        if channel and channel != C.CHANNEL_UNKNOWN:
            cur["channels"].add(channel)
        cur["claims_brand"] |= bool(claims)
        cur["infringing"] |= bool(infringing)
        if claims and headline and headline != "N/A":
            cur["headline"] = headline

    print(f"Replaying {len(by_snap)} DOM snapshot(s) covering {len(records)} record(s)...")
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page()
        for i, (path, recs) in enumerate(by_snap.items(), 1):
            engine_key = recs[0]["engine"]
            try:
                containers = await classify_snapshot(page, path, engine_key)
                # Page-level fallback: did this SERP carry ANY paid-ad markup?
                sponsored_sel = C.SEARCH_ENGINES[engine_key]["sponsored_container_sel"]
                page_has_ads = bool(await page.query_selector_all(sponsored_sel))
            except Exception as e:
                print(f"  skip {os.path.basename(path)}: {e}", file=sys.stderr)
                continue

            by_host = {c["host"]: c for c in containers}

            for rec in recs:
                _, engine, true_host = findings_store.fingerprint_of(rec)
                # every spelling of this record's host that could appear in the DOM
                candidates = [
                    rec.get("destination_host"),
                    C.host_of(rec.get("destination_url")),
                    C.host_of(rec.get("display_url")),
                    C.host_of(rec.get("dest_hint")),
                    rec.get("registered_host"),
                    C.host_of(rec.get("registered_url")),
                ]
                match = next((by_host[h] for h in candidates if h and h in by_host), None)

                if match:
                    bump(engine, true_host, match["channel"], match["claims_brand"],
                         match["infringing"], match["headline"])
                else:
                    # Could not tie the record to a container (DOM drift, or the
                    # landing host never appears on the SERP because of cloaking).
                    # Fall back to the page-level signal, which is still sound: a
                    # SERP with no ad markup at all cannot have produced a paid ad.
                    verdict = brandmatch.assess(
                        rec.get("headline"), true_host,
                        C.BRAND_TERMS, C.ALLOWLIST_DOMAINS)
                    bump(engine, true_host,
                         C.CHANNEL_SPONSORED if page_has_ads else C.CHANNEL_ORGANIC,
                         verdict["claims_brand"], verdict["infringing"],
                         rec.get("headline"))
            if i % 50 == 0:
                print(f"  {i}/{len(by_snap)}")
        await browser.close()

    # ---- write back ------------------------------------------------------
    conn = findings_store.connect(args.db)   # applies the column migration
    rows = conn.execute(
        "SELECT fingerprint, engine, primary_host FROM findings").fetchall()

    stats = collections.Counter()
    updates = 0
    for row in rows:
        key = (row["engine"], row["primary_host"])
        v = acc.get(key)
        if not v or not v["channels"]:
            stats["unclassified (no snapshot evidence)"] += 1
            continue
        channels = sorted(v["channels"])
        stats["+".join(channels)] += 1
        if v["infringing"]:
            stats["__infringing"] += 1
        if not args.dry_run:
            conn.execute(
                "UPDATE findings SET channels_seen = ?, last_channel = ?, "
                "claims_brand = ?, infringing = ? WHERE fingerprint = ?",
                (json.dumps(channels), channels[-1],
                 int(v["claims_brand"]), int(v["infringing"]), row["fingerprint"]),
            )
            updates += 1
    if not args.dry_run:
        conn.commit()

    print(f"\n{len(rows)} case(s) in the store")
    for k, n in sorted(stats.items()):
        if k.startswith("__"):
            continue
        print(f"  {n:4}  {k}")
    print(f"\n  {stats['__infringing']} case(s) verdict = BRAND INFRINGEMENT")
    print(f"\n{'DRY RUN — nothing written' if args.dry_run else f'{updates} case(s) updated'}")
    conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
