"""
findings_store.py — campaign dedup, case identity, and first/last-seen tracking.

Closes Lens #1 gap #4: without this, every run re-flags the same live ad and
writes a fresh record (phish-example-1.com appeared 61× across 185 files), so an
analyst cannot tell "new campaign today" from "same campaign running 13 days."

Case identity (fingerprint) is  engine : destination-host  where the host is
host_of(destination_url), falling back to host_of(display_url) when the click
did not resolve, else "unresolved". Validated against 403 historical records:
destination-primary keying produced zero over-collapse (no single key mapping
to multiple real landing domains), whereas display-primary wrongly merged one
ad's two distinct phishing landing pages into a single case.

Device and query are case ATTRIBUTES (devices_seen / queries_seen), not part of
identity — otherwise one desktop+mobile campaign would split into two cases and
defeat the dedup. Engine IS in the key: Google and Bing takedowns differ.

Pure-ish and dependency-light (stdlib sqlite3 + domainmatch) so it is unit
testable against a temp DB with no browser. The caller wraps use in try/except
and fails OPEN — a store error must never block an alert.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone

from domainmatch import host_of

# Escalation trigger — a campaign seen in at least this many runs across at
# least this many days is flagged PERSISTENT for analyst escalation. Tunable
# here in one place; surfaced in the alert email's persistence block.
PERSISTENT_MIN_RUNS = 3
PERSISTENT_MIN_DAYS = 2

_SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    fingerprint          TEXT PRIMARY KEY,
    engine               TEXT,
    primary_host         TEXT,
    first_seen           TEXT,
    last_seen            TEXT,
    times_seen           INTEGER,   -- number of RUNS the case appeared in (not raw detections)
    raw_detections       INTEGER,   -- cumulative individual ad records observed
    devices_seen         TEXT,      -- JSON list
    queries_seen         TEXT,      -- JSON list
    last_headline        TEXT,
    last_display_url     TEXT,
    last_destination_url TEXT,
    last_evidence_json   TEXT,
    -- reserved for Manager reporting (priority #2); not populated by this module
    status               TEXT DEFAULT 'open',
    advertiser           TEXT,
    country              TEXT
)
"""

# Columns added after the table shipped. Applied by _migrate() on every connect
# so an existing findings.db is upgraded in place and first_seen history — the
# whole point of the store — survives.
#
# channels_seen is an ATTRIBUTE, not part of the fingerprint, for the same
# reason device is: a host that appears both as a paid ad and as a poisoned
# organic result is ONE campaign reached two ways, and splitting it would
# defeat the dedup and reset its first_seen.
_MIGRATIONS = {
    "channels_seen":   "TEXT DEFAULT '[]'",  # JSON list: sponsored_ad / organic
    "last_channel":    "TEXT",
    "claims_brand":    "INTEGER DEFAULT 0",
    "infringing":      "INTEGER DEFAULT 0",  # title claims the brand, host is not ours
    # Attribution (v8). Persisted as first-class columns so the durable
    # identifiers survive beyond the ephemeral alert/JSON and can be queried for
    # reporting. All are STICKY: once captured, a later run that failed to
    # capture (ad went dark, panel didn't open, ATC withdrew the creative) must
    # not null them back out. See _best_attribution().
    "gad_campaignid":         "TEXT",     # Google campaign id (from tracking_id)
    "atc_advertiser_name":    "TEXT",     # Ads Transparency Center advertiser
    "atc_advertiser_verified":"INTEGER DEFAULT 0",
    "atc_advertiser_id":      "TEXT",     # AR… stable advertiser account id
    "atc_creative_id":        "TEXT",     # CR… stable ad/creative id
    "atc_creative_url":       "TEXT",     # permalink to the ATC creative record
    "atc_ad_count":           "TEXT",     # ads retained for the domain in ATC
    "atc_screenshot":         "TEXT",     # evidence screenshot path
}

# Attribution columns, in a fixed order reused by SELECT / INSERT / UPDATE and
# the sticky-merge below. Keeps the three SQL statements from drifting apart.
# The existing advertiser/country columns (My Ad Center panel) are included so
# they finally get populated — they shipped in the base schema but no code ever
# wrote to them.
_ATTR_COLUMNS = (
    "advertiser", "country",
    "gad_campaignid",
    "atc_advertiser_name", "atc_advertiser_verified", "atc_advertiser_id",
    "atc_creative_id", "atc_creative_url", "atc_ad_count", "atc_screenshot",
)


def _migrate(conn: sqlite3.Connection) -> None:
    have = {r["name"] for r in conn.execute("PRAGMA table_info(findings)")}
    for col, decl in _MIGRATIONS.items():
        if col not in have:
            conn.execute(f"ALTER TABLE findings ADD COLUMN {col} {decl}")


def connect(db_path: str) -> sqlite3.Connection:
    """Opens (creating if needed) the findings DB and ensures the schema."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute(_SCHEMA)
    _migrate(conn)
    conn.commit()
    return conn


def _parse_ts(value: str | None) -> datetime | None:
    """
    Tolerant UTC parse. Handles both timestamp shapes in this project:
      run_timestamp  "2026-07-10T14:30:00Z"
      ad timestamp   "2026-07-09T23:35:33.123456+00:00"
    Returns a timezone-aware datetime, or None if unparseable.
    """
    if not value:
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _age_days(first_seen: str, run_ts: str) -> int:
    a, b = _parse_ts(first_seen), _parse_ts(run_ts)
    if a is None or b is None:
        return 0
    return max(0, (b - a).days)


def fingerprint_of(ad: dict) -> tuple[str, str, str]:
    """
    Returns (fingerprint, engine, primary_host) for a finding record.
    Destination host is primary; display host is the fallback when the click
    did not resolve; "unresolved" only when neither parses.
    """
    engine = (ad.get("engine") or "unknown").lower()
    host = host_of(ad.get("destination_url")) or host_of(ad.get("display_url")) or "unresolved"
    return f"{engine}:{host}", engine, host


def classify_persistence(times_seen: int, age_days: int, is_new: bool) -> str:
    """
    Human-readable case status for the alert email.
      NEW        — first ever observation this run
      PERSISTENT — crossed the escalation thresholds
      recurring  — seen before but below the escalation bar
    """
    if is_new:
        return "NEW"
    if times_seen >= PERSISTENT_MIN_RUNS and age_days >= PERSISTENT_MIN_DAYS:
        return "PERSISTENT"
    return "recurring"


def _best_attribution(ads_in_group: list[dict], existing: sqlite3.Row | None) -> dict:
    """
    Compute the sticky attribution values to store for a case.

    Attribution is hard-won and intermittent: the My Ad Center panel opens only
    while an ad is live, and the Transparency Center only carries verified
    advertisers. So a value once captured must survive later runs that captured
    nothing. Rule per field: take the first non-empty value seen across this
    run's ads for the case, else fall back to what is already stored.

    The two ATC identity fields that must stay internally consistent
    (advertiser_id / creative_id / creative_url / verified) are taken as a block
    from the first ad in the group that actually resolved a creative this run;
    only if none did do we keep the existing block.
    """
    def _grp(key):
        for a in ads_in_group:
            v = a.get(key)
            if v not in (None, "", []):
                return v
        return None

    def _old(key):
        if existing is None:
            return None
        try:
            return existing[key]
        except (KeyError, IndexError):
            return None

    # My Ad Center panel → advertiser / country (existing base-schema columns).
    advertiser = _grp("advertiser_name")     or _old("advertiser")
    country    = _grp("advertiser_location") or _old("country")

    # Google campaign id lives on the ad as tracking_id (label gad_campaignid).
    gad = None
    for a in ads_in_group:
        if (a.get("engine") or "").lower() == "google" and a.get("tracking_id"):
            gad = a.get("tracking_id")
            break
    gad = gad or _old("gad_campaignid")

    # ATC block — atomic: prefer a fresh observation that resolved a creative.
    atc_src = next((a for a in ads_in_group if a.get("atc_creative_id")), None)
    if atc_src is not None:
        atc_name     = atc_src.get("atc_advertiser_name")
        atc_verified = 1 if atc_src.get("atc_advertiser_verified") else 0
        atc_adv_id   = atc_src.get("atc_advertiser_id")
        atc_cr_id    = atc_src.get("atc_creative_id")
        atc_cr_url   = atc_src.get("atc_creative_url")
        atc_screen   = atc_src.get("atc_screenshot")
    else:
        atc_name     = _old("atc_advertiser_name")
        atc_verified = _old("atc_advertiser_verified") or 0
        atc_adv_id   = _old("atc_advertiser_id")
        atc_cr_id    = _old("atc_creative_id")
        atc_cr_url   = _old("atc_creative_url")
        atc_screen   = _old("atc_screenshot")

    # Ad count reflects the latest lookup for the domain even when 0 (it is a
    # freshness signal, not an identifier), but never overwrite a known count
    # with a null from a run where the lookup was skipped.
    atc_count = _grp("atc_ad_count")
    if atc_count is None:
        atc_count = _old("atc_ad_count")

    return {
        "advertiser":               advertiser,
        "country":                  country,
        "gad_campaignid":           gad,
        "atc_advertiser_name":      atc_name,
        "atc_advertiser_verified":  atc_verified,
        "atc_advertiser_id":        atc_adv_id,
        "atc_creative_id":          atc_cr_id,
        "atc_creative_url":         atc_cr_url,
        "atc_ad_count":             atc_count,
        "atc_screenshot":           atc_screen,
    }


def record_observation(conn: sqlite3.Connection, ads_in_group: list[dict], run_ts: str) -> dict:
    """
    Records one run's observation of a single case (all ads in the group share
    a fingerprint) and returns the enrichment to stamp on every ad in the group.

    Same-case reappearance semantics: a case that resurfaces after going quiet
    keeps its original first_seen and advances last_seen — it is not re-opened
    as a new case. This preserves a future takedown/reappearance (MTTR) metric.

    times_seen counts RUNS: within a single run (same run_ts) the count is not
    double-bumped even if called more than once for the same fingerprint.

    Returns: {fingerprint, first_seen, last_seen, times_seen, is_new, age_days,
              status, devices_seen, queries_seen}
    """
    fp, engine, host = fingerprint_of(ads_in_group[0])
    rep = ads_in_group[-1]  # latest record carries the freshest context fields

    devices = {a.get("device") for a in ads_in_group if a.get("device")}
    queries = {a.get("query") for a in ads_in_group if a.get("query")}
    channels = {a.get("detection_channel") for a in ads_in_group
                if a.get("detection_channel")}
    detections = len(ads_in_group)

    # Infringement is sticky: once a case has been seen claiming the brand while
    # landing off-brand, a later run whose title failed to extract must not
    # quietly downgrade it.
    claims = any(a.get("claims_brand") for a in ads_in_group)
    infringing = any(a.get("infringing") for a in ads_in_group)

    row = conn.execute(
        "SELECT first_seen, last_seen, times_seen, raw_detections, devices_seen, "
        "queries_seen, channels_seen, last_channel, claims_brand, infringing, "
        + ", ".join(_ATTR_COLUMNS) +
        " FROM findings WHERE fingerprint = ?",
        (fp,),
    ).fetchone()

    # Sticky attribution values (My Ad Center + campaign id + ATC), merged with
    # whatever this run captured. Column order matches _ATTR_COLUMNS.
    attr = _best_attribution(ads_in_group, row)
    attr_vals = tuple(attr[c] for c in _ATTR_COLUMNS)

    if row is None:
        first_seen = run_ts
        times_seen = 1
        is_new = True
        raw_detections = detections
        conn.execute(
            "INSERT INTO findings (fingerprint, engine, primary_host, first_seen, "
            "last_seen, times_seen, raw_detections, devices_seen, queries_seen, "
            "channels_seen, last_channel, claims_brand, infringing, "
            "last_headline, last_display_url, last_destination_url, last_evidence_json, "
            + ", ".join(_ATTR_COLUMNS) + ", status) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,"
            + ",".join("?" * len(_ATTR_COLUMNS)) + ", 'open')",
            (
                fp, engine, host, first_seen, run_ts, times_seen, raw_detections,
                json.dumps(sorted(devices)), json.dumps(sorted(queries)),
                json.dumps(sorted(channels)), rep.get("detection_channel"),
                int(claims), int(infringing),
                rep.get("headline"), rep.get("display_url"),
                rep.get("destination_url"), rep.get("evidence_json"),
                *attr_vals,
            ),
        )
    else:
        first_seen = row["first_seen"]
        is_new = False
        devices |= set(json.loads(row["devices_seen"] or "[]"))
        queries |= set(json.loads(row["queries_seen"] or "[]"))
        channels |= set(json.loads(row["channels_seen"] or "[]"))
        claims = claims or bool(row["claims_brand"])
        infringing = infringing or bool(row["infringing"])
        raw_detections = (row["raw_detections"] or 0) + detections
        # Keep the last known channel if this run could not determine one.
        last_channel = rep.get("detection_channel") or row["last_channel"]
        # Guard: if this exact run already counted this case, do not re-bump the
        # run counter (idempotent within a run / accidental double call).
        if row["last_seen"] == run_ts:
            times_seen = row["times_seen"]
        else:
            times_seen = (row["times_seen"] or 0) + 1
        conn.execute(
            "UPDATE findings SET last_seen = ?, times_seen = ?, raw_detections = ?, "
            "devices_seen = ?, queries_seen = ?, channels_seen = ?, last_channel = ?, "
            "claims_brand = ?, infringing = ?, last_headline = ?, last_display_url = ?, "
            "last_destination_url = ?, last_evidence_json = ?, "
            + ", ".join(f"{c} = ?" for c in _ATTR_COLUMNS) +
            " WHERE fingerprint = ?",
            (
                run_ts, times_seen, raw_detections,
                json.dumps(sorted(devices)), json.dumps(sorted(queries)),
                json.dumps(sorted(channels)), last_channel,
                int(claims), int(infringing),
                rep.get("headline"), rep.get("display_url"),
                rep.get("destination_url"), rep.get("evidence_json"),
                *attr_vals, fp,
            ),
        )

    conn.commit()
    age_days = _age_days(first_seen, run_ts)
    return {
        "fingerprint":  fp,
        "first_seen":   first_seen,
        "last_seen":    run_ts,
        "times_seen":   times_seen,
        "raw_detections": raw_detections,
        "is_new":       is_new,
        "age_days":     age_days,
        "status":       classify_persistence(times_seen, age_days, is_new),
        "devices_seen": sorted(devices),
        "queries_seen": sorted(queries),
        "channels_seen": sorted(channels),
        "claims_brand": claims,
        "infringing":   infringing,
        "attribution":  attr,   # sticky, best-known attribution for the case
    }


def enrich_flagged(conn: sqlite3.Connection, flagged: list[dict], run_ts: str) -> dict:
    """
    Groups a run's flagged ads by fingerprint (within-run dedup), records one
    observation per case, and stamps the persistence fields onto every ad dict
    in place. Returns {fingerprint: enrichment} for the run's distinct cases.

    Mutates each ad, adding: first_seen, last_seen, times_seen, is_new,
    age_days, case_status, fingerprint.
    """
    groups: dict[str, list[dict]] = {}
    for ad in flagged:
        fp, _, _ = fingerprint_of(ad)
        groups.setdefault(fp, []).append(ad)

    cases = {}
    for fp, group in groups.items():
        rec = record_observation(conn, group, run_ts)
        cases[fp] = rec
        for ad in group:
            ad["fingerprint"] = rec["fingerprint"]
            ad["first_seen"]  = rec["first_seen"]
            ad["last_seen"]   = rec["last_seen"]
            ad["times_seen"]  = rec["times_seen"]
            ad["is_new"]      = rec["is_new"]
            ad["age_days"]    = rec["age_days"]
            ad["case_status"] = rec["status"]
            # Backfill best-known attribution so the alert shows a prior run's
            # advertiser / creative id even on a run where capture was skipped
            # (ad dark, ATC withdrawn). Only fill fields the ad lacks this run.
            for k, v in rec["attribution"].items():
                if v not in (None, "", 0) and ad.get(k) in (None, "", []):
                    ad[k] = v
    return cases
