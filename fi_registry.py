"""
fi_registry.py — the known-legitimate financial institution registry, and the
single rule that turns a case into a review state.

Why this exists
---------------
The brand terms are deliberately generic ("account login", "online portal"), so
real, licensed financial institutions bid on them and rank for them. They are
not offences, but they were still counted as campaigns in every report metric.
Measured against a 113-case store: 90 cases (80%) were non-infringing, and most
of that volume was legitimate competitors.

Three concepts, deliberately distinct — do not merge them:

    ALLOWLIST_DOMAINS   "we own this"          suffix match, never flagged at all
    triaged_domains     "an analyst looked at  exact host, per-incident
                         this specific host
                         and it was benign"
    THIS registry       "this organization is  suffix match, durable, carries
                         a legitimate FI"      the basis for the decision

The registry is the missing one. An allowlist entry would wrongly claim we own a
competitor's domain; a triage entry records a one-off look at a single host and
carries no reason, so nobody can later audit why a domain stopped being counted.

The review-state rule
---------------------
Exactly three states, matching how the findings actually sort:

    threat      infringing — the title claims a brand term and lands off-brand
    legitimate  the host belongs to a registered institution
    unreviewed  neither — nobody has adjudicated it yet

`unreviewed` is not a synonym for "benign". It holds legitimate businesses
nobody has got to yet AND any real threat whose title did not claim the brand
(a false negative of the title heuristic). Reports must show it as a work queue
rather than folding it into either of the other two, or a recall gap becomes
invisible.

Two safety properties, both deliberate:

  * FAIL CLOSED on conflict. An infringing case stays a threat even when its
    host is on the registry — a registry entry can never suppress a live brand
    claim. That combination means either a brandmatch false positive on the
    institution's own title, or a compromised legitimate domain. Both need a
    human, so `conflicts()` surfaces them instead of hiding them.

  * FAIL OPEN on a missing or broken registry. Any load error yields an empty
    set, so every case falls back to `unreviewed` and stays visible. Because
    `legitimate` requires POSITIVE membership, a registry that fails to load can
    never hide a finding.

Matching is label-boundary suffix (domainmatch.host_in, exact=False), the same
mode as the allowlist: a real institution serves `www.`, `secure.` and
`locator.` subdomains off one registered domain, and exact-host matching would
leave every one of them stranded in `unreviewed`. The boundary check is what
keeps that safe — `evil-example.com` and `example.com.evil.ru` do not match an
`example.com` entry.

Pure stdlib + domainmatch, so it is unit-testable with no browser and no DB.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from domainmatch import host_in, host_of

# Review states. Import these rather than writing the strings, so a typo is an
# AttributeError here instead of a silently-empty bucket in a manager report.
THREAT     = "threat"
LEGITIMATE = "legitimate"
UNREVIEWED = "unreviewed"

STATES = (THREAT, LEGITIMATE, UNREVIEWED)

# Human-readable, for the alert email and the report. Says what the state means
# operationally, not just what it is called.
STATE_LABEL = {
    THREAT:     "BRAND INFRINGEMENT",
    LEGITIMATE: "known institution",
    UNREVIEWED: "unreviewed",
}

_KEY = "known_financial_institutions"


# --------------------------------------------------------------------------- #
# The rule — imported by BOTH serp_monitor (alert email) and report_data
# (metrics), so the two can never disagree about what counts as a threat.
# --------------------------------------------------------------------------- #

def review_state(infringing: bool, host: str | None, fi_hosts) -> str:
    """
    The review state for one case. See the module docstring for the semantics.

    Fails closed: `infringing` wins over registry membership, so a registry
    entry can never suppress a case that claims the brand and lands off-brand.
    """
    if infringing:
        return THREAT
    if host and host_in(host, fi_hosts):
        return LEGITIMATE
    return UNREVIEWED


def is_conflict(infringing: bool, host: str | None, fi_hosts) -> bool:
    """
    True when a case is BOTH infringing and on the registry.

    Not a fourth state — it stays a threat. It is surfaced because it should be
    near-zero, and when it fires it means one of two things a human must settle:
    brandmatch mis-firing on the institution's own title, or a legitimate
    domain that has been compromised.
    """
    return bool(infringing) and bool(host) and host_in(host, fi_hosts)


# --------------------------------------------------------------------------- #
# Registry file I/O
# --------------------------------------------------------------------------- #

def load_entries(path: str | None) -> list[dict]:
    """
    Every registry entry, or [] on any problem (missing file, bad JSON, wrong
    shape). Fails open by design — see the module docstring.
    """
    if not path:
        return []
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception:
        return []
    entries = data.get(_KEY) if isinstance(data, dict) else None
    if not isinstance(entries, list):
        return []
    return [e for e in entries if isinstance(e, dict) and e.get("domain")]


def load_hosts(path: str | None) -> set[str]:
    """
    Canonical registered hosts from the registry, for host_in() suffix matching.

    Entries are canonicalized through host_of() so a registry written with a
    scheme or a trailing path ("https://example.com/personal") still matches.
    """
    hosts = set()
    for e in load_entries(path):
        h = host_of(e["domain"]) or (e["domain"] or "").strip().lower().strip(".")
        if h and "." in h:
            hosts.add(h)
    return hosts


def add_entry(path: str, domain: str, institution: str = "",
              basis: str = "", added_by: str = "") -> dict | None:
    """
    Adds one institution to the registry, creating the file if needed.

    Returns the stored entry, or None if the domain could not be canonicalized
    or is already present. Every entry records WHY it was trusted (`basis`) and
    by whom, so the decision can be audited later — that provenance is the
    reason this is a registry and not just another suppression list.
    """
    host = host_of(domain) or (domain or "").strip().lower().strip(".")
    if not host or "." not in host:
        return None

    entries = load_entries(path)
    if any((host_of(e["domain"]) or e["domain"].lower()) == host for e in entries):
        return None

    entry = {
        "domain":      host,
        "institution": institution or "",
        "basis":       basis or "",
        "added_by":    added_by or "",
        "added":       datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    entries.append(entry)
    entries.sort(key=lambda e: e["domain"])

    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({_KEY: entries}, indent=2) + "\n", encoding="utf-8")
    return entry
