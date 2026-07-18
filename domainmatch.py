"""
domainmatch.py — host extraction and label-boundary domain matching.

Shared by serp_monitor.py for allowlist / triage suppression. Kept dependency
free (no tldextract / no Public Suffix List download) so it runs on an isolated
monitoring box, and pure (no I/O) so it is unit-testable without a browser.

Why label-boundary matching instead of substring or registrable-domain:

  - Substring ("contosoportal.com" in display_url) is an evasion hole: a hostile
    display URL like "contosoportal.com.evil.ru", or Google's breadcrumb form
    "evil.ru > contosoportal.com > login" (the path renders as > segments), both
    contain the brand string and were silently suppressed.

  - Registrable-domain folding (tldextract) would over-suppress: the triage
    list holds subdomain-scoped entries such as "play.google.com" and
    "cityofcontoso.civichost.example". Folding those to google.com /
    civichost.example would blind the monitor to the rest of those domains.

Label-boundary matching gives the security property without either downside:
a host matches an entry only if it IS that entry or is a subdomain of it
(host == entry  or  host endswith "." + entry).

Allowlist uses suffix matching (Contoso owns every subdomain of contosoportal.com).
Triage uses exact-host matching (analysts triage a specific host they looked
at, not a hosting provider) — see host_in(exact=...).
"""

from __future__ import annotations

# Unicode breadcrumb separators Google/Bing use to render the display-URL path
# (U+203A single right-pointing angle quotation, and the ASCII '>' fallback).
_BREADCRUMB_CHARS = ("›", ">")


def host_of(display_url: str | None) -> str | None:
    """
    Canonicalizes a scraped display URL down to its bare host.

    Handles every display-URL shape seen in the evidence set:
      "https://www.contosoportal.com > account > overview"  -> "contosoportal.com"
      "contosoportal.com.evil.ru"                            -> "contosoportal.com.evil.ru"
      "https://evil.ru > contosoportal.com > login"          -> "evil.ru"
      "https://www.appfinder-example.com > app > contoso-account"   -> "appfinder-example.com"
      "N/A" / "" / None                                  -> None

    Returns a lowercased host with scheme, path/breadcrumbs, port, and a single
    leading "www." stripped. Returns None when nothing parseable remains — the
    caller MUST treat None as "cannot verify, do not suppress" (fail closed).
    """
    if not display_url:
        return None

    text = display_url.strip()
    if not text or text.upper() == "N/A":
        return None

    # Drop scheme.
    if "://" in text:
        text = text.split("://", 1)[1]

    # The host is everything before the first path/breadcrumb separator.
    for sep in ("/",) + _BREADCRUMB_CHARS:
        if sep in text:
            text = text.split(sep, 1)[0]

    host = text.strip().strip(".").lower()

    # Strip credentials ("user@host") and port ("host:443") if present.
    if "@" in host:
        host = host.split("@", 1)[1]
    if ":" in host:
        host = host.split(":", 1)[0]

    # Strip a single leading "www." — but not "www.com" style edge cases where
    # nothing would remain.
    if host.startswith("www.") and len(host) > 4:
        host = host[4:]

    if not host or "." not in host:
        return None
    return host


def host_matches(host: str, entry: str) -> bool:
    """
    True if `host` is `entry` or a subdomain of it (label-boundary suffix).

    host_matches("login.contosoportal.com", "contosoportal.com")   -> True
    host_matches("contosoportal.com.evil.ru", "contosoportal.com")  -> False
    host_matches("notcontosoportal.com", "contosoportal.com")       -> False
    """
    if not host or not entry:
        return False
    host  = host.lower().strip(".")
    entry = entry.lower().strip(".")
    return host == entry or host.endswith("." + entry)


def host_in(host: str | None, entries, *, exact: bool = False) -> bool:
    """
    True if `host` matches any entry.

    exact=False (default): suffix match — host or any subdomain of an entry.
    exact=True:            entry must equal the host exactly.

    A None host never matches (fail closed — the caller flags rather than
    suppresses when the display URL could not be parsed).
    """
    if host is None:
        return False
    host = host.lower().strip(".")
    if exact:
        return any(host == e.lower().strip(".") for e in entries)
    return any(host_matches(host, e) for e in entries)
