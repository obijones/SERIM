"""
url_resolve.py — ad destination resolution helpers (Lens #1 gap #5).

Closes the "58% no resolved destination" gap. The real distribution (405
records) is 90% resolved / 10% failed, with 63% of failures on Bing mobile,
where a SERP overlay intercepts the middle-click. The fix is per-href-shape,
not a global "static-first" — proven against evidence:

  - Bing ad anchors carry the FINAL landing URL directly in href
    ("https://contoso.clientportal.example/Welcome/tabid/169931/Default.aspx").
    Reading it beats the click that is failing on the overlay -> skip the click.

  - Google ad anchors are always "/aclk?...&adurl=<registered>" redirectors.
    The adurl is the REGISTERED domain, NOT the landing page: on 103 resolved
    Google records the clicked destination host diverged from the adurl host
    48 times (cloaking). So the click is load-bearing and stays; adurl is only
    a fallback when the click fails, and is recorded separately as a cloaking
    signal.

Pure and dependency-light (stdlib + domainmatch) so it is unit-testable offline
against the real href strings captured in the evidence DOMs.
"""

from __future__ import annotations

import urllib.parse

from domainmatch import host_of

# Hosts that are ad-serving / tracking infrastructure, never a landing page.
_ENGINE_HOSTS = (
    "google", "doubleclick", "googleadservices", "googlesyndication", "gstatic",
    "bing.com", "msn.com", "microsoft.com", "bat.bing.com", "c.bing.com",
    "live.com", "windows.com",
)

# URL schemes/prefixes that indicate a failed navigation, not a real page.
_BAD_PREFIXES = ("chrome-error://", "about:blank", "about:", "data:", "chrome://")


def _is_engine_host(host: str | None) -> bool:
    return bool(host) and any(s in host for s in _ENGINE_HOSTS)


def is_real_destination(url: str | None) -> bool:
    """
    True only if `url` is a real external landing page: an http(s) URL that is
    not a browser error page and whose host is not ad/engine infrastructure.
    Rejects None, chrome-error://, about:blank, and engine/tracking hosts.
    """
    if not url:
        return False
    low = url.strip().lower()
    if low.startswith(_BAD_PREFIXES):
        return False
    if not low.startswith(("http://", "https://")):
        return False
    return not _is_engine_host(host_of(url))


def classify_href(href: str | None) -> str:
    """
    Classifies an ad anchor href by resolution strategy:
      "direct"             — an external landing URL; use as-is, skip the click
      "google_redirector"  — /aclk...; click to resolve, adurl is fallback
      "bing_redirector"    — /aclick...; not seen in evidence, defensive only
      "engine"             — points at engine/tracking infra with no landing
      "none"               — empty / unusable
    """
    if not href:
        return "none"
    h = href.strip()
    low = h.lower()
    # Redirectors — match by path regardless of leading host or scheme.
    if "/aclk" in low:
        return "google_redirector"
    if "/aclick" in low:
        return "bing_redirector"
    if low.startswith(("http://", "https://")):
        return "direct" if not _is_engine_host(host_of(h)) else "engine"
    return "none"


def extract_adurl(href: str | None) -> str | None:
    """
    Pulls the registered landing URL out of a Google "/aclk?...&adurl=<enc>"
    redirector href. Returns the decoded URL, or None if absent/unusable.
    This is the REGISTERED domain (a cloaking signal), not the resolved page.
    """
    if not href:
        return None
    query = urllib.parse.urlparse(href.replace("&amp;", "&")).query
    params = urllib.parse.parse_qs(query)
    for key in ("adurl", "u"):
        vals = params.get(key)
        if vals:
            decoded = urllib.parse.unquote(vals[0])
            if decoded.lower().startswith(("http://", "https://")):
                return decoded
    return None


def best_destination_host(
    destination_url: str | None,
    registered_url: str | None,
    dest_hint: str | None,
    display_url: str | None,
) -> str | None:
    """
    Best-effort landing host from strongest to weakest signal, so a flagged
    record is never left without a host when ANY signal exists (evidence shows
    100% of resolution failures are host-recoverable from captured data):
        resolved destination -> registered (adurl) -> DOM hint -> display URL.
    Engine/tracking hosts are skipped at each tier.
    """
    for candidate in (destination_url, registered_url, dest_hint, display_url):
        host = host_of(candidate)
        if host and not _is_engine_host(host):
            return host
    return None


def suppression_host(
    display_url: str | None = None,
    link_href: str | None = None,
    link_dtld: str | None = None,
) -> tuple[str | None, str | None]:
    """
    Best host evidence available BEFORE the click, for the allowlist/triage
    gates. Returns (host, source); (None, None) means the caller MUST fail
    closed and flag the ad.

    The gates used to read the rendered display URL alone. Google's mobile SERP
    does not render one — 61 of 61 historical google/mobile records extracted
    display_url = "N/A", against a 100% parse rate on every other
    engine/device. host_of("N/A") is None, so both gates failed closed and the
    allowlist and triage list were, in effect, switched off on that surface:
    Contoso's own ads and 33 already-triaged-benign domains were re-flagged.

    Priority — strongest usable signal first, falling back only when a signal
    is absent:
        1. "display"  the rendered display URL (unchanged behaviour, so Bing
                      and Google desktop are byte-for-byte unaffected)
        2. "href"     the ad anchor's own href, when it is a direct landing URL
                      rather than an engine redirector — strictly stronger than
                      (1), since it is where the click actually goes
        3. "dtld"     the data-dtld / data-final-url attribute — the SAME fact
                      as (1), not a weaker one: the engine renders the visible
                      display text from this attribute. Reading it is a
                      reliable extraction of a signal we already trust, not a
                      new trust assumption.

    Every tier is matched by the caller through label-boundary host_in(), so
    the substring evasion hole closed in v7 stays closed.

    NOTE: engine hosts are deliberately NOT filtered out here, unlike in
    best_destination_host(). There, an engine host means "the redirector, not
    the landing page". Here it can mean a real advertiser: the triage list
    holds benign advertisers such as play.google.com and youtube.com, and
    discarding them as "engine infrastructure" silently re-flags 52 already
    triaged Bing ads. Redirector hrefs are still excluded — but by
    classify_href(), which is the check that actually distinguishes them.
    """
    host = host_of(display_url)
    if host:
        return host, "display"

    # "direct" excludes /aclk and /aclick redirectors and engine-owned hrefs,
    # so this tier cannot resolve to the search engine's own host.
    if classify_href(link_href) == "direct":
        host = host_of(link_href)
        if host:
            return host, "href"

    host = host_of(link_dtld)
    if host:
        return host, "dtld"

    return None, None
