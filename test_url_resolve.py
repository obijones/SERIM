"""
Regression tests for url_resolve.py — destination resolution (Lens #1 gap #5).

Pure logic, offline. href strings are drawn from real evidence DOMs.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from url_resolve import (
    classify_href, extract_adurl, is_real_destination, best_destination_host,
    suppression_host,
)
from domainmatch import host_in


# --------------------------------------------------------------------------- #
# classify_href
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("href, kind", [
    # Bing: direct landing URL in href -> skip the click
    ("https://contoso.clientportal.example/Welcome/tabid/169931/Default.aspx", "direct"),
    ("https://www.contosoportal.com/logins", "direct"),
    # Google: /aclk redirector -> click to resolve
    ("/aclk?sa=l&adurl=https://www.adventure-works.com/lp", "google_redirector"),
    ("https://www.google.com/aclk?sa=l&adurl=https://x.com", "google_redirector"),
    # Bing redirector shape (defensive; not seen in evidence)
    ("/aclick?ld=abc&u=a1aHR0cHM", "bing_redirector"),
    # engine/tracking host, no landing
    ("https://www.bing.com/search?q=contoso", "engine"),
    ("", "none"),
    (None, "none"),
])
def test_classify_href(href, kind):
    assert classify_href(href) == kind


# --------------------------------------------------------------------------- #
# extract_adurl (Google registered domain)
# --------------------------------------------------------------------------- #

def test_extract_adurl_decodes_registered_url():
    href = "/aclk?sa=l&adurl=https%3A%2F%2Fwww.adventure-works.com%2Flp%3Fk%3D1&foo=bar"
    assert extract_adurl(href) == "https://www.adventure-works.com/lp?k=1"


def test_extract_adurl_absent_returns_none():
    assert extract_adurl("https://contoso.clientportal.example/x") is None
    assert extract_adurl("/aclk?sa=l&nope=1") is None
    assert extract_adurl(None) is None


# --------------------------------------------------------------------------- #
# is_real_destination
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("url, ok", [
    ("https://contoso.clientportal.example/x", True),
    ("http://phish-example-3.cc", True),
    ("chrome-error://chromewebdata/", False),   # the failure sentinel to reject
    ("about:blank", False),
    ("https://www.bing.com/aclick", False),      # engine host
    ("https://www.google.com/aclk", False),
    (None, False),
    ("", False),
])
def test_is_real_destination(url, ok):
    assert is_real_destination(url) is ok


# --------------------------------------------------------------------------- #
# best_destination_host — never null when any signal exists
# --------------------------------------------------------------------------- #

def test_prefers_resolved_destination():
    h = best_destination_host("https://landing.example/x", "https://reg.example",
                              "hint.example", "display.example › p")
    assert h == "landing.example"


def test_falls_through_to_display_when_all_else_missing():
    # The 100%-recoverable case: click failed, no hint, but display URL exists.
    h = best_destination_host(None, None, None, "https://contoso.clientportal.example › Welcome")
    assert h == "contoso.clientportal.example"


def test_skips_engine_hosts_in_fallback():
    # A resolved-but-engine URL must not win; fall through to the real display host.
    h = best_destination_host("https://www.bing.com/aclick", None, None, "https://phish.top")
    assert h == "phish.top"


def test_all_null_returns_none():
    assert best_destination_host(None, None, None, None) is None
    assert best_destination_host(None, None, None, "N/A") is None


# --------------------------------------------------------------------------- #
# suppression_host — the host the allowlist/triage gates decide on.
#
# The bug this closes: Google's mobile SERP renders no display URL (61/61
# historical google/mobile records had display_url "N/A", against a 100% parse
# rate everywhere else), so both gates fell back to fail-closed and re-flagged
# brand-owned and already-triaged domains.
# --------------------------------------------------------------------------- #

ALLOWLIST = ["contosoportal.com", "contosoaccount.com", "contosologin.com"]


def test_rendered_display_url_still_wins():
    """Bing and Google desktop must be byte-for-byte unaffected."""
    host, src = suppression_host(
        display_url="https://www.contosoportal.com › business",
        link_href="https://contosoportal.com/business",
        link_dtld="contosoportal.com",
    )
    assert (host, src) == ("contosoportal.com", "display")


def test_direct_href_used_when_no_display_url():
    host, src = suppression_host(
        display_url="N/A", link_href="https://contosologin.com/ui")
    assert (host, src) == ("contosologin.com", "href")


def test_dtld_used_when_href_is_a_redirector():
    """Google mobile: the anchor is an /aclk redirector, so fall to data-dtld."""
    host, src = suppression_host(
        display_url="N/A",
        link_href="https://www.google.com/aclk?sa=L&ai=xyz&adurl=https://evil.ru",
        link_dtld="contosologin.com",
    )
    assert (host, src) == ("contosologin.com", "dtld")


def test_redirector_href_never_leaks_the_engine_host():
    """An /aclk href must not resolve the gate to google.com."""
    host, src = suppression_host(display_url="N/A",
                                 link_href="https://www.google.com/aclk?sa=L&ai=xyz")
    assert (host, src) == (None, None)


def test_triaged_advertisers_on_engine_domains_survive():
    """
    Regression: the triage list holds benign advertisers whose hosts contain an
    engine substring (play.google.com, youtube.com). Filtering them out as
    "engine infrastructure" re-flagged 52 already-triaged Bing ads. The gate
    must hand the real host to the triage list and let IT decide.
    """
    triaged = {"play.google.com", "youtube.com"}
    host, src = suppression_host(display_url="https://play.google.com › store › apps")
    assert (host, src) == ("play.google.com", "display")
    assert host_in(host, triaged, exact=True) is True


def test_fails_closed_when_nothing_is_recoverable():
    assert suppression_host("N/A", None, None) == (None, None)
    assert suppression_host(None, None, None) == (None, None)


def test_the_contosologin_false_positive():
    """The exact ad from the 2026-07-11 alert: allowlisted, must be suppressed."""
    host, src = suppression_host(
        display_url="N/A",
        link_href="https://contosologin.com/ui",
        link_dtld="contosologin.com",
    )
    assert host_in(host, ALLOWLIST) is True


def test_derived_host_is_still_label_boundary_matched():
    """Deriving the host must not re-open the v7 substring evasion hole."""
    host, _ = suppression_host(display_url="N/A",
                               link_href="https://contosoportal.com.evil.ru/login")
    assert host == "contosoportal.com.evil.ru"
    assert host_in(host, ALLOWLIST) is False
