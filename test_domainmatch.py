"""
Regression tests for domainmatch.py — the allowlist/triage evasion-hole fix.

Pure logic, no browser, no network: run with `pytest tests/` any time.
Cases are drawn from real display-URL strings in the evidence set.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from domainmatch import host_of, host_matches, host_in

# The live allowlist from serp_monitor.py (brand-owned; suffix-matched).
ALLOWLIST = ["contosoportal.com", "contosoaccount.com", "contosologin.com"]


# --------------------------------------------------------------------------- #
# host_of — canonicalization
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("raw, expected", [
    # Bing form: scheme + www + breadcrumb path
    ("https://www.contosoportal.com › account › overview › contoso-portal", "contosoportal.com"),
    # Google breadcrumb form (path renders as › segments)
    ("https://phish-example-1.com › contoso-account-online-portal-login", "phish-example-1.com"),
    ("https://www.appfinder-example.com › app › contoso-account", "appfinder-example.com"),
    # Bare hosts
    ("contosoportal.com.evil.ru", "contosoportal.com.evil.ru"),
    ("https://notcontosoportal.com", "notcontosoportal.com"),
    ("https://contoso-login.com", "contoso-login.com"),
    # www stripping + case folding + trailing dot
    ("HTTPS://WWW.ContosoPortal.CoM.", "contosoportal.com"),
    # port and credentials
    ("https://user@evil.ru:8443 › contosoportal.com", "evil.ru"),
    # unparseable -> None (fail closed)
    ("N/A", None),
    ("n/a", None),
    ("", None),
    (None, None),
    ("localhost", None),          # no dot -> not a real registrable host
])
def test_host_of(raw, expected):
    assert host_of(raw) == expected


# --------------------------------------------------------------------------- #
# host_matches — label-boundary suffix
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("host, entry, expected", [
    ("contosoportal.com",           "contosoportal.com", True),
    ("login.contosoportal.com",     "contosoportal.com", True),   # subdomain ok
    ("www.contosoportal.com",       "contosoportal.com", True),
    ("contosoportal.com.evil.ru",   "contosoportal.com", False),  # the core exploit
    ("notcontosoportal.com",        "contosoportal.com", False),  # label boundary
    ("evilcontosoportal.com",       "contosoportal.com", False),
    ("contosoportal.com",           "",              False),
    ("",                        "contosoportal.com", False),
])
def test_host_matches(host, entry, expected):
    assert host_matches(host, entry) is expected


# --------------------------------------------------------------------------- #
# is_allowlisted semantics — host_in(suffix) over the brand allowlist
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("display_url, allowlisted", [
    # Legit brand ads — suppressed
    ("https://www.contosoportal.com › account › overview › contoso-portal", True),
    ("login.contosoportal.com", True),
    ("https://contosologin.com", True),
    # Evasion attempts — MUST NOT be allowlisted (these are the whole point)
    ("contosoportal.com.evil.ru", False),
    ("https://evil.ru › contosoportal.com › login", False),   # breadcrumb path spoof
    ("https://notcontosoportal.com", False),
    # Unparseable -> not allowlisted -> flagged (fail closed)
    ("N/A", False),
])
def test_is_allowlisted_semantics(display_url, allowlisted):
    assert host_in(host_of(display_url), ALLOWLIST) is allowlisted


# --------------------------------------------------------------------------- #
# is_triaged semantics — host_in(exact) over analyst-triaged hosts
# --------------------------------------------------------------------------- #

def test_is_triaged_is_exact_host():
    triaged = {"play.google.com", "clientportal.example"}
    # exact host suppressed
    assert host_in(host_of("https://play.google.com › store"), triaged, exact=True) is True
    # sibling / parent domain NOT suppressed by a subdomain triage entry
    assert host_in(host_of("https://google.com"), triaged, exact=True) is False
    assert host_in(host_of("https://mail.google.com"), triaged, exact=True) is False
    # a triaged bare domain does NOT suppress a hostile subdomain (the tightening)
    assert host_in(host_of("https://attacker.clientportal.example"), triaged, exact=True) is False
    assert host_in(host_of("https://clientportal.example"), triaged, exact=True) is True
    # unparseable -> not triaged -> flagged
    assert host_in(host_of("N/A"), triaged, exact=True) is False
