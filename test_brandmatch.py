"""
Tests for brandmatch.py — the analyst's infringement rule.

  "An advertisement with a [Headline] of 'Contoso Online Portal' that does not
   have a url with 'contosologin.com' or 'contosoaccount.com/ui' is
   infringing on our brand."

The hard part is NOT catching the phishing — it is not crying wolf on the
unrelated businesses that share the word "contoso", nor on other businesses
that legitimately appear for the same generic search terms.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from brandmatch import assess, claimed_brand_term, collapse

BRAND_TERMS = ["contoso online portal", "contoso account login"]
ALLOWLIST = ["contosoportal.com", "contosoaccount.com", "contosologin.com"]


# --------------------------------------------------------------------------- #
# collapse — punctuation/spacing must not defeat the match
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("raw, expected", [
    ("Contoso Account - Log In",  "contosoaccountlogin"),
    ("contoso   account  login",  "contosoaccountlogin"),
    ("Contoso|Account|Login",     "contosoaccountlogin"),
    ("N/A",                  ""),
    (None,                   ""),
])
def test_collapse(raw, expected):
    assert collapse(raw) == expected


# --------------------------------------------------------------------------- #
# The phishing titles, taken verbatim from captured evidence
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("title, host", [
    # organic SEO poisoning (Bing) — the whole reason the organic channel exists
    ("Contoso Online Portal | Contoso Portal Login", "contoso-login.com"),
    ("Contoso Online Portal | Account Management", "contoso-login.com"),
    # PADDED title — the words of "contoso online portal" are interleaved with
    # "account". This is the most-detected phishing site in the whole evidence set
    # (62 detections) and a contiguous-substring rule silently misses it.
    ("contoso account online portal login - phish-example-1.com", "phish-example-1.com"),
    # sponsored hijacking (Google)
    ("Contoso Account - Log In",                       "advertiser-example.one"),
    ("Contoso online portal – Log in",                 "phish-example-2.info"),
    ("Contoso Online Portal - Secure - Welcome",       "phish-example-3.cc"),
    # typosquatted hosts still get caught on the TITLE, not the domain
    ("Contoso Online Portal® | Official Site",         "contosoportall.com"),
])
def test_real_threats_are_infringing(title, host):
    v = assess(title, host, BRAND_TERMS, ALLOWLIST)
    assert v["claims_brand"] is True
    assert v["infringing"] is True


# --------------------------------------------------------------------------- #
# Brand's own ads must NOT be called infringement
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("title, host", [
    ("Contoso Online Portal | Official Login", "contosologin.com"),
    ("Contoso Account Login",                  "contosoportal.com"),
    ("Contoso Account Login",                  "login.contosoportal.com"),  # subdomain
])
def test_brand_owned_is_not_infringing(title, host):
    v = assess(title, host, BRAND_TERMS, ALLOWLIST)
    assert v["claims_brand"] is True
    assert v["brand_owned"] is True
    assert v["infringing"] is False


# --------------------------------------------------------------------------- #
# THE FALSE-POSITIVE TRAP the analyst called out explicitly:
#   - contoso.com is a real, unrelated business that merely shares the word
#   - the search terms are generic, so unrelated businesses legitimately appear
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("title, host", [
    ("Contoso Gelato — Italian Ice Cream",            "contosogelato.com"),
    ("City of Contoso, Texas",                        "cityofcontoso.civichost.example"),
    ("Contoso — Enterprise Software",                 "gpd.contoso.com"),   # NOT the Contoso brand
    ("Contoso, Inc. Login",                           "gpd.contoso.com"),
    # other legitimate businesses appearing for the same generic terms — not an offence
    ("Fabrikam — Online Account Portal",              "fabrikam.com"),
    ("Account Management Services | Northwind Traders", "northwindtraders.com"),
    ("Wingtip — Digital Login Platform",              "wingtiptoys.com"),
    ("Wikipedia — Contoso Corporation",               "en.wikipedia.org"),
])
def test_legitimate_lookalikes_are_not_infringement(title, host):
    v = assess(title, host, BRAND_TERMS, ALLOWLIST)
    assert v["claims_brand"] is False, f"{title!r} must not be read as a brand claim"
    assert v["infringing"] is False


def test_partial_brand_term_is_not_a_claim():
    """'Contoso Portal' alone is not 'Contoso Online Portal' — require the whole term."""
    assert claimed_brand_term("Contoso | Contoso Portal Section", BRAND_TERMS) is None


# --------------------------------------------------------------------------- #
# Fail-closed on an unresolvable host
# --------------------------------------------------------------------------- #

def test_brand_claim_with_unknown_host_fails_closed():
    """Claims the brand, and we cannot prove the destination is ours -> infringing."""
    v = assess("Contoso Account Login", None, BRAND_TERMS, ALLOWLIST)
    assert v["infringing"] is True


def test_no_brand_claim_with_unknown_host_is_not_infringement():
    """Absence of a brand claim is not evidence of one, even with no host."""
    v = assess("Some Unrelated Ad", None, BRAND_TERMS, ALLOWLIST)
    assert v["infringing"] is False


def test_missing_title_is_not_a_claim():
    """Extraction failure must not manufacture an infringement verdict."""
    assert assess("N/A", "evil.ru", BRAND_TERMS, ALLOWLIST)["infringing"] is False
    assert assess(None, "evil.ru", BRAND_TERMS, ALLOWLIST)["infringing"] is False
