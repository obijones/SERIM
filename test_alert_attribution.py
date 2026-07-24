"""
Tests for the advertiser-attribution guidance in the analyst alert email.

The bug these pin down is a workflow one, not a crash. An analyst receives the
alert, re-runs the same query by hand to click the ad's three-dot menu and get
the reporter/advertiser details — and the ad is not there. That is not a defect
in the search or the script: sponsored results are auction-served and audience-,
geo-, device- and budget-targeted, and impersonators rotate and cloak them, so a
manual re-search usually will not reproduce the impression. The three-dot menu
only exists while the ad serves.

So the email must never send an analyst down that path, and must always hand
them the route that survives the ad going dark: the Ads Transparency Center,
which is searchable BY LANDING DOMAIN — a value every finding already has —
plus the campaign/click IDs and the detection-time evidence.

Offline: builds synthetic Contoso findings and renders the email body. No
browser, no network, no database.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import serp_monitor as C


def _ad(**over):
    """A minimal flagged-ad dict with every field build_alert_email reads."""
    base = {
        "engine":            "google",
        "device":            "desktop",
        "query":             "contoso account login",
        "serp_url":          "https://www.google.com/search?q=contoso+account+login",
        "timestamp":         "2026-07-24T10:00:00Z",
        "headline":          "Contoso Login — Official Site",
        "display_url":       "contoso-secure-login.example",
        "ad_copy":           "Sign in to your account",
        "destination_url":   "https://contoso-secure-login.example/signin",
        "destination_host":  "contoso-secure-login.example",
        "resolution_method": "click",
        "detection_channel": C.CHANNEL_SPONSORED,
        "infringing":        True,
        "fingerprint":       "google:contoso-secure-login.example",
        "serp_screenshot":   "/evidence/serp.png",
        "dom_snapshot":      "/evidence/dom.html",
        "tracking_id":       "1234567890",
        "tracking_label":    "gad_campaignid",
    }
    base.update(over)
    return base


def _body(ads):
    msg = C.build_alert_email(ads, "2026-07-24T10:00:00Z")
    return msg.get_payload(0).get_payload(decode=True).decode("utf-8")


# --- the domain link: always there for a Google paid finding -----------------

def test_atc_domain_url_is_a_pure_function_of_the_host():
    """No live ad, no capture, no lookup — just the landing domain."""
    url = C.atc_domain_url("www.Contoso-Secure-Login.example")
    assert url is not None
    assert "adstransparency.google.com" in url
    assert "domain=contoso-secure-login.example" in url   # normalized, www stripped
    assert C.atc_domain_url(None) is None
    assert C.atc_domain_url("") is None


def test_uncaptured_google_ad_still_gets_a_transparency_center_link():
    """The failing case: nothing was captured from the live panel and the
    lookup found nothing. The analyst must still leave with a clickable,
    domain-keyed route — that is the whole point."""
    body = _body([_ad()])
    assert C.atc_domain_url("contoso-secure-login.example") in body
    assert "ADS TRANSPARENCY CENTER" in body


def test_resolved_creative_also_links_the_domain_page():
    """Even on a hit, the domain page is worth having: it lists the
    advertiser's OTHER ads, which is how a campaign gets scoped."""
    body = _body([_ad(
        atc_creative_id="CR000000000000000000",
        atc_advertiser_id="AR000000000000000000",
        atc_advertiser_name="Example Advertiser LLC",
        atc_creative_url="https://adstransparency.google.com/advertiser/AR0/creative/CR0",
    )])
    assert "CR000000000000000000" in body
    assert C.atc_domain_url("contoso-secure-login.example") in body


# --- the guidance must not send the analyst back to the SERP ----------------

def test_email_never_tells_the_analyst_to_reopen_the_ad_menu():
    """The old fallback told the analyst to re-search, click the ⋮ menu and
    Inspect Element the panel — the exact sequence that cannot work once the
    ad stops serving. Developer debugging guidance does not belong in an
    analyst alert at all; selector drift raises its own operator alert."""
    body = _body([_ad()])
    for dead_end in ("Inspect Element",
                     "check brand_monitor.log",
                     "Manually click"):
        assert dead_end not in body, f"analyst is still being sent to: {dead_end}"


def test_email_explains_why_a_re_search_comes_up_empty():
    """An empty re-search reads as 'resolved' unless the alert says otherwise."""
    body = _body([_ad()])
    assert "NOTE ON RE-SEARCHING" in body
    assert "auction-served" in body


# --- scope: the link is meaningless for Bing and for organic ----------------

def test_no_transparency_center_section_for_bing():
    """Microsoft has no equivalent public ad archive — offering the link would
    be a dead end dressed up as a lead."""
    body = _body([_ad(engine="bing", tracking_label="msclkid",
                      serp_url="https://www.bing.com/search?q=contoso")])
    assert "adstransparency.google.com" not in body
    assert "ADS TRANSPARENCY CENTER" not in body


def test_no_transparency_center_section_for_organic():
    """An SEO-poisoned result was never an ad: no advertiser, no creative, no
    archive entry. Its route is the registrar and the host."""
    body = _body([_ad(detection_channel=C.CHANNEL_ORGANIC)])
    assert "adstransparency.google.com" not in body
    assert "ADS TRANSPARENCY CENTER" not in body
    assert "Registrar abuse contact" in body


def test_unresolved_host_degrades_without_a_broken_link():
    """A finding whose landing host never resolved has nothing to key on. It
    must say so rather than emit a link with an empty domain."""
    body = _body([_ad(destination_url=None, destination_host=None)])
    assert "domain=" not in body
    assert "ADS TRANSPARENCY CENTER" in body       # section still explains itself
