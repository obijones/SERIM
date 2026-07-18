"""
serp_monitor.py: Search Engine Results Page Monitor (Multi-Engine)

Repairs advertiser attribution capture (My Ad Center panel), which
had silently failed since Google rotated its ad-menu selectors. v6 remains on
disk as a known-good fallback.

Dependencies: see requirements.txt
Usage:
    python serp_monitor.py                        # single run, both engines, both devices
    python serp_monitor.py --engine google        # Google only (both devices)
    python serp_monitor.py --engine bing          # Bing only (both devices)
    python serp_monitor.py --device desktop       # desktop fingerprint only (both engines)
    python serp_monitor.py --device mobile        # mobile fingerprint only (both engines)
    python serp_monitor.py --engine google --device mobile  # combine freely
    python serp_monitor.py --schedule             # scheduled, both engines, both devices
    python serp_monitor.py --schedule --google-interval 240 --bing-interval 120
    python serp_monitor.py --triage example-partner.org
    python serp_monitor.py --list-triage
    python serp_monitor.py --help                 # full flag reference

Prerequisites:
    Run setup_profile.py ONCE before first use to initialize the browser
    profile with Google consent/cookie state.
    Bing does not require a persistent profile; no setup needed.
"""

import asyncio
import json
import logging
import os
import re
import smtplib
import argparse
import schedule
import sqlite3
import time
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from pathlib import Path
from urllib.parse import urlparse, parse_qs

from dotenv import load_dotenv
from playwright.async_api import async_playwright, Page, ElementHandle
from playwright_stealth import Stealth
from pyvirtualdisplay import Display

from domainmatch import host_of, host_in
import brandmatch
import findings_store
import url_resolve

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

load_dotenv()

# ---------------------------------------------------------------------------
# Brand terms to monitor
# ---------------------------------------------------------------------------
# Add additional search queries below in the same format: "search term here"
# Each string is submitted to BOTH search engines exactly as written.
# Examples of terms to add when ready:
#   "angry ip scanner",
#   "account login",
#   "remote admin tool",
#   "archive tool",
# ---------------------------------------------------------------------------
BRAND_TERMS = [
    "Place search terms here",
    "Place second search term here"
]

# ---------------------------------------------------------------------------
# Search engine configuration
# ---------------------------------------------------------------------------
# Each engine entry defines:
#   url_template   : search URL with {query} placeholder
#   ad_selectors   : ordered list of CSS selectors to try for ad containers
#   headline_sel   : CSS selector for the ad headline element
#   display_url_selectors : ordered list for the visible display URL
#   ad_copy_selectors     : ordered list for the ad body copy text
#   tracking_param : URL parameter containing the campaign/click ID
# ---------------------------------------------------------------------------
SEARCH_ENGINES = {
    "google": {
        "url_template": "https://www.google.com/search?q={query}",
        "ad_selectors": [
            "div#tads .uEierd",
            "div#tads [data-text-ad]",
            "div#tads li",
            "[data-text-ad]",
            ".uEierd",
        ],
        "headline_sel":        'div[role="heading"]',
        "display_url_selectors": [".qzEoUe", ".x2VHCd", "cite", "span[aria-label]"],
        "ad_copy_selectors":     [".MUxGbd", ".yDYNvb", ".lEBKkf"],
        "tracking_param":      "gad_campaignid",
        "tracking_fallback":   "adwordscampaignid",
        "click_id_param":      "gclid",
        "complaint_url":       "https://services.google.com/inquiry/aw_tmcomplaint",
        # Channel classification (see detect_channel). Google's ad_selectors are
        # already scoped to div#tads, and a replay of 25 SERPs found 0 elements
        # leaking in from organic containers, but classify explicitly anyway
        # rather than assuming it.
        "sponsored_container_sel": "#tads, #tadsb, [data-text-ad], .uEierd",
        "organic_container_sel":   "#rso .g, #search .g",
        "generic_selectors":       set(),
    },
    "bing": {
        "url_template": "https://www.bing.com/search?q={query}",
        "ad_selectors": [
            "#b_results .b_ad",
            ".b_adLastChild",
            "li.b_ad",
            "[data-bm]",
        ],
        "headline_sel":        "h2 a, .b_title h2 a",
        "display_url_selectors": [
            ".b_adurl cite",
            ".b_caption .b_adurl",
            ".b_adurl",
            "cite",
        ],
        "ad_copy_selectors":     [".b_caption p", ".b_snippet", ".b_dList"],
        "tracking_param":      "msclkid",
        "tracking_fallback":   None,
        "click_id_param":      "msclkid",
        # Microsoft Advertising trademark complaint form
        "complaint_url":       "https://about.ads.microsoft.com/en/forms/policies/intellectual-property-complaint-form",
        # Channel classification (see detect_channel).
        #
        # "[data-bm]" in ad_selectors above is NOT an ad container; it is a
        # generic Bing attribute carried by hundreds of unrelated elements. Bing
        # serves no ads on most of these queries (only 54 of 331 captured SERPs
        # contained any ad markup at all), so the selector chain falls through to
        # it and the monitor ends up scanning the ORGANIC results.
        #
        # That is how 247 of 301 Bing findings were produced, including every
        # one of the confirmed phishing sites (phish-example-1.com,
        # contoso-login.com, phish-example-4.com, phish-example-5.com,
        # phish-example-6.com), none of which was ever a paid ad. The fallback is
        # therefore KEPT deliberately: it is a real second detector for SEO
        # poisoning. What was wrong was the LABEL, not the detection, so every
        # finding now carries a channel, and the takedown route follows from it.
        "sponsored_container_sel": ".b_ad, .b_adLastChild, li.b_ad, .b_adurl, .b_adSlug",
        "organic_container_sel":   "li.b_algo",
        # Selectors that are not ad containers. A non-ad element matched only by
        # one of these is page furniture, not a missed ad, so its rejection is
        # not worth a log line (this alone was 6,111 lines of "Skipping
        # non-visible or empty ad element").
        "generic_selectors":       {"[data-bm]"},
    },
}

# Detection channels: HOW a result reached the SERP. Orthogonal to whether it
# infringes the brand (see brandmatch.py).
CHANNEL_SPONSORED = "sponsored_ad"   # a paid ad     -> engine ads-policy complaint
CHANNEL_ORGANIC   = "organic"        # a ranked page -> registrar / hosting abuse
CHANNEL_UNKNOWN   = "unknown"

# Engines to check on each run, overridden by --engine CLI flag
ACTIVE_ENGINES = list(SEARCH_ENGINES.keys())  # ["google", "bing"]

# Display URLs that are legitimate domains hardcoded at deploy time
ALLOWLIST_DOMAINS = [
    "contoso.com",
    "example.com",
]

# Persistent browser profile directory, created by setup_profile.py
# Used for Google (consent cookie required). Bing does not require it
# but benefits from the same profile for consistent fingerprinting.
PROFILE_DIR  = os.getenv("PROFILE_DIR",  "/path/to/browser_profile/")

# Analyst triage list: JSON file of benign third-party domains
# Shared across both search engines; a triaged domain is suppressed everywhere
TRIAGE_FILE  = os.getenv("TRIAGE_FILE",  "/path/to/triaged_domains/")

# Output directory for evidence artifacts
EVIDENCE_DIR = Path(os.getenv("EVIDENCE_DIR", "/path/to/evidence_directory"))

# SQLite campaign store: dedup + case identity + first/last-seen (v7, Lens #1
# gap #4). Seed historical first_seen dates once with backfill_findings.py.
FINDINGS_DB = os.getenv("FINDINGS_DB", "/path/to/findings.db")

# Ads Transparency Center enrichment. Looks up each flagged destination
# domain in adstransparency.google.com, which is searchable by domain and
# retains ads ~13 months after last display, so it yields the advertiser's
# verified legal name plus a stable advertiser/creative (AR…/CR…) ID even when
# the ad can no longer be reproduced in a live SERP. Coverage is partial: only
# verified advertisers appear, and creatives are withdrawn when an account is
# suspended, so expect a fraction of malicious domains to return zero ads.
ENABLE_TRANSPARENCY_LOOKUP = os.getenv("ENABLE_TRANSPARENCY_LOOKUP", "1") != "0"
TRANSPARENCY_REGION        = os.getenv("TRANSPARENCY_REGION", "US")
# Cap per run so a large flagged set can't blow up wall-clock.
TRANSPARENCY_MAX_DOMAINS   = int(os.getenv("TRANSPARENCY_MAX_DOMAINS", "25"))

# SMTP settings, populate via .env file
SMTP_HOST     = os.getenv("SMTP_HOST",     "smtp.mailgun.org")
SMTP_PORT     = int(os.getenv("SMTP_PORT", 587))
SMTP_USER     = os.getenv("SMTP_USER",     "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
ALERT_FROM    = os.getenv("ALERT_FROM",    "security-team@yourdomain.com")
# Multiple recipients: comma-separated in .env
# ALERT_TO=analyst1@example.com,analyst2@example.com
ALERT_TO_RAW  = os.getenv("ALERT_TO", "analyst@yourdomain.com")
ALERT_TO_LIST = [a.strip() for a in ALERT_TO_RAW.split(",") if a.strip()]
ALERT_TO      = ", ".join(ALERT_TO_LIST)

# Log file
LOG_FILE = os.getenv("LOG_FILE", "brand_monitor.log")

# ---------------------------------------------------------------------------
# Browser fingerprint profiles
# ---------------------------------------------------------------------------
# Each profile is passed to a separate Playwright browser context so the
# script competes in both the desktop and mobile ad auctions per run.
# Google and Bing use the User-Agent + viewport + is_mobile flag together
# to route requests into the correct auction bucket.
#
# DESKTOP: standard Windows Chrome fingerprint used since v2.
# MOBILE:  Pixel 8 Android Chrome fingerprint. is_mobile=True and
#            has_touch=True are required; without them Playwright sends
#            a desktop UA with a narrow viewport, which Google treats as
#            a resized desktop browser rather than a real mobile device.
# ---------------------------------------------------------------------------
DESKTOP_PROFILE = {
    "user_agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/148.0.7778.96 Safari/537.36"
    ),
    "viewport":            {"width": 1366, "height": 768},
    "device_scale_factor": 1.0,
    "is_mobile":           False,
    "has_touch":           False,
    "label":               "desktop",
}

MOBILE_PROFILE = {
    "user_agent": (
        "Mozilla/5.0 (Linux; Android 14; Pixel 8) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/148.0.6440.91 Mobile Safari/537.36"
    ),
    "viewport":            {"width": 390, "height": 844},
    "device_scale_factor": 2.75,
    "is_mobile":           True,
    "has_touch":           True,
    "label":               "mobile",
}

# Profiles active per run; both by default.
# Override to [DESKTOP_PROFILE] or [MOBILE_PROFILE] to restrict if needed.
DEVICE_PROFILES = [DESKTOP_PROFILE, MOBILE_PROFILE]

# Legacy aliases, used by health check probe and other single-context paths
# that always need a desktop UA/viewport (DOM probe, cookie check, etc.).
VIEWPORT   = DESKTOP_PROFILE["viewport"]
USER_AGENT = DESKTOP_PROFILE["user_agent"]

# Seconds to wait after page load before scraping
DWELL_TIME = 3

# Warn when Google cookies expire within this many days
COOKIE_WARN_DAYS = 30

# Minimum DOM byte count for a real SERP (Google and Bing)
DOM_MIN_BYTES = 50_000

# URL used to probe Google profile health
HEALTH_CHECK_URL = "https://www.google.com/search?q=weather"

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(LOG_FILE, mode="a"),
    ],
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Attribution capture stats (v7, self-healing)
# ---------------------------------------------------------------------------
# Tracks whether the My Ad Center panel is actually being captured on Google
# desktop ads. v6 failed silently; selectors had rotated, so every attempt
# produced null advertiser fields with no operator-visible signal. A run-level
# success counter makes that drift obvious immediately (see
# _report_attribution_health, called at the end of each run_once).
# Reset at the start of every run_once() call.
# ---------------------------------------------------------------------------
ATTRIBUTION_STATS = {"attempted": 0, "menu_found": 0, "panel_captured": 0,
                     "accordion_expanded": 0}

# ---------------------------------------------------------------------------
# Campaign / Click ID extraction
# ---------------------------------------------------------------------------

def extract_tracking_id(url: str | None, engine_key: str) -> tuple[str | None, str]:
    """
    Extracts the platform campaign or click ID from a tracking URL.

    Google: gad_campaignid identifies the advertiser account directly.

    Bing: Two tracking modes depending on advertiser configuration:
      1. Auto-tagging enabled  → msclkid parameter is appended by Bing
      2. Auto-tagging disabled → advertiser uses UTM parameters instead.
         In this case utm_campaign contains the campaign ID and
         utm_content contains ad_id_adgroup_id concatenated with underscore.

    The msclkid is preferred when present. UTM parameters are extracted
    as a fallback and all available IDs are returned in the label so the
    analyst has the full picture for the trademark complaint submission.

    Returns (id_value, id_label) for inclusion in the alert email.
    """
    if not url:
        return None, ""

    engine   = SEARCH_ENGINES.get(engine_key, {})
    primary  = engine.get("tracking_param")
    fallback = engine.get("tracking_fallback")

    try:
        params = parse_qs(urlparse(url).query)

        # Primary platform ID (gad_campaignid for Google, msclkid for Bing)
        if primary and primary in params:
            val = params[primary][0]
            log.info(f"  {engine_key} tracking ID ({primary}): {val}")
            return val, primary

        # Configured fallback
        if fallback and fallback in params:
            val = params[fallback][0]
            log.info(f"  {engine_key} tracking ID ({fallback}): {val}")
            return val, fallback

        # Bing UTM fallback: when advertiser has auto-tagging disabled,
        # Bing does not append msclkid. The advertiser's UTM parameters
        # carry the campaign attribution instead.
        if engine_key == "bing":
            utm_parts = []

            if "utm_campaign" in params:
                campaign_id = params["utm_campaign"][0]
                utm_parts.append(f"utm_campaign={campaign_id}")
                log.info(f"  Bing UTM campaign ID: {campaign_id}")

            if "utm_content" in params:
                # utm_content typically encodes ad_id_adgroup_id
                content_val = params["utm_content"][0]
                utm_parts.append(f"utm_content={content_val}")
                log.info(f"  Bing UTM content (ad/adgroup ID): {content_val}")

            if "utm_term" in params:
                term_val = params["utm_term"][0]
                utm_parts.append(f"utm_term={term_val}")
                log.info(f"  Bing UTM term: {term_val}")

            if utm_parts:
                combined = " | ".join(utm_parts)
                label    = "UTM (auto-tagging disabled)"
                log.info(f"  Bing tracking via UTM params — msclkid absent")
                return combined, label

    except Exception as e:
        log.warning(f"  Tracking ID extraction failed: {e}")

    return None, ""

# ---------------------------------------------------------------------------
# Evidence directory
# ---------------------------------------------------------------------------

def ensure_evidence_dir() -> None:
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# Analyst triage list management
# ---------------------------------------------------------------------------

def load_triaged_domains() -> set[str]:
    """
    Loads the analyst-triaged benign domain list from TRIAGE_FILE.
    Returns an empty set if the file does not exist yet.
    Domains are stored as lowercase for case-insensitive matching.
    Shared across Google and Bing; a triaged domain is suppressed everywhere.
    """
    path = Path(TRIAGE_FILE)
    if not path.exists():
        return set()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        # Canonicalize every stored entry to a bare host through the same
        # extractor used for comparison (v7). Entries that fail to parse are
        # dropped with a warning rather than silently kept in a form that could
        # never match. host_of accepts an already-bare host unchanged.
        domains = set()
        for raw in data.get("triaged_domains", []):
            host = host_of(raw)
            if host is None:
                log.warning(f"Ignoring unparseable triage entry: {raw!r}")
                continue
            domains.add(host)
        if domains:
            log.info(f"Loaded {len(domains)} triaged domain(s) from {TRIAGE_FILE}")
        return domains
    except Exception as e:
        log.warning(f"Could not load triage file {TRIAGE_FILE}: {e}")
        return set()


def save_triaged_domain(domain: str) -> str | None:
    """
    Adds a domain to the persistent triage list and saves the file.
    Called when an analyst marks a finding benign via --triage flag.
    """
    host = host_of(domain)
    if host is None:
        log.error(f"Cannot triage unparseable value: {domain!r}")
        return None

    path    = Path(TRIAGE_FILE)
    domains = load_triaged_domains()

    if host in domains:
        log.info(f"Domain already in triage list: {host}")
        return host

    domains.add(host)
    data = {"triaged_domains": sorted(domains)}
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    log.info(f"Added '{host}' to triage list — saved to {TRIAGE_FILE}")
    return host


async def detect_channel(el: ElementHandle, engine_key: str) -> str:
    """
    How did this result reach the page, by paid placement or organic ranking?

    Decided from the element's own position in the DOM (nearest enclosing
    container), not from which selector happened to match it, so it stays
    correct even as the selector list changes.
    """
    engine = SEARCH_ENGINES[engine_key]
    for sel, channel in (
        (engine.get("sponsored_container_sel"), CHANNEL_SPONSORED),
        (engine.get("organic_container_sel"),   CHANNEL_ORGANIC),
    ):
        if not sel:
            continue
        try:
            # closest() includes the element itself, so a container that IS the
            # matched element classifies correctly.
            if await el.evaluate("(e, s) => !!e.closest(s)", sel):
                return channel
        except Exception:
            pass
    return CHANNEL_UNKNOWN


async def resolve_container(el: ElementHandle, engine_key: str) -> ElementHandle:
    """
    Walk an element up to the result container it belongs to.

    Required for organic results: the generic "[data-bm]" fallback matches a
    SUB-NODE of a Bing result, not the result itself, and the headline selector
    ("h2 a") finds nothing beneath it, so every organic result extracted as
    headline "N/A". Since the brand-infringement rule reads the TITLE, leaving
    this unfixed would have made infringement silently return False on every
    organic result, i.e. on exactly the SEO-poisoning cases it exists to catch.
    """
    engine = SEARCH_ENGINES[engine_key]
    sels = [s for s in (engine.get("sponsored_container_sel"),
                        engine.get("organic_container_sel")) if s]
    for sel in sels:
        try:
            handle = await el.evaluate_handle("(e, s) => e.closest(s)", sel)
            container = handle.as_element()
            if container:
                return container
        except Exception:
            pass
    return el


async def is_valid_ad(ad: ElementHandle) -> bool:
    """
    Validates that a matched ad element is a real visible rendered ad
    and not a ghost container, hidden slot, or structural wrapper.

    Bing's DOM contains structural .b_ad elements that match the selector
    but are empty wrappers with no visible content, no anchors, and no
    viewport presence. These produce N/A headline/display_url extractions
    and cause element screenshot timeouts.

    Three checks must all pass:
      1. Element is visible in the DOM (not display:none / visibility:hidden)
      2. Element contains at least one anchor tag with an href
      3. Element has non-trivial inner text (rules out empty containers)
    """
    try:
        # Check 1: visibility
        is_visible = await ad.is_visible()
        if not is_visible:
            return False

        # Check 2: has at least one anchor
        anchor = await ad.query_selector("a[href]")
        if not anchor:
            return False

        # Check 3: has meaningful text content (more than whitespace)
        text = (await ad.inner_text()).strip()
        if len(text) < 10:
            return False

        return True

    except Exception:
        return False


def is_allowlisted(host: str | None) -> bool:
    """
    True only if the ad's host IS a brand-owned allowlist domain or a subdomain
    of one (label-boundary suffix match). The brand owns every subdomain of
    its allowlisted domain, so suffix matching is safe here and an attacker
    cannot obtain e.g. login.example.com.

    v7: replaces the v6 substring test (`domain in display_url`), which
    suppressed hostile URLs like "contoso.com.evil.ru" and Google breadcrumb
    forms like "evil.ru > example.com > login".

    Takes an already-resolved host from url_resolve.suppression_host(), which
    falls back to the ad's own link when the SERP renders no display URL. A
    host of None means no signal was recoverable -> False, fail closed, flag it.
    """
    return host_in(host, ALLOWLIST_DOMAINS)


def is_triaged(host: str | None, triaged_domains: set[str]) -> bool:
    """
    True only if the ad's host EXACTLY matches an analyst-triaged host.

    v7: exact-host match (not suffix). An analyst triages the specific host they
    reviewed, not a hosting provider so a triaged "clientportal.example" no longer
    silently suppresses "attacker.clientportal.example". Subdomain-scoped entries
    such as "play.google.com" still work because they are stored, and compared,
    as full hosts. Host of None -> False (fail closed, flag it).
    """
    return host_in(host, triaged_domains, exact=True)

# ---------------------------------------------------------------------------
# Profile health checks
# ---------------------------------------------------------------------------

def check_cookie_expiry() -> tuple[bool, str]:
    """
    Reads the Chromium profile's SQLite cookie database and checks whether
    any Google consent or session cookies are close to expiry or expired.
    Individual expired ancillary cookies (e.g. __Secure-STRP) are advisory
    warnings only the DOM probe is the authoritative health gate.
    """
    cookie_db = Path(PROFILE_DIR) / "Default" / "Cookies"
    if not cookie_db.exists():
        return False, (
            f"Cookie database not found at {cookie_db}. "
            "Run setup_profile.py to initialize the browser profile."
        )

    EPOCH_DIFF_US = 11_644_473_600 * 1_000_000
    now_us        = int(datetime.now(timezone.utc).timestamp() * 1_000_000) + EPOCH_DIFF_US
    warn_us       = now_us + (COOKIE_WARN_DAYS * 86_400 * 1_000_000)
    now_dt        = datetime.now(timezone.utc)

    expired     = []
    expiring    = []
    google_seen = 0

    try:
        import shutil, tempfile
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
            tmp_path = tmp.name
        shutil.copy2(str(cookie_db), tmp_path)

        conn   = sqlite3.connect(tmp_path)
        cursor = conn.execute(
            "SELECT host_key, name, expires_utc FROM cookies "
            "WHERE host_key LIKE '%google%' OR host_key LIKE '%gstatic%'"
        )
        rows = cursor.fetchall()
        conn.close()
        Path(tmp_path).unlink(missing_ok=True)

        for host, name, expires_utc in rows:
            if expires_utc == 0:
                continue
            google_seen += 1
            if expires_utc < now_us:
                exp_dt = datetime.fromtimestamp(
                    (expires_utc - EPOCH_DIFF_US) / 1_000_000, tz=timezone.utc
                )
                expired.append(f"{host} [{name}] expired {exp_dt.strftime('%Y-%m-%d')}")
            elif expires_utc < warn_us:
                exp_dt = datetime.fromtimestamp(
                    (expires_utc - EPOCH_DIFF_US) / 1_000_000, tz=timezone.utc
                )
                days_left = (exp_dt - now_dt).days
                expiring.append(
                    f"{host} [{name}] expires {exp_dt.strftime('%Y-%m-%d')} "
                    f"({days_left} day(s))"
                )

    except Exception as e:
        return False, f"Cookie database read failed: {e}"

    if google_seen == 0:
        return False, (
            "No Google cookies found in browser profile. "
            "Run setup_profile.py to accept Google consent and initialize cookies."
        )

    if expired:
        msg = (
            f"WARNING: {len(expired)} Google cookie(s) have expired "
            "(may be ancillary DOM probe is the authoritative check):\n  " +
            "\n  ".join(expired)
        )
        log.warning(f"[HEALTH] {msg}")

    if expiring:
        return True, (
            f"WARNING: {len(expiring)} Google cookie(s) expire within "
            f"{COOKIE_WARN_DAYS} days plan to refresh the profile soon:\n  " +
            "\n  ".join(expiring)
        )

    return True, f"Cookie health OK — {google_seen} Google cookie(s) checked."


def check_dom_size(dom_size: int, title: str, engine_key: str = "google") -> tuple[bool, str]:
    """
    Evaluates a pre-measured DOM size against the health threshold.
    """
    if dom_size < DOM_MIN_BYTES:
        return False, (
            f"[{engine_key.upper()}] DOM size {dom_size:,} bytes "
            f"(minimum {DOM_MIN_BYTES:,}). "
            f"Page title: '{title}'. "
            "Google is likely serving a consent wall. "
            "Run setup_profile.py to refresh the profile."
        )
    return True, (
        f"[{engine_key.upper()}] DOM size {dom_size:,} bytes — '{title[:60]}'"
    )


async def probe_dom_size() -> tuple[int, str]:
    """
    Opens a browser session and measures the Google SERP DOM size.
    Called only on the first run subsequent runs use live measurements.
    """
    if not Path(PROFILE_DIR).exists():
        return 0, "profile directory missing"

    try:
        async with async_playwright() as p:
            context = await p.chromium.launch_persistent_context(
                user_data_dir=PROFILE_DIR,
                headless=False,
                args=[
                    "--disable-blink-features=AutomationControlled",
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                ],
                user_agent=USER_AGENT,
                viewport=VIEWPORT,
                locale="en-US",
            )
            page = await context.new_page()
            await Stealth().apply_stealth_async(page)
            try:
                await page.goto(
                    HEALTH_CHECK_URL,
                    wait_until="networkidle",
                    timeout=20_000,
                )
                await asyncio.sleep(2)
                dom_size = len(await page.content())
                title    = await page.title()
            finally:
                await context.close()
        return dom_size, title
    except Exception as e:
        log.warning(f"[HEALTH] DOM probe error: {e}")
        return 0, str(e)


def run_profile_health_checks(dom_size: int = 0, title: str = "") -> bool:
    """
    Runs cookie expiry check and DOM size evaluation.
    DOM probe is the authoritative gate cookie issues are advisory.
    Returns True if healthy, False if setup_profile.py needs to be run.
    """
    all_healthy  = True
    dom_fail_msg = None

    cookie_ok, cookie_msg = check_cookie_expiry()
    if cookie_ok:
        log.info(f"[HEALTH] {cookie_msg}")
    else:
        log.warning(f"[HEALTH] {cookie_msg}")

    if dom_size > 0:
        dom_ok, dom_msg = check_dom_size(dom_size, title, "google")
    else:
        log.info("[HEALTH] Running DOM probe (first run)...")
        measured_size, measured_title = asyncio.run(probe_dom_size())
        dom_ok, dom_msg = check_dom_size(measured_size, measured_title, "google")

    if dom_ok:
        log.info(f"[HEALTH] {dom_msg}")
    else:
        log.error(f"[HEALTH] {dom_msg}")
        all_healthy  = False
        dom_fail_msg = dom_msg

    if not all_healthy:
        _send_profile_alert(
            cookie_msg if not cookie_ok else None,
            dom_fail_msg,
        )

    return all_healthy


def _send_profile_alert(cookie_msg: str | None, dom_msg: str | None) -> None:
    """Sends an operator alert when the browser profile needs refreshing."""
    if not SMTP_USER or not SMTP_PASSWORD:
        log.warning("[HEALTH] SMTP not configured — cannot send profile alert email.")
        return

    msg = MIMEMultipart("mixed")
    msg["Subject"] = "[BRAND MONITOR] Browser profile needs refreshing — action required"
    msg["From"]    = ALERT_FROM
    msg["To"]      = ALERT_TO

    lines = [
        "=" * 70,
        "BRAND PROTECTION — PROFILE HEALTH ALERT",
        "=" * 70,
        "",
        f"Timestamp: {datetime.now(timezone.utc).isoformat()}",
        "",
        "The brand protection monitor detected that the browser profile",
        "requires refreshing. Ad detection will be unreliable or non-functional",
        "until the profile is renewed.",
        "",
        "[ ISSUE DETAILS ]",
    ]
    if cookie_msg:
        lines += ["", f"  Cookie issue:  {cookie_msg}"]
    if dom_msg:
        lines += ["", f"  DOM probe:     {dom_msg}"]
    lines += [
        "",
        "[ REQUIRED ACTION ]",
        "  Run the following from a desktop session (not SSH):",
        "",
        "    cd /path/to/project",
        "    source bin/activate",
        "    python setup_profile.py",
        "",
        "  The cron job will resume normal operation on its next scheduled run.",
        "",
        "=" * 70,
    ]

    msg.attach(MIMEText("\n".join(lines), "plain"))

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(ALERT_FROM, ALERT_TO_LIST, msg.as_string())
        log.info(f"[HEALTH] Profile alert email sent to {ALERT_TO}")
    except Exception as e:
        log.error(f"[HEALTH] Failed to send profile alert email: {e}")

# ---------------------------------------------------------------------------
# Attribution capture health (v7, self-healing)
# ---------------------------------------------------------------------------

def _report_attribution_health() -> None:
    """
    Summarises advertiser-attribution capture for the run and raises an operator
    alert when attribution was attempted but captured zero My Ad Center panels,
    the signature of Google selector drift.

    This exists because v6 failed silently: the menu selectors had rotated, so
    every attribution attempt produced null advertiser fields with no operator-
    visible signal for weeks. A run-level success counter makes drift obvious.

    Reads the module-level ATTRIBUTION_STATS, populated by fetch_advertiser_info.
    Attribution only runs on Google desktop, so a Bing-only or mobile-only run
    reports nothing.
    """
    stats     = ATTRIBUTION_STATS
    attempted = stats["attempted"]

    if attempted == 0:
        return

    log.info(
        "[ATTRIBUTION] Capture summary — attempted: %d, menu found: %d, "
        "panel captured: %d, accordion expanded: %d"
        % (attempted, stats["menu_found"], stats["panel_captured"],
           stats["accordion_expanded"])
    )

    # v8: a panel that opens but whose "About this advertiser" accordion never
    # expands yields only menu chrome, the exact failure that produced zero
    # parsed fields across all pre-v8 history. Surface it distinctly from
    # menu/panel selector drift.
    if stats["panel_captured"] > 0 and stats["accordion_expanded"] == 0:
        log.warning(
            "[ATTRIBUTION] %d panel(s) opened but the 'About this advertiser' "
            "accordion never expanded — advertiser fields will be null. The "
            "accordion selector has likely rotated; review ACCORDION_SELECTORS "
            "in fetch_advertiser_info() (v8)."
            % stats["panel_captured"]
        )

    if stats["panel_captured"] == 0:
        msg = (
            f"Advertiser attribution attempted on {attempted} Google desktop "
            f"ad(s) but captured 0 My Ad Center panels this run "
            f"(menu button found on {stats['menu_found']}). "
            "This is the signature of Google selector drift — the three-dot menu "
            "aria-label / jsname or the panel selectors have likely rotated. "
            "Review MENU_SELECTORS and PANEL_SELECTORS in fetch_advertiser_info() "
            "and the latest [DEBUG] DOM dump in the log."
        )
        log.error(f"[ATTRIBUTION] {msg}")
        _send_attribution_alert(msg)
    elif stats["menu_found"] == 0:
        log.warning(
            "[ATTRIBUTION] Menu button never found this run — check MENU_SELECTORS."
        )


def _send_attribution_alert(detail: str) -> None:
    """Sends an operator alert when advertiser attribution stops capturing (v7)."""
    if not SMTP_USER or not SMTP_PASSWORD:
        log.warning(
            "[ATTRIBUTION] SMTP not configured — cannot send attribution alert."
        )
        return

    msg = MIMEMultipart("mixed")
    msg["Subject"] = (
        "[BRAND MONITOR] Advertiser attribution not capturing — "
        "selectors may have drifted"
    )
    msg["From"] = ALERT_FROM
    msg["To"]   = ALERT_TO

    lines = [
        "=" * 70,
        "BRAND PROTECTION — ATTRIBUTION HEALTH ALERT",
        "=" * 70,
        "",
        f"Timestamp: {datetime.now(timezone.utc).isoformat()}",
        "",
        detail,
        "",
        "[ REQUIRED ACTION ]",
        "  1. Open a flagged Google SERP in Chrome and click the ad's ⋮ menu.",
        "  2. Inspect the menu trigger and the panel dialog for the current",
        "     aria-label / jsname values.",
        "  3. Update MENU_SELECTORS / PANEL_SELECTORS in fetch_advertiser_info().",
        "",
        "  Advertiser name / location / funder — and the foreign-funder IC3",
        "  referral signal — remain unavailable until this is corrected.",
        "",
        "=" * 70,
    ]
    msg.attach(MIMEText("\n".join(lines), "plain"))

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(ALERT_FROM, ALERT_TO_LIST, msg.as_string())
        log.info(f"[ATTRIBUTION] Attribution alert email sent to {ALERT_TO}")
    except Exception as e:
        log.error(f"[ATTRIBUTION] Failed to send attribution alert email: {e}")

# ---------------------------------------------------------------------------
# Advertiser info capture (Google only)
# ---------------------------------------------------------------------------

async def fetch_advertiser_info(
    page: Page,
    ad_element: ElementHandle,
    headline: str,
    engine_key: str,
) -> dict:
    """
    Captures the 'About this ad' / 'My Ad Center' panel for Google ads whose
    headline contains brand-related terms.

    Google's My Ad Center panel is triggered by clicking the three-dot menu
    (⋮) on a sponsored ad. The panel renders in the DOM and exposes:
      - Advertiser name (e.g. 'Example Advertiser LLC')
      - Advertiser location (e.g. 'Elbonia')
      - Ad funded by (e.g. 'Jane Doe')

    Only attempted for Google ads. Bing does not expose an equivalent panel
    in an automatable form.

    v5 fixes vs v4:
      - ROOT CAUSE FIX: Menu button is searched at PAGE scope, not inside the
        ad element subtree. Google places the ⋮ button as a sibling or parent-
        adjacent node, not a descendant of the ad container matched by the ad
        selector. ad_element.query_selector() was silently finding nothing.
      - Updated menu button selectors: aria-label is now "About this ad" on
        current Google SERPs (was "More options"). Added jsname-based selector
        (EpPYLd) which is stable across class name rotations.
      - Scroll-into-view before click: prevents silent failures when the menu
        button is above or below the visible viewport.
      - Updated panel selectors to current DOM structure. Removed the overly
        broad 'div[jsname]' fallback which matched thousands of elements.
      - Added debug DOM dump: if no panel selector matches after both attempts,
        logs the visible page text near the ad for selector development.

    Returns a dict with advertiser attribution fields, all None if unavailable.
    """
    empty = {
        "advertiser_name":     None,
        "advertiser_location": None,
        "ad_funded_by":        None,
        "advertiser_panel_screenshot": None,
    }

    # Only attempt for Google
    if engine_key != "google":
        return empty

    # v7 (Phase 2): attribution runs on every flagged Google desktop ad.
    # By the time we reach this function the ad has already passed the
    # allowlist/triage filters and been flagged, so gating on an exact
    # brand-term match only cost coverage; phishing headlines like
    # "Example Account - Log In" do not contain the verbatim term "example account login"
    # (and headline can be "N/A" when extraction misses), so v6 silently skipped
    # them. We keep a soft brand-token check purely for the log, but proceed
    # regardless.
    brand_tokens   = {tok for t in BRAND_TERMS for tok in t.lower().split()}
    headline_lower = (headline or "").lower()
    if not any(tok in headline_lower for tok in brand_tokens):
        log.info(
            f"  Advertiser info: headline has no brand token ('{headline[:60]}') "
            "— attempting attribution anyway (v7)"
        )

    # Count this as an attribution attempt for run-level health tracking (v7).
    ATTRIBUTION_STATS["attempted"] += 1

    try:
        # ------------------------------------------------------------------
        # Step 1: Locate the three-dot menu button.
        #
        # ROOT CAUSE FIX (v5): Search at PAGE scope, not ad_element scope.
        #
        # Google renders the ⋮ button as a sibling or parent-adjacent node
        # relative to the ad container div matched by the ad selector. It is
        # NOT a descendant of that element, so ad_element.query_selector()
        # always returned None silently. We now use page.query_selector_all()
        # and pick the button closest to the ad element's bounding box.
        #
        # Selector notes (current as of mid-2026):
        #   aria-label="About this ad"  : primary, stable semantic label.
        #   aria-label="More options"   : legacy label, kept as fallback.
        #   [jsname="EpPYLd"]           : Google's internal jsname for the
        #                                 three-dot ad menu; survives class
        #                                 name rotations.
        #   .mNfcNd                     : current class, may rotate; lower
        #                                 priority than semantic selectors.
        # ------------------------------------------------------------------
        menu_btn = None

        # Ordered by specificity / stability
        MENU_SELECTORS = [
            # v7 PRIMARY: current Google desktop label. Confirmed in captured
            # evidence DOM (2026-07): the ad-menu trigger aria-label is now
            # "Why this ad?". The v6 primary "About this ad" matched nothing.
            '[aria-label="Why this ad?"]',
            'button[aria-label="Why this ad?"]',
            '[aria-label^="Why this ad"]',        # tolerate trailing-punctuation drift
            # Legacy labels, retained as fallbacks across Google A/B variants.
            '[aria-label="About this ad"]',
            'button[aria-label="About this ad"]',
            '[jsname="EpPYLd"]',
            'button[jsname="EpPYLd"]',
            '[aria-label="More options"]',        # legacy fallback
            'button[aria-label="More options"]',  # legacy fallback
            '.mNfcNd',
            'button.mNfcNd',
        ]

        # Get the ad element's bounding box so we can find the closest button
        try:
            ad_box = await ad_element.bounding_box()
        except Exception:
            ad_box = None

        for sel in MENU_SELECTORS:
            candidates = await page.query_selector_all(sel)
            if not candidates:
                continue

            if ad_box and len(candidates) > 1:
                # Multiple buttons on the page; pick the one whose centre is
                # closest to the ad element's vertical midpoint
                ad_mid_y = ad_box["y"] + ad_box["height"] / 2
                best_dist = float("inf")
                for btn in candidates:
                    try:
                        box = await btn.bounding_box()
                        if box:
                            dist = abs((box["y"] + box["height"] / 2) - ad_mid_y)
                            if dist < best_dist:
                                best_dist = dist
                                menu_btn  = btn
                    except Exception:
                        continue
            else:
                menu_btn = candidates[0]

            if menu_btn:
                log.info(f"  Found three-dot menu via page-scope selector: {sel}")
                break

        if not menu_btn:
            log.warning(
                "  Advertiser info: three-dot menu button not found at page scope. "
                "Google may have rotated selectors — check MENU_SELECTORS. "
                "Run-level attribution health alert will fire if no panel is "
                "captured this run (v7)."
            )
            return empty

        # Menu button located; record for run-level health tracking (v7).
        ATTRIBUTION_STATS["menu_found"] += 1

        # ------------------------------------------------------------------
        # Step 2: Scroll button into view, then click.
        #
        # Silent click failures occur when the button is outside the visible
        # viewport. scroll_into_view_if_needed() corrects this before click.
        # ------------------------------------------------------------------
        try:
            await menu_btn.scroll_into_view_if_needed(timeout=3_000)
            await asyncio.sleep(0.3)  # brief settle after scroll
        except Exception as e:
            log.warning(f"  Scroll-into-view failed (non-fatal): {e}")

        await menu_btn.click()
        await asyncio.sleep(2)  # wait for panel animation

        # ------------------------------------------------------------------
        # Step 3: Locate the My Ad Center / About This Ad panel.
        #
        # The panel renders in the page body as an overlay/dialog, not inside
        # the ad element. Updated selectors for current Google DOM (mid-2026):
        #   [aria-label="About This Ad"]   : dialog container, most reliable.
        #   [aria-label="My Ad Center"]    : alternate label used on some SERPs.
        #   [role="dialog"]                : semantic role fallback.
        #   [jsname="xQjRM"]               : Google's internal jsname for the
        #                                    About This Ad dialog.
        #   .yFoibb                        : retained as class fallback.
        # ------------------------------------------------------------------
        PANEL_SELECTORS = [
            '[aria-label="About This Ad"]',
            '[aria-label="About this ad"]',
            '[aria-label="My Ad Center"]',
            '[jsname="xQjRM"]',
            '[role="dialog"]',
            '.yFoibb',
        ]

        panel = None
        for panel_sel in PANEL_SELECTORS:
            panel = await page.query_selector(panel_sel)
            if panel:
                log.info(f"  My Ad Center panel found via: {panel_sel}")
                break

        if not panel:
            # Panel may still be animating in; wait and retry once
            await asyncio.sleep(2)
            for panel_sel in PANEL_SELECTORS:
                panel = await page.query_selector(panel_sel)
                if panel:
                    log.info(f"  Panel found on retry via: {panel_sel}")
                    break

        if not panel:
            # ------------------------------------------------------------------
            # Debug fallback: dump visible page text near the ad so we can
            # identify the actual panel selector without a live session.
            # ------------------------------------------------------------------
            log.warning("  Advertiser info: My Ad Center panel did not open.")
            try:
                body_text = await page.inner_text("body")
                # Capture ~800 chars around any "advertiser" keyword in the text
                idx = body_text.lower().find("advertiser")
                if idx >= 0:
                    snippet = body_text[max(0, idx - 100):idx + 700].replace("\n", " | ")
                    log.warning(f"  [DEBUG] Body text near 'advertiser': {snippet}")
                else:
                    log.warning(
                        "  [DEBUG] 'advertiser' keyword not found in page body — "
                        "panel may not have opened at all. Try increasing sleep "
                        "after menu_btn.click() if the network is slow."
                    )
            except Exception as dbg_e:
                log.warning(f"  [DEBUG] Body text dump failed: {dbg_e}")

            await page.keyboard.press("Escape")
            return empty

        # Panel located and about to be read; record for run-level health (v7).
        ATTRIBUTION_STATS["panel_captured"] += 1

        # ------------------------------------------------------------------
        # Step 3b (v8): Expand the "About this advertiser" accordion.
        #
        # ROOT CAUSE of zero parsed fields across all history: the My Ad Center
        # panel opens with "About this advertiser" as a COLLAPSED accordion. The
        # verified advertiser name and location are lazy-loaded into the DOM only
        # AFTER that row is clicked. Reading panel.inner_text() while collapsed
        # returns menu chrome only ("My Ad Center | Report | About this
        # advertiser | Why you're seeing this ad | Ad Settings | ..."), which
        # contains no label/value pairs for the Step-4 parser to find.
        #
        # We click the expander, wait for the lazy load, then continue. Search
        # is page-scoped because the accordion row lives inside the dialog but
        # some Google variants render its expanded content as a sibling overlay.
        # ------------------------------------------------------------------
        ACCORDION_SELECTORS = [
            '[aria-label="About this advertiser"]',
            '[aria-label="About this advertiser"] button',
            'button[aria-label="About this advertiser"]',
            # Some variants label the row "About the advertiser".
            '[aria-label="About the advertiser"]',
        ]
        accordion = None
        for acc_sel in ACCORDION_SELECTORS:
            accordion = await panel.query_selector(acc_sel) or await page.query_selector(acc_sel)
            if accordion:
                break
        # Text fallback: find a clickable row whose text is the accordion label.
        if not accordion:
            for cand in await panel.query_selector_all('[role="button"], button, div[jsaction]'):
                try:
                    ctext = (await cand.inner_text()).strip().lower()
                except Exception:
                    continue
                if ctext.startswith("about this advertiser") or ctext.startswith("about the advertiser"):
                    accordion = cand
                    break

        if accordion:
            try:
                await accordion.scroll_into_view_if_needed(timeout=2_000)
                await accordion.click()
                # Wait for the verified name/location to lazy-load in. Poll for
                # the panel text to grow past the collapsed-chrome baseline
                # rather than sleeping a fixed interval.
                baseline_len = len((await panel.inner_text()) or "")
                for _ in range(10):  # up to ~3s
                    await asyncio.sleep(0.3)
                    if len((await panel.inner_text()) or "") > baseline_len + 5:
                        break
                log.info("  Expanded 'About this advertiser' accordion (v8).")
                ATTRIBUTION_STATS["accordion_expanded"] += 1
            except Exception as e:
                log.warning(f"  'About this advertiser' click failed (non-fatal): {e}")
        else:
            log.warning(
                "  'About this advertiser' accordion row not found — parsing "
                "collapsed panel (advertiser fields likely unavailable). Google "
                "may have changed the panel layout (v8)."
            )

        # ------------------------------------------------------------------
        # Step 4: Extract advertiser attribution fields from panel text.
        # ------------------------------------------------------------------
        panel_text = await panel.inner_text()
        log.info(f"  Panel text: {panel_text[:300].replace(chr(10), ' | ')}")

        advertiser_name     = None
        advertiser_location = None
        ad_funded_by        = None

        # Parse panel text line by line.
        # Google's panel label/value pairs appear on consecutive lines:
        #   "Advertiser"         → next line is the name
        #   "Location"           → next line is the country
        #   "Ad funded by"       → next line is the funder name
        # Some variants use inline format: "Paid for by JOHN DOE"
        panel_lines = [ln.strip() for ln in panel_text.split("\n") if ln.strip()]
        for i, line in enumerate(panel_lines):
            ll = line.lower()
            if ll in ("advertiser", "advertiser name"):
                if i + 1 < len(panel_lines):
                    advertiser_name = panel_lines[i + 1]
            elif ll == "location":
                if i + 1 < len(panel_lines):
                    advertiser_location = panel_lines[i + 1]
            elif ll in ("ad funded by", "funded by"):
                if i + 1 < len(panel_lines):
                    ad_funded_by = panel_lines[i + 1]
            # Inline formats
            elif ll.startswith("paid for by"):
                ad_funded_by = line[len("paid for by"):].strip()
            elif ll.startswith("ad funded by"):
                ad_funded_by = line[len("ad funded by"):].strip()
            # v7 (Phase 3): inline colon-delimited variants, e.g.
            #   "Advertiser: Example Advertiser LLC"  /  "Location: Elbonia"
            elif ll.startswith("advertiser:") and advertiser_name is None:
                advertiser_name = line.split(":", 1)[1].strip() or advertiser_name
            elif ll.startswith("location:") and advertiser_location is None:
                advertiser_location = line.split(":", 1)[1].strip() or advertiser_location
            # "About this ad" heading followed by advertiser name on next line
            elif ll in ("about this ad", "about these results") and advertiser_name is None:
                if i + 1 < len(panel_lines):
                    candidate = panel_lines[i + 1]
                    # Skip if it looks like a UI label rather than a name
                    if candidate.lower() not in ("advertiser", "location", "ad funded by"):
                        advertiser_name = candidate
            # v8: expanded "About this advertiser" accordion. Layout is:
            #   About this advertiser
            #   <Advertiser legal name>       e.g. "Example Advertiser LLC"
            #   Verified                      (optional trust badge)
            #   <Location>                    e.g. "United States"
            # Walk forward past chrome/badge lines to take the name, then the
            # next non-badge line as the location.
            elif ll in ("about this advertiser", "about the advertiser"):
                _skip = {"verified", "about this advertiser", "about the advertiser",
                         "advertiser", "location"}
                j = i + 1
                while j < len(panel_lines) and panel_lines[j].lower() in _skip:
                    j += 1
                if j < len(panel_lines) and advertiser_name is None:
                    advertiser_name = panel_lines[j]
                    k = j + 1
                    while k < len(panel_lines) and panel_lines[k].lower() in _skip:
                        k += 1
                    if k < len(panel_lines) and advertiser_location is None:
                        advertiser_location = panel_lines[k]

        # ------------------------------------------------------------------
        # Step 5: Screenshot the panel as evidence.
        # ------------------------------------------------------------------
        panel_screenshot_path = None
        try:
            safe_headline = headline[:40].replace(" ", "_").replace("/", "_")
            ts            = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            panel_path    = EVIDENCE_DIR / f"advertiser_panel_{ts}_{safe_headline}.png"
            await panel.screenshot(path=str(panel_path))
            panel_screenshot_path = str(panel_path)
            log.info(f"  Advertiser panel screenshot: {panel_path}")
        except Exception as e:
            log.warning(f"  Advertiser panel screenshot failed: {e}")

        # Log attribution findings at WARNING level so they surface in cron logs
        if advertiser_name:
            log.warning(f"  Advertiser name:     {advertiser_name}")
        if advertiser_location:
            log.warning(f"  Advertiser location: {advertiser_location}")
        if ad_funded_by:
            log.warning(f"  Ad funded by:        {ad_funded_by}")
        if not any([advertiser_name, advertiser_location, ad_funded_by]):
            log.warning(
                "  Panel opened but no attribution fields parsed. "
                f"Raw panel text: {panel_text[:400].replace(chr(10), ' | ')}"
            )

        # Close the panel before continuing
        await page.keyboard.press("Escape")
        await asyncio.sleep(0.5)

        return {
            "advertiser_name":             advertiser_name,
            "advertiser_location":         advertiser_location,
            "ad_funded_by":                ad_funded_by,
            "advertiser_panel_screenshot": panel_screenshot_path,
        }

    except Exception as e:
        log.warning(f"  Advertiser info capture failed: {e}")
        try:
            await page.keyboard.press("Escape")
        except Exception:
            pass
        return empty


# ---------------------------------------------------------------------------
# Ads Transparency Center lookup (v8)
# ---------------------------------------------------------------------------

# /advertiser/AR<digits>/creative/CR<digits>: the durable identifiers Google's
# Transparency Center assigns. AR = advertiser account, CR = creative (the ad).
_ATC_CREATIVE_RE = re.compile(r"/advertiser/(AR\d+)/creative/(CR\d+)")


def _normalize_domain(host: str | None) -> str | None:
    """Reduce a destination host to the registrable-ish form ATC expects."""
    if not host:
        return None
    host = host.strip().lower()
    if host.startswith("www."):
        host = host[4:]
    return host or None


async def _lookup_one_domain(page: Page, domain: str) -> dict:
    """
    Query the Transparency Center for a single domain and extract the advertiser
    identity + first creative permalink. Returns a result dict (fields None when
    the domain has no live/retained ads). Never raises; errors are captured in
    the returned dict so one bad domain can't abort the batch.
    """
    result = {
        "domain":                 domain,
        "atc_advertiser_name":    None,
        "atc_advertiser_verified": False,
        "atc_advertiser_id":      None,
        "atc_creative_id":        None,
        "atc_creative_url":       None,
        "atc_ad_count":           None,
        "atc_screenshot":         None,
        "atc_error":              None,
    }
    url = (
        "https://adstransparency.google.com/"
        f"?region={TRANSPARENCY_REGION}&domain={domain}"
    )
    try:
        await page.goto(url, timeout=45_000, wait_until="networkidle")
        # The ad grid renders client-side after networkidle; give it a beat.
        await asyncio.sleep(3)
        body_text = await page.inner_text("body")

        # Ad count, e.g. "1 ad" / "0 ads" / "~6K ads".
        m_count = re.search(r"([~\d.,KkMm]+)\s+ads?\b", body_text)
        if m_count:
            result["atc_ad_count"] = m_count.group(1)

        # First creative permalink → advertiser + creative IDs.
        for a in await page.query_selector_all("a"):
            href = await a.get_attribute("href")
            if not href:
                continue
            m = _ATC_CREATIVE_RE.search(href)
            if m:
                result["atc_advertiser_id"] = m.group(1)
                result["atc_creative_id"]   = m.group(2)
                result["atc_creative_url"]  = (
                    "https://adstransparency.google.com"
                    f"/advertiser/{m.group(1)}/creative/{m.group(2)}"
                    f"?region={TRANSPARENCY_REGION}"
                )
                break

        # Advertiser display name: the line immediately preceding a "Verified"
        # marker on the results page, else the first non-chrome content line.
        lines = [ln.strip() for ln in body_text.split("\n") if ln.strip()]
        _CHROME = {
            "verified", "ads transparency center", "sign in", "faq",
            "all topics", "political ads", "search", "any time",
            "all platforms", "all formats",
        }
        for i, ln in enumerate(lines):
            if ln.lower() == "verified":
                result["atc_advertiser_verified"] = True
                if i > 0 and lines[i - 1].lower() not in _CHROME:
                    result["atc_advertiser_name"] = lines[i - 1]
                break

        # Screenshot as durable evidence (only worth keeping when ads exist).
        if result["atc_creative_id"] or (
            result["atc_ad_count"] not in (None, "0")
        ):
            ts   = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            safe = re.sub(r"[^A-Za-z0-9._-]", "_", domain)
            path = EVIDENCE_DIR / f"atc_{safe}_{ts}.png"
            try:
                await page.screenshot(path=str(path), full_page=True)
                result["atc_screenshot"] = str(path)
            except Exception as e:
                log.warning(f"  [ATC] Screenshot failed for {domain}: {e}")

        if result["atc_creative_id"]:
            log.warning(
                f"  [ATC] {domain}: advertiser '{result['atc_advertiser_name']}' "
                f"({'verified' if result['atc_advertiser_verified'] else 'unverified'}) "
                f"— creative {result['atc_creative_id']} — {result['atc_creative_url']}"
            )
        else:
            log.info(
                f"  [ATC] {domain}: no retained creative "
                f"(ad count: {result['atc_ad_count']})"
            )
    except Exception as e:
        result["atc_error"] = str(e)
        log.warning(f"  [ATC] Lookup failed for {domain}: {e}")
    return result


async def lookup_transparency_center(domains: list[str]) -> dict:
    """
    Look up a batch of destination domains in the Ads Transparency Center.

    Runs in its own plain (unauthenticated) Chromium context; ATC needs no
    login and must NOT reuse the SERP persistent profile. Returns a mapping of
    normalized domain -> result dict. Fails open: any error yields an empty map
    so enrichment never blocks the alert path.
    """
    normalized = []
    seen = set()
    for d in domains:
        nd = _normalize_domain(d)
        if nd and nd not in seen:
            seen.add(nd)
            normalized.append(nd)

    if not normalized:
        return {}

    if len(normalized) > TRANSPARENCY_MAX_DOMAINS:
        log.warning(
            f"[ATC] {len(normalized)} domains to look up — capping at "
            f"{TRANSPARENCY_MAX_DOMAINS} this run (raise TRANSPARENCY_MAX_DOMAINS "
            "to cover more). Remaining domains are skipped, not lost — they "
            "recur on the next run."
        )
        normalized = normalized[:TRANSPARENCY_MAX_DOMAINS]

    results: dict = {}
    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context()
            page    = await context.new_page()
            for domain in normalized:
                results[domain] = await _lookup_one_domain(page, domain)
            await context.close()
            await browser.close()
    except Exception as e:
        log.error(f"[ATC] Transparency Center batch failed (continuing): {e}")

    hits = sum(1 for r in results.values() if r.get("atc_creative_id"))
    log.info(
        f"[ATC] Looked up {len(results)} domain(s); "
        f"{hits} yielded a creative ID."
    )
    return results


# ---------------------------------------------------------------------------
# Evidence capture
# ---------------------------------------------------------------------------

async def capture_evidence(
    page: Page,
    ad_element: ElementHandle,
    query: str,
    engine_key: str,
    timestamp: str,
    ad_index: int,
    device_label: str = "desktop",
    display_url: str | None = None,
) -> dict:
    """
    Captures SERP screenshot, ad screenshot, DOM snapshot, DOM destination
    hints, and resolved landing page URL for a flagged ad.
    engine_key and device_label are included in filenames so desktop and
    mobile artifacts are clearly separated on disk.
    My Ad Center panel capture is only attempted on desktop; the panel DOM
    structure on mobile SERPs differs from desktop and requires separate selectors.
    """
    safe_query  = query.replace(" ", "_")
    base_name   = f"{timestamp}_{engine_key}_{device_label}_{safe_query}_ad{ad_index}"

    serp_path = EVIDENCE_DIR / f"{base_name}_serp.png"
    ad_path   = EVIDENCE_DIR / f"{base_name}_ad.png"
    dom_path  = EVIDENCE_DIR / f"{base_name}_dom.html"

    await page.screenshot(path=str(serp_path), full_page=True)
    log.info(f"  SERP screenshot saved: {serp_path}")

    try:
        await ad_element.screenshot(path=str(ad_path))
        log.info(f"  Ad element screenshot saved: {ad_path}")
    except Exception as e:
        log.warning(f"  Ad element screenshot failed: {e}")
        ad_path = None

    if not dom_path.exists():
        dom = await page.content()
        dom_path.write_text(dom, encoding="utf-8")
        log.info(f"  DOM snapshot saved: {dom_path}")

    # ------------------------------------------------------------------
    # DOM destination hint extraction
    # ------------------------------------------------------------------
    dest_hint   = None
    hint_source = None

    for sel, attrs in [
        ("[data-dtld]",       ["data-dtld"]),
        ("[data-final-url]",  ["data-final-url"]),
        ("a[ping]",           ["ping"]),
        ("[data-rw]",         ["data-rw"]),
        ("[data-u]",          ["data-u"]),   # Bing uses data-u for destination
    ]:
        try:
            el = await ad_element.query_selector(sel)
            if el:
                for attr in attrs:
                    val = await el.get_attribute(attr)
                    if val:
                        parsed = urlparse(val)
                        domain = parsed.netloc or val
                        if domain and not any(
                            skip in domain for skip in [
                                "google", "doubleclick", "googleadservices",
                                "googlesyndication", "gstatic",
                                "bing.com", "msn.com", "microsoft.com",
                                "bat.bing.com", "c.bing.com",
                            ]
                        ):
                            dest_hint   = val
                            hint_source = f"{sel} → {attr}"
                            log.info(f"  DOM destination hint ({hint_source}): {dest_hint}")
                            break
            if dest_hint:
                break
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Advertiser attribution (Google desktop only, brand-term headlines)
    # ------------------------------------------------------------------
    # My Ad Center panel capture is only attempted on the desktop context.
    # The mobile SERP renders a different DOM layout for the About This Ad
    # panel; the existing selectors in fetch_advertiser_info() target the
    # desktop structure and will reliably miss on mobile. Mobile findings
    # still capture full evidence (screenshot, DOM, tracking ID, destination).
    _headline_quick = "N/A"
    try:
        _hl_el = await ad_element.query_selector('div[role="heading"]')
        if _hl_el:
            _headline_quick = (await _hl_el.inner_text()).strip()
    except Exception:
        pass

    if device_label == "desktop":
        advertiser_info = await fetch_advertiser_info(
            page, ad_element, _headline_quick, engine_key
        )
    else:
        log.info("  Advertiser info: skipped on mobile context (desktop only)")
        advertiser_info = {
            "advertiser_name":             None,
            "advertiser_location":         None,
            "ad_funded_by":                None,
            "advertiser_panel_screenshot": None,
        }

    # ------------------------------------------------------------------
    # Destination resolution (v7, Lens #1 gap #5), per-href-shape:
    #   direct href (Bing)          -> that IS the landing URL; skip the click
    #                                  (sidesteps the mobile overlay intercept)
    #   /aclk redirector (Google)   -> click to follow the chain (load-bearing;
    #                                  the adurl is only the registered domain)
    #   click fails / chrome-error  -> fall back to the registered adurl domain
    # A best-effort destination_host is always derived so no flagged record is
    # left without a host for dedup/reporting.
    # ------------------------------------------------------------------
    dest_url          = None
    redirect_url      = None
    registered_url    = None
    resolution_method = "unresolved"
    tracking_id       = None
    tracking_label    = ""

    try:
        anchor = await ad_element.query_selector(
            'a[data-ved], a[href^="/aclk"], a[href^="http"]'
        )
        if not anchor:
            anchor = await ad_element.query_selector("a")

        href = await anchor.get_attribute("href") if anchor else None
        kind = url_resolve.classify_href(href)
        registered_url = url_resolve.extract_adurl(href)  # Google registered (cloaking) domain

        if not anchor:
            log.warning("  No clickable anchor found in ad element")

        elif kind == "direct":
            # Bing: the href already carries the final landing URL. Reading it
            # is strictly better than the click that fails on the mobile overlay.
            dest_url = href
            resolution_method = "static-href"
            tracking_id, tracking_label = extract_tracking_id(href, engine_key)
            log.info(f"  Static landing page (href, no click): {dest_url[:90]}")

        else:
            # Google /aclk redirector (or unknown); click to resolve the chain.
            if kind == "bing_redirector":
                log.warning("  Bing /aclick redirector seen (not in prior evidence) "
                            "— attempting click resolution")
            async with page.context.expect_page(timeout=15_000) as new_page_info:
                await anchor.click(button="middle")

            new_tab = await new_page_info.value
            try:
                await new_tab.wait_for_load_state("domcontentloaded", timeout=15_000)
                redirect_url = new_tab.url
                log.info(f"  Tracking URL: {redirect_url[:80]}...")

                tracking_id, tracking_label = extract_tracking_id(redirect_url, engine_key)

                # Poll for final landing page through the redirect chain
                prev_url   = redirect_url
                stable_for = 0
                for _ in range(int(10 / 0.5)):
                    await asyncio.sleep(0.5)
                    current = new_tab.url
                    if current == prev_url:
                        stable_for += 0.5
                        if stable_for >= 1.5:
                            break
                    else:
                        log.info(f"  Redirect hop: {current[:80]}...")
                        if not tracking_id:
                            tracking_id, tracking_label = extract_tracking_id(current, engine_key)
                        stable_for = 0
                    prev_url = current

                dest_url = new_tab.url
                resolution_method = "click-intercept"
                log.info(f"  Resolved landing page: {dest_url}")

                if not tracking_id:
                    tracking_id, tracking_label = extract_tracking_id(dest_url, engine_key)

            except Exception as e:
                log.warning(f"  New tab navigation failed: {e}")
                dest_url = new_tab.url if new_tab else None
            finally:
                await new_tab.close()

    except Exception as e:
        log.warning(f"  Click-intercept redirect resolution failed: {e}")

    # Reject browser error pages / engine-only hosts as a real destination.
    if dest_url and not url_resolve.is_real_destination(dest_url):
        log.info(f"  Resolved URL is not a real landing page ({dest_url[:60]}) — discarding")
        dest_url = None

    # Fallback: when the click yielded no real page, use the registered adurl
    # domain (better than nothing; itself a cloaking indicator).
    if not dest_url and url_resolve.is_real_destination(registered_url):
        dest_url = registered_url
        resolution_method = "adurl-fallback"
        log.info(f"  Falling back to registered (adurl) domain: {dest_url[:90]}")

    # Best-effort host; never null when any signal exists.
    registered_host  = host_of(registered_url)
    destination_host = url_resolve.best_destination_host(
        dest_url, registered_url, dest_hint, display_url
    )
    cloaking_suspected = bool(
        registered_host and destination_host
        and registered_host != destination_host
        and url_resolve.is_real_destination(dest_url)
    )
    if cloaking_suspected:
        log.warning(
            f"  Cloaking suspected: registered as {registered_host} but landed on {destination_host}"
        )

    if tracking_id:
        log.warning(f"  {engine_key.upper()} tracking ID ({tracking_label}): {tracking_id}")

    return {
        "serp_screenshot":             str(serp_path),
        "ad_screenshot":               str(ad_path) if ad_path else None,
        "dom_snapshot":                str(dom_path),
        "dest_hint":                   dest_hint,
        "dest_hint_source":            hint_source,
        "google_redirect":             redirect_url,
        "destination_url":             dest_url,
        "destination_host":            destination_host,
        "resolution_method":           resolution_method,
        "registered_url":              registered_url,
        "registered_host":             registered_host,
        "cloaking_suspected":          cloaking_suspected,
        "tracking_id":                 tracking_id,
        "tracking_label":              tracking_label,
        "advertiser_name":             advertiser_info.get("advertiser_name"),
        "advertiser_location":         advertiser_info.get("advertiser_location"),
        "ad_funded_by":                advertiser_info.get("ad_funded_by"),
        "advertiser_panel_screenshot": advertiser_info.get("advertiser_panel_screenshot"),
    }

# ---------------------------------------------------------------------------
# Ad field extraction
# ---------------------------------------------------------------------------

async def extract_ad_fields(ad: ElementHandle, engine_key: str) -> dict:
    """
    Extracts headline, display URL, ad copy, and sitelinks from a sponsored
    ad element using engine-specific selectors from SEARCH_ENGINES config.
    """
    engine   = SEARCH_ENGINES[engine_key]
    headline = "N/A"
    display_url = "N/A"
    ad_copy     = "N/A"
    sitelinks   = []

    # Headline
    try:
        el = await ad.query_selector(engine["headline_sel"])
        if el:
            headline = (await el.inner_text()).strip()
    except Exception:
        pass

    # Display URL
    for sel in engine["display_url_selectors"]:
        try:
            el = await ad.query_selector(sel)
            if el:
                text = (await el.inner_text()).strip()
                if text:
                    display_url = text
                    break
        except Exception:
            pass

    # Ad copy
    for sel in engine["ad_copy_selectors"]:
        try:
            el = await ad.query_selector(sel)
            if el:
                text = (await el.inner_text()).strip()
                if text:
                    ad_copy = text
                    break
        except Exception:
            pass

    # Sitelinks: Bing and Google both surface these
    for sl_sel in [".b_vList", ".U3A9Ac", ".action-card", ".b_subModule"]:
        try:
            els = await ad.query_selector_all(sl_sel)
            for sl in els:
                text = (await sl.inner_text()).strip()
                if text:
                    sitelinks.append(text)
        except Exception:
            pass

    # Link-derived host signals (v7). The rendered display URL is the only
    # thing the allowlist/triage gates used to see, and Google's mobile layout
    # never renders one, so the gates fell back to fail-closed and flagged
    # brand-owned and already-triaged domains. These two attributes give the
    # gates a host to decide on when the visible text is absent. Both are read
    # off the ad element itself, so a missing one is simply None (fail closed).
    # The TITLE anchor is tried before any anchor: in a Bing organic result the
    # first a[href] in DOM order is often an image-search link
    # ("/images/search?view=..."), not the landing page. Falling back to a bare
    # a[href] preserves the previous behaviour for ad containers, where the
    # first anchor IS the landing anchor (held across all 435 captured SERPs).
    # DOM drift is this monitor's recurring failure mode; if suppression ever
    # behaves oddly on one engine, check this assumption first.
    link_href = None
    for sel in ["h2 a[href]", ".b_title h2 a[href]", "a[href]"]:
        try:
            el = await ad.query_selector(sel)
            if el:
                href = await el.get_attribute("href")
                if href:
                    link_href = href
                    break
        except Exception:
            pass

    link_dtld = None
    for sel, attr in [
        ("[data-dtld]",      "data-dtld"),
        ("[data-final-url]", "data-final-url"),
        ("[data-u]",         "data-u"),
    ]:
        try:
            el = await ad.query_selector(sel)
            if el:
                val = await el.get_attribute(attr)
                if val:
                    link_dtld = val
                    break
        except Exception:
            pass

    return {
        "headline":    headline,
        "display_url": display_url,
        "ad_copy":     ad_copy,
        "sitelinks":   sitelinks,
        "link_href":   link_href,
        "link_dtld":   link_dtld,
    }

# ---------------------------------------------------------------------------
# Per-engine SERP check
# ---------------------------------------------------------------------------

async def check_sponsored_ads(
    query: str,
    page: Page,
    engine_key: str,
    device_label: str = "desktop",
) -> list[dict]:
    """
    Navigates to a SERP for the given query on the specified engine and
    returns a list of flagged (non-allowlisted, non-triaged) sponsored ads.

    device_label ("desktop" or "mobile") is stamped onto every finding
    dict and included in evidence filenames so desktop and mobile results
    are clearly distinguishable in alerts and on disk.

    My Ad Center panel capture is suppressed on the mobile context because
    the panel DOM structure differs from desktop and the existing selectors
    target the desktop layout. Mobile findings still capture SERP screenshot,
    ad screenshot, DOM snapshot, tracking ID, and destination URL.
    """
    engine          = SEARCH_ENGINES[engine_key]
    flagged         = []
    timestamp       = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    triaged_domains = load_triaged_domains()
    tag             = f"{engine_key.upper()}][{device_label.upper()}"

    log.info(f"[{tag}] Checking query: '{query}'")

    url = engine["url_template"].format(query=query.replace(" ", "+"))
    try:
        await page.goto(url, wait_until="networkidle", timeout=30_000)
    except Exception as e:
        log.error(f"  Page load failed: {e}")
        return flagged

    await asyncio.sleep(DWELL_TIME)

    dom_size = len(await page.content())
    if dom_size < DOM_MIN_BYTES:
        log.warning(
            f"  [{tag}] DOM suspiciously small ({dom_size} bytes) — "
            "possible consent wall or bot block."
        )
        return flagged

    # Try selectors in priority order
    ad_blocks = []
    used_selector = None
    for sel in engine["ad_selectors"]:
        ad_blocks = await page.query_selector_all(sel)
        if ad_blocks:
            used_selector = sel
            log.info(f"  Selector hit: '{sel}' — {len(ad_blocks)} block(s)")
            break

    if not ad_blocks:
        log.info(f"  [{tag}] Found 0 sponsored ad block(s) for '{query}'")
        return flagged

    # A generic selector (Bing's "[data-bm]") matches the whole page, not ad
    # containers. Most of what it returns is furniture (a search box, images),
    # and rejecting it is normal, not a missed detection. Logging each rejection
    # produced 6,111 lines of "Skipping non-visible or empty ad element" and
    # gave the false impression the monitor was failing to detect something.
    generic_match = used_selector in engine.get("generic_selectors", set())

    serp_url = page.url
    ad_index = 0
    seen_containers = []

    for ad in ad_blocks:
        # Validate the element is a real visible rendered result before
        # processing. Bing's DOM contains structural wrappers that match the
        # selector but are empty, hidden, or off-screen; these produce N/A
        # extractions and cause element screenshot timeouts.
        if not await is_valid_ad(ad):
            if not generic_match:
                # Only worth surfacing when a REAL ad container was rejected:
                # that means an actual ad failed to parse.
                log.info(f"  [{tag}] Skipping non-visible or empty ad element")
            continue

        # Re-anchor to the enclosing result container. Under a generic selector
        # the match is a sub-node, and the headline lives on the container; an
        # organic result extracted from a sub-node yields headline "N/A", which
        # would silently defeat the brand-infringement check below.
        ad = await resolve_container(ad, engine_key)

        # The same container can be reached from several matched sub-nodes, so
        # the same result would otherwise be processed (and alerted) repeatedly.
        already_seen = False
        for other in seen_containers:
            try:
                if await ad.evaluate("(e, o) => e === o", other):
                    already_seen = True
                    break
            except Exception:
                pass
        if already_seen:
            continue
        seen_containers.append(ad)

        channel     = await detect_channel(ad, engine_key)
        fields      = await extract_ad_fields(ad, engine_key)
        display_url = fields["display_url"]

        # Secondary guard: if extraction still returned N/A on both fields,
        # the element is a structural container not a real ad
        if fields["headline"] == "N/A" and display_url == "N/A":
            log.info(f"  [{tag}] Skipping element with no extractable content")
            continue

        # Decide suppression on the strongest host signal available pre-click,
        # not on the rendered display URL alone; Google mobile renders no
        # display URL, which silently disabled the allowlist and triage list on
        # that surface. Returns (None, None) when nothing is recoverable, and
        # both gates then fail closed.
        supp_host, host_source = url_resolve.suppression_host(
            display_url=display_url,
            link_href=fields["link_href"],
            link_dtld=fields["link_dtld"],
        )

        # Surface the host in the alert even when the SERP rendered no display
        # URL, so an analyst never sees a bare "N/A" and has to open the DOM.
        if display_url == "N/A" and supp_host:
            display_url = supp_host

        if is_allowlisted(supp_host):
            log.info(f"  ALLOWLISTED: host={supp_host} (source={host_source})")
            continue

        if is_triaged(supp_host, triaged_domains):
            log.info(f"  TRIAGED (benign): host={supp_host} (source={host_source})")
            continue

        if supp_host is None:
            log.warning(
                f"  [{tag}] No host recoverable from display URL, href, or "
                f"data-dtld — failing closed and flagging for manual review"
            )

        # Does this result CLAIM the brand while landing somewhere we do not
        # own? Channel-agnostic: a poisoned organic result and a hijacking ad
        # are the same offence arriving by different routes. This is a SIGNAL,
        # not a gate: the search terms are generic, so an unrelated
        # business ranking or bidding on the same term is expected and is
        # NOT an offence. It is flagged either way; this decides the verdict.
        verdict = brandmatch.assess(
            fields["headline"], supp_host, BRAND_TERMS, ALLOWLIST_DOMAINS)

        ad_index += 1
        label = "INFRINGING" if verdict["infringing"] else "flagged"
        log.warning(
            f"  [{tag}] {label} [{channel}]: '{fields['headline']}' — {display_url}"
        )

        artifacts = await capture_evidence(
            page, ad, query, engine_key, timestamp, ad_index,
            device_label=device_label,
            display_url=display_url,
        )

        flagged.append({
            "detection_channel": channel,
            "claims_brand":      verdict["claims_brand"],
            "matched_brand_term": verdict["matched_term"],
            "infringing":        verdict["infringing"],
            "engine":        engine_key,
            "device":        device_label,
            "query":         query,
            "serp_url":      serp_url,
            "headline":      fields["headline"],
            "display_url":   display_url,
            "display_url_source": host_source,
            "ad_copy":       fields["ad_copy"],
            "sitelinks":     fields["sitelinks"],
            "timestamp":     datetime.now(timezone.utc).isoformat(),
            **artifacts,
        })

    return flagged

# ---------------------------------------------------------------------------
# Main check loop: all engines
# ---------------------------------------------------------------------------

async def run_checks(
    active_engines: list[str],
    device_profiles: list[dict] = None,
) -> tuple[list[dict], int, str]:
    """
    Runs brand term checks across all active search engines and all selected
    device profiles (desktop and/or mobile) in a single Playwright session.

    device_profiles defaults to DEVICE_PROFILES (both desktop and mobile) if
    not specified. Pass [DESKTOP_PROFILE] or [MOBILE_PROFILE] to restrict to
    a single device pass; this is how --device desktop / --device mobile
    are implemented at the CLI level.

    Each device profile gets its own browser context so the UA, viewport,
    is_mobile, and has_touch flags are fully isolated; Google and Bing route
    each context into the correct auction bucket independently.

    The persistent profile directory is used for both contexts so Google
    consent cookies apply to both. Mobile context inherits the same cookies
    but presents a distinct device fingerprint to the ad server.

    My Ad Center panel capture (fetch_advertiser_info) is only attempted on
    the desktop context; the panel DOM structure differs on mobile and the
    existing selectors target the desktop layout.

    Returns (flagged_ads, last_dom_size, last_page_title).
    """
    if device_profiles is None:
        device_profiles = DEVICE_PROFILES

    all_flagged   = []
    last_dom_size = 0
    last_title    = ""

    if not Path(PROFILE_DIR).exists():
        raise RuntimeError(
            f"Browser profile not found at {PROFILE_DIR}. "
            "Run setup_profile.py first."
        )

    BROWSER_ARGS = [
        "--disable-blink-features=AutomationControlled",
        "--no-sandbox",
        "--disable-dev-shm-usage",
        "--disable-gpu",
    ]

    async with async_playwright() as p:
        for profile in device_profiles:
            label = profile["label"].upper()
            log.info(f"[{label}] Opening browser context — {profile['user_agent'][:60]}...")

            context = await p.chromium.launch_persistent_context(
                user_data_dir=PROFILE_DIR,
                headless=False,
                args=BROWSER_ARGS,
                user_agent=profile["user_agent"],
                viewport=profile["viewport"],
                device_scale_factor=profile["device_scale_factor"],
                is_mobile=profile["is_mobile"],
                has_touch=profile["has_touch"],
                locale="en-US",
            )

            page = await context.new_page()
            await Stealth().apply_stealth_async(page)

            for engine_key in active_engines:
                for term in BRAND_TERMS:
                    try:
                        flagged = await check_sponsored_ads(
                            term, page, engine_key,
                            device_label=profile["label"],
                        )
                        all_flagged.extend(flagged)

                        # Track largest DOM size seen, used for health check
                        dom = await page.content()
                        if len(dom) > last_dom_size:
                            last_dom_size = len(dom)
                            last_title    = await page.title()

                    except Exception as e:
                        log.error(
                            f"[{engine_key.upper()}][{label}] "
                            f"Unhandled error on '{term}': {e}"
                        )

            await context.close()
            log.info(f"[{label}] Context closed.")

    return all_flagged, last_dom_size, last_title

# ---------------------------------------------------------------------------
# Alert email
# ---------------------------------------------------------------------------

def _classification_lines(ad: dict) -> list[str]:
    """
    The two independent questions an analyst needs answered first: how did this
    reach the page, and is it actually impersonating us?

    Kept separate on purpose. "Sponsored" is not a synonym for "bad"; the
    monitored queries are generic, so unrelated businesses legitimately
    bid and rank on them. The offence is claiming the brand while landing
    somewhere the brand does not own.
    """
    channel = ad.get("detection_channel", CHANNEL_UNKNOWN)
    channel_text = {
        CHANNEL_SPONSORED: "SPONSORED AD — a paid placement bought against this search term",
        CHANNEL_ORGANIC:   "ORGANIC RESULT — not a paid ad; this page RANKED here (SEO poisoning)",
    }.get(channel, "UNKNOWN — could not determine paid vs organic; treat with caution")

    lines = [
        "[ CLASSIFICATION ]",
        f"  Channel:           {channel_text}",
    ]

    if ad.get("infringing"):
        lines += [
            f"  Verdict:           ** BRAND INFRINGEMENT **",
            f"  Why:               the title claims \"{ad.get('matched_brand_term')}\" "
            f"but the destination is not a brand-owned domain",
        ]
    elif ad.get("claims_brand"):
        lines += [
            "  Verdict:           brand term present, destination IS brand-owned — not an offence",
        ]
    else:
        lines += [
            "  Verdict:           no brand claim in the title. The monitored search terms",
            "                     are generic, so this may simply be another unrelated",
            "                     business appearing for the same query — review before acting.",
        ]

    lines.append("")
    return lines


def _display_url_note(ad: dict) -> str:
    """
    Provenance suffix for the Display URL line. Google's mobile SERP renders no
    display URL, so the host shown there is recovered from the ad's own link.
    Saying which signal it came from keeps the analyst from trusting a derived
    host as though it were the text Google actually displayed to the user.
    """
    return {
        "href": "   (not shown on the results page — taken from the ad's link)",
        "dtld": "   (not shown on the results page — taken from the ad's link)",
    }.get(ad.get("display_url_source"), "")


def _persistence_lines(ad: dict, device_label: str) -> list[str]:
    """
    Builds the [ CAMPAIGN PERSISTENCE ] block for one finding (v7, gap #4).
    Returns an empty list when the store did not annotate this ad, so the email
    degrades gracefully rather than printing blank fields.
    """
    if not ad.get("fingerprint"):
        return []

    status = ad.get("case_status", "recurring")
    banner = {
        "NEW":        "NEW — first observation of this campaign",
        "PERSISTENT": "** PERSISTENT — escalate (long-running campaign) **",
    }.get(status, "recurring campaign")

    times = ad.get("times_seen", 1)
    raw   = ad.get("raw_detections")
    age   = ad.get("age_days", 0)
    devs  = ", ".join(ad.get("devices_seen") or []) or device_label

    seen_line = f"  Times seen:        {times} run(s)"
    if raw:
        seen_line += f"; {raw} total detections"

    return [
        "[ CAMPAIGN PERSISTENCE ]",
        f"  Case ID:           {ad.get('fingerprint')}",
        f"  Status:            {banner}",
        f"  First seen (UTC):  {ad.get('first_seen', 'N/A')}  ({age} day(s) ago)",
        f"  Last seen (UTC):   {ad.get('last_seen', 'N/A')}",
        seen_line,
        f"  Seen on devices:   {devs}",
        "",
    ]


def build_alert_email(flagged_ads: list[dict], run_timestamp: str) -> MIMEMultipart:
    """
    Builds a structured analyst alert email. Findings are grouped by search
    engine. Each finding includes engine-specific takedown guidance and the
    platform tracking ID (gad_campaignid for Google, msclkid for Bing).
    """
    count   = len(flagged_ads)
    engines = sorted({ad["engine"] for ad in flagged_ads})

    # Campaign persistence summary (v7, Lens #1 gap #4). Counts DISTINCT cases
    # by fingerprint, not raw detections. Reads with .get defaults so a store
    # failure degrades to "unavailable" rather than raising.
    distinct_cases = {}
    for ad in flagged_ads:
        fp = ad.get("fingerprint")
        if fp:
            distinct_cases[fp] = ad
    have_persistence = bool(distinct_cases)
    new_campaigns    = sum(1 for a in distinct_cases.values() if a.get("is_new"))
    recurring        = len(distinct_cases) - new_campaigns
    persistent       = sum(1 for a in distinct_cases.values() if a.get("case_status") == "PERSISTENT")

    # Channel + infringement split. "Sponsored ad" is no longer a synonym for
    # the whole product: an organic result that impersonates the brand (SEO
    # poisoning) is the same offence arriving by a different route, and needs a
    # different takedown.
    n_sponsored  = sum(1 for a in flagged_ads
                       if a.get("detection_channel") == CHANNEL_SPONSORED)
    n_organic    = sum(1 for a in flagged_ads
                       if a.get("detection_channel") == CHANNEL_ORGANIC)
    n_infringing = sum(1 for a in flagged_ads if a.get("infringing"))

    # Surface brand infringement first, then new campaigns; a result claiming
    # the brand while landing off-brand is the highest-priority triage signal.
    flagged_ads = sorted(
        flagged_ads,
        key=lambda a: (not a.get("infringing", False),
                       not a.get("is_new", False),
                       a.get("fingerprint") or ""),
    )

    msg = MIMEMultipart("mixed")
    subject_kind = (f"{n_infringing} BRAND INFRINGEMENT" if n_infringing
                    else f"{count} result(s)")
    msg["Subject"] = (
        f"[BRAND ALERT] {subject_kind} — {n_sponsored} sponsored ad(s), "
        f"{n_organic} organic "
        f"[{', '.join(e.upper() for e in engines)}] — {run_timestamp}"
    )
    msg["From"] = ALERT_FROM
    msg["To"]   = ALERT_TO

    lines = [
        "=" * 70,
        "BRAND PROTECTION — SEARCH RESULT ALERT",
        "=" * 70,
        "",
        f"Detection timestamp (UTC): {run_timestamp}",
        f"Search engines monitored:  {', '.join(e.upper() for e in ACTIVE_ENGINES)}",
        f"Monitored brand terms:     {', '.join(BRAND_TERMS)}",
        f"Total results flagged:     {count}",
        "",
        "  By channel (how it reached the page):",
        f"    Sponsored ads:         {n_sponsored}  (paid placement — engine ads complaint)",
        f"    Organic results:       {n_organic}  (SEO poisoning — registrar / host abuse)",
        "",
        "  By verdict (what it claims to be):",
        f"    BRAND INFRINGEMENT:    {n_infringing}  (claims a brand term, lands off-brand)",
        f"    Other:                 {count - n_infringing}  (no brand claim — may be a legitimate",
        "                              unrelated business appearing for the same query)",
    ]

    if have_persistence:
        lines += [
            f"Distinct campaigns:        {len(distinct_cases)}  "
            f"({new_campaigns} new this run, {recurring} recurring)",
            f"Persistent campaigns:      {persistent}  (escalation candidates)",
        ]
    else:
        lines.append("Campaign persistence:      unavailable (store not updated this run)")

    lines += [
        "",
        "This alert was generated automatically by the brand protection",
        "monitoring script. Each finding below contains all information",
        "required to reproduce the ad and submit a takedown request.",
        "",
    ]

    for i, ad in enumerate(flagged_ads, 1):
        engine_key = ad["engine"]
        engine_cfg = SEARCH_ENGINES.get(engine_key, {})

        device_label = ad.get("device", "desktop")

        lines += [
            "-" * 70,
            f"FINDING {i} of {count}",
            "-" * 70,
            "",
        ]
        lines += _classification_lines(ad)
        lines += _persistence_lines(ad, device_label)
        lines += [
            "[ SEARCH CONTEXT ]",
            f"  Search engine:     {engine_key.upper()}",
            f"  Device context:    {device_label.upper()} — {'mobile auction (phone/tablet UA)' if device_label == 'mobile' else 'desktop auction'}",
            f"  Search query:      {ad['query']}",
            f"  SERP URL:          {ad['serp_url']}",
            f"  Detection time:    {ad['timestamp']}",
            "",
            "[ AD CONTENT ]",
            f"  Headline:          {ad['headline']}",
            f"  Display URL:       {ad['display_url']}{_display_url_note(ad)}",
            f"  Ad copy:           {ad['ad_copy']}",
        ]

        if ad.get("sitelinks"):
            lines.append("  Sitelinks:")
            for sl in ad["sitelinks"]:
                lines.append(f"    - {sl}")

        dest_url  = ad.get("destination_url")
        dest_host = ad.get("destination_host")
        method    = ad.get("resolution_method", "unresolved")

        lines += [
            "",
            "[ DESTINATION ]",
            f"  Tracking redirect: {ad.get('google_redirect') or 'N/A'}",
        ]
        if dest_url:
            lines.append(f"  Landing page:      {dest_url}")
        elif dest_host:
            # Click did not resolve, but a host was recovered from the display
            # URL / DOM hint, better than "could not resolve" (v7, gap #5).
            lines.append(
                f"  Landing host:      {dest_host}  "
                "(best-effort — click did not resolve; see SERP screenshot)"
            )
        else:
            lines.append("  Landing page:      Could not resolve — see SERP screenshot")

        lines.append(f"  Resolution method: {method}")

        # Registered-vs-landing divergence is a cloaking indicator (v7, gap #5).
        if ad.get("cloaking_suspected"):
            lines += [
                f"  Registered domain: {ad.get('registered_host')}",
                f"  ** CLOAKING SUSPECTED — ad registered as {ad.get('registered_host')} "
                f"but landed on {dest_host}. Flag in the complaint. **",
            ]

        if ad.get("dest_hint"):
            lines += [
                f"  DOM hint:          {ad['dest_hint']}",
                f"  DOM hint source:   {ad.get('dest_hint_source', 'N/A')}",
            ]

        # Advertiser attribution from My Ad Center panel (Google only)
        adv_name     = ad.get("advertiser_name")
        adv_location = ad.get("advertiser_location")
        ad_funded_by = ad.get("ad_funded_by")
        adv_panel    = ad.get("advertiser_panel_screenshot")

        # Advertiser attribution (My Ad Center / ATC / campaign id) only applies
        # to paid ads. A confirmed-ORGANIC result was never an ad; it has no
        # advertiser panel, no creative in the Transparency Center, and no
        # campaign id, so these sections are pure noise for it and are skipped.
        # Gate on != ORGANIC (not == SPONSORED) so unknown-channel findings keep
        # their existing behavior and still get attribution + the ad takedown
        # route below; only confirmed-organic drops out here and into its own
        # registrar/host/Safe-Browsing guidance.
        is_organic = ad.get("detection_channel") == CHANNEL_ORGANIC

        if not is_organic and any([adv_name, adv_location, ad_funded_by]):
            lines += [
                "",
                "[ ADVERTISER ATTRIBUTION — My Ad Center ]",
                f"  Advertiser name:     {adv_name or 'Not captured'}",
                f"  Advertiser location: {adv_location or 'Not captured'}",
                f"  Ad funded by:        {ad_funded_by or 'Not disclosed'}",
            ]
            if adv_panel:
                lines.append(f"  Panel screenshot:    {adv_panel}")
            if adv_location and adv_location.lower() not in ("united states", "us", "usa"):
                lines += [
                    "  ** FOREIGN FUNDER DETECTED — include in IC3 referral. **",
                    "  ** Location and funder name are key threat actor attribution indicators. **",
                ]
        elif not is_organic and engine_key == "google":
            lines += [
                "",
                "[ ADVERTISER ATTRIBUTION — My Ad Center ]",
                "  Panel not captured — check brand_monitor.log for [DEBUG] selector output.",
                "  The debug output shows page text near 'advertiser' to identify the",
                "  current panel selector. Manually click the ⋮ menu on the ad in Chrome",
                "  → Inspect Element on the panel to find the updated aria-label or jsname.",
            ]

        # Ads Transparency Center: durable advertiser identity + ad ID (v8).
        # Present even when the live panel could not be captured, and persists
        # after the ad stops serving.
        if not is_organic and ad.get("atc_creative_id"):
            lines += [
                "",
                "[ ADS TRANSPARENCY CENTER — durable ad record ]",
                f"  Advertiser:          {ad.get('atc_advertiser_name') or 'N/A'}"
                + ("  (Google-Verified)" if ad.get("atc_advertiser_verified") else ""),
                f"  Advertiser ID:       {ad.get('atc_advertiser_id')}",
                f"  Ad (creative) ID:    {ad.get('atc_creative_id')}",
                f"  Permalink:           {ad.get('atc_creative_url')}",
                "  ** This is the stable ad ID for the Google report — it persists even",
                "     when the ad no longer appears in a live search. **",
            ]
            if ad.get("atc_screenshot"):
                lines.append(f"  ATC screenshot:      {ad.get('atc_screenshot')}")
        elif not is_organic and engine_key == "google" and ad.get("atc_ad_count") is not None:
            lines += [
                "",
                "[ ADS TRANSPARENCY CENTER — durable ad record ]",
                f"  No retained creative for {ad.get('destination_host')} "
                f"(ad count: {ad.get('atc_ad_count')}).",
                "  Likely the advertiser account was suspended and its ads withdrawn,",
                "  or the advertiser is unverified. Use the live evidence + campaign ID below.",
            ]

        # Platform-specific attribution section, paid ads only (see is_organic).
        tracking_id    = ad.get("tracking_id")
        tracking_label = ad.get("tracking_label") or engine_cfg.get("tracking_param", "ID")

        if not is_organic:
            lines += [
                "",
                f"[ {engine_key.upper()} ADS ATTRIBUTION ]",
            ]

            if tracking_id:
                if engine_key == "google":
                    lines += [
                        f"  Campaign ID ({tracking_label}): {tracking_id}",
                        "  ** Include this ID in the Google Ads trademark complaint. **",
                        "  ** Google can pull the advertiser account directly from it. **",
                    ]
                elif engine_key == "bing":
                    if "UTM" in (tracking_label or ""):
                        # Auto-tagging disabled; UTM params extracted instead of msclkid
                        lines += [
                            f"  Attribution ({tracking_label}):",
                            f"    {tracking_id}",
                            "  NOTE: msclkid absent — advertiser has auto-tagging disabled.",
                            "  ** Include utm_campaign value in the Microsoft Advertising complaint. **",
                            "  ** utm_content encodes the ad ID and ad group ID (format: adid_adgroupid). **",
                        ]
                    else:
                        lines += [
                            f"  Click ID ({tracking_label}): {tracking_id}",
                            "  ** Include this ID in the Microsoft Advertising complaint. **",
                            "  ** Microsoft can trace the advertiser account from the msclkid. **",
                        ]
            else:
                lines += [
                    f"  {tracking_label or 'Tracking ID'}:  Not extracted — check tracking redirect URL above.",
                ]

        lines += [
            "",
            "[ TAKEDOWN SUBMISSION GUIDANCE ]",
        ]

        # The takedown route follows the CHANNEL, not the engine. An ads-policy
        # trademark complaint does nothing about a page that was never an ad;
        # it simply ranked. Sending analysts to the ads form for an organic
        # result wastes the one route that can actually get the page removed.
        if ad.get("detection_channel") == CHANNEL_ORGANIC:
            safebrowsing = ("https://safebrowsing.google.com/safebrowsing/report_phish/"
                            if engine_key == "google"
                            else "https://www.microsoft.com/en-us/wdsi/support/report-unsafe-site")
            lines += [
                "  This is an ORGANIC result — it was never a paid ad, so an ads",
                "  trademark complaint does not apply. Go after the page itself:",
                "",
                "  1. Registrar abuse contact  <-- primary route:",
                "       Run: whois <landing domain> — submit abuse report citing",
                "       brand impersonation / credential phishing.",
                "  2. Hosting provider abuse contact:",
                "       The landing page is often a COMPROMISED legitimate site. The",
                "       owner may not know. Notify the host and the site owner.",
                f"  3. Phishing blocklist report:  {safebrowsing}",
                "  4. Search-engine removal (de-index) request — slower, and it hides",
                "       the page rather than removing the phishing content.",
            ]
        elif engine_key == "google":
            lines += [
                "  1. Google Ads trademark complaint (include Campaign ID above):",
                f"       {engine_cfg.get('complaint_url', 'https://services.google.com/inquiry/aw_tmcomplaint')}",
                "  2. Google Safe Browsing phishing report:",
                "       https://safebrowsing.google.com/safebrowsing/report_phish/",
                "  3. Registrar abuse contact:",
                "       Run: whois <display domain> — submit abuse report citing",
                "       brand impersonation. Response typically 24-48 hrs.",
                "  4. Note on cloaking: If landing page matches display URL, the",
                "       advertiser uses a cloaking intermediary. Document the true",
                "       destination from a manual click and include in submissions.",
            ]
        elif engine_key == "bing":
            lines += [
                "  1. Microsoft Advertising trademark complaint (include Click ID):",
                f"       {engine_cfg.get('complaint_url', 'https://about.ads.microsoft.com/en/forms/policies/intellectual-property-complaint-form')}",
                "  2. Microsoft Safety Report (phishing):",
                "       https://www.microsoft.com/en-us/wdsi/support/report-unsafe-site",
                "  3. Registrar abuse contact:",
                "       Run: whois <display domain> — submit abuse report citing",
                "       brand impersonation. Response typically 24-48 hrs.",
            ]

        lines += [
            "",
            "[ EVIDENCE ARTIFACTS ]",
            f"  SERP screenshot:   {ad['serp_screenshot']}",
            f"  Ad screenshot:     {ad.get('ad_screenshot') or 'N/A'}",
            f"  DOM snapshot:      {ad['dom_snapshot']}",
            "",
        ]

    lines += [
        "=" * 70,
        "SCREENSHOTS ATTACHED — see attachments for visual evidence.",
        "JSON record saved to evidence directory for case tracking.",
        "=" * 70,
    ]

    msg.attach(MIMEText("\n".join(lines), "plain"))

    attached = set()
    for ad in flagged_ads:
        for key in ["serp_screenshot", "ad_screenshot", "advertiser_panel_screenshot"]:
            path = ad.get(key)
            if path and path not in attached and Path(path).exists():
                with open(path, "rb") as f:
                    img = MIMEImage(f.read(), name=Path(path).name)
                    img.add_header(
                        "Content-Disposition",
                        "attachment",
                        filename=Path(path).name,
                    )
                    msg.attach(img)
                attached.add(path)

    return msg


def send_alert(flagged_ads: list[dict], run_timestamp: str) -> None:
    """Sends the analyst alert email via Mailgun SMTP on port 587/STARTTLS."""
    if not SMTP_USER or not SMTP_PASSWORD:
        log.warning("SMTP credentials not configured — skipping email alert.")
        return

    msg = build_alert_email(flagged_ads, run_timestamp)

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(ALERT_FROM, ALERT_TO_LIST, msg.as_string())
        log.info(f"Alert email sent to {ALERT_TO}")
    except smtplib.SMTPAuthenticationError:
        log.error(
            "SMTP authentication failed — verify SMTP_USER and SMTP_PASSWORD in .env. "
            "Mailgun SMTP credentials are per-domain, not account credentials."
        )
    except smtplib.SMTPConnectError:
        log.error(
            f"SMTP connection failed — {SMTP_HOST}:{SMTP_PORT}. "
            "Try port 2525 in .env if your ISP blocks 587."
        )
    except smtplib.SMTPNotSupportedError:
        log.error("SMTP server does not support STARTTLS.")
    except TimeoutError:
        log.error(f"SMTP connection timed out — {SMTP_HOST}:{SMTP_PORT}.")
    except Exception as e:
        log.error(f"Failed to send alert email: {type(e).__name__}: {e}")

# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

def run_once(
    active_engines: list[str] | None = None,
    device_profiles: list[dict] | None = None,
) -> None:
    """Single execution: start virtual display, run checks, alert, stop."""
    if active_engines is None:
        active_engines = ACTIVE_ENGINES
    if device_profiles is None:
        device_profiles = DEVICE_PROFILES

    ensure_evidence_dir()
    run_timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Reset attribution capture counters for this run (v7 self-healing).
    ATTRIBUTION_STATS.update(attempted=0, menu_found=0, panel_captured=0,
                             accordion_expanded=0)

    display = Display(visible=False, size=(VIEWPORT["width"], VIEWPORT["height"]))
    display.start()
    log.info("Virtual display started")

    try:
        log.info(f"Running checks on: {[e.upper() for e in active_engines]}")
        log.info(f"Device profiles: {[p['label'].upper() for p in device_profiles]}")
        log.info("Running profile health checks...")

        profile_healthy = run_profile_health_checks(
            dom_size=getattr(run_once, "_last_dom_size", 0),
            title=getattr(run_once, "_last_title", ""),
        )
        if not profile_healthy:
            log.error(
                "Profile health check failed — skipping ad detection. "
                "Run setup_profile.py from a desktop session to refresh the profile."
            )
            return

        flagged, dom_size, title = asyncio.run(
            run_checks(active_engines, device_profiles=device_profiles)
        )

        run_once._last_dom_size = dom_size
        run_once._last_title    = title

        # Attribution capture health; alerts operator on selector drift (v7).
        _report_attribution_health()

        # Ads Transparency Center enrichment (v8). Durable advertiser identity +
        # AR/CR IDs for each flagged destination domain, independent of whether
        # the ad is still serving. Fails OPEN; never blocks the alert.
        if flagged and ENABLE_TRANSPARENCY_LOOKUP:
            try:
                # Skip confirmed-organic results: a page that ranked (never an
                # ad) will never be in the Ads Transparency Center, so looking
                # it up is pure waste. Unknown-channel domains ARE looked up;
                # a creative hit there is itself evidence the result was an ad.
                domains = [
                    ad.get("destination_host")
                    for ad in flagged
                    if ad.get("destination_host")
                    and ad.get("detection_channel") != CHANNEL_ORGANIC
                ]
                atc = asyncio.run(lookup_transparency_center(domains))
                for ad in flagged:
                    key = _normalize_domain(ad.get("destination_host"))
                    if key and key in atc:
                        # Don't overwrite the domain field already on the ad.
                        ad.update({
                            k: v for k, v in atc[key].items() if k != "domain"
                        })
            except Exception as e:
                log.error(f"[ATC] Enrichment step failed (continuing): {e}")

        if flagged:
            log.warning(f"{len(flagged)} flagged ad(s) found — sending alert")

            # Dedup + first/last-seen enrichment (v7, Lens #1 gap #4).
            # Fails OPEN: a store error annotates nothing but never blocks the
            # alert. Runs before the JSON write so both outputs carry the fields.
            try:
                conn  = findings_store.connect(FINDINGS_DB)
                cases = findings_store.enrich_flagged(conn, flagged, run_timestamp)
                conn.close()
                new_cases = sum(1 for c in cases.values() if c["is_new"])
                log.info(
                    f"Campaign store: {len(cases)} distinct case(s) this run "
                    f"({new_cases} new, {len(cases) - new_cases} recurring)"
                )
            except Exception as e:
                log.error(f"Campaign store update failed (continuing without dedup): {e}")

            json_path = (
                EVIDENCE_DIR
                / f"{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_flagged.json"
            )
            json_path.write_text(json.dumps(flagged, indent=2), encoding="utf-8")
            log.info(f"JSON record saved: {json_path}")
            send_alert(flagged, run_timestamp)
        else:
            log.info("No unauthorized sponsored ads detected")

    except Exception as e:
        log.error(f"Fatal error during run: {e}")
        raise

    finally:
        display.stop()
        log.info("Virtual display stopped")


def run_scheduled(
    google_interval: int,
    bing_interval: int,
    active_engines: list[str],
    device_profiles: list[dict] | None = None,
) -> None:
    """
    Runs checks on independent per-engine schedules.

    Intervals are specified in MINUTES so sub-hour values (e.g. 30) are
    supported without decimal arguments.

    Google: 240 minute (4h) minimum recommended. Session fingerprinting
             suppresses ad delivery on frequent repeat searches from the
             same profile. Running more often risks silent false-negatives.

    Bing:   30-120 minute intervals are safe. No observed consent wall,
             less aggressive bot detection, and no frequency capping
             behavior comparable to Google. More frequent checks increase
             the probability of catching short-lived campaigns.

    Each engine runs independently; a Google check does not block or
    delay a scheduled Bing check, and vice versa.

    device_profiles is passed through unchanged to every scheduled firing;
    if restricted via --device desktop / --device mobile, the schedule runs
    only that device profile for the life of the process.
    """
    if device_profiles is None:
        device_profiles = DEVICE_PROFILES

    def fmt(mins):
        return f"{mins}m" if mins < 60 else f"{mins // 60}h" if mins % 60 == 0 else f"{mins // 60}h{mins % 60}m"

    if "google" in active_engines and "bing" in active_engines:
        log.info(
            f"Scheduled mode: GOOGLE every {fmt(google_interval)}, "
            f"BING every {fmt(bing_interval)}"
        )
        schedule.every(google_interval).minutes.do(
            run_once, active_engines=["google"], device_profiles=device_profiles
        )
        schedule.every(bing_interval).minutes.do(
            run_once, active_engines=["bing"], device_profiles=device_profiles
        )
    elif "google" in active_engines:
        log.info(f"Scheduled mode: GOOGLE every {fmt(google_interval)}")
        schedule.every(google_interval).minutes.do(
            run_once, active_engines=["google"], device_profiles=device_profiles
        )
    elif "bing" in active_engines:
        log.info(f"Scheduled mode: BING every {fmt(bing_interval)}")
        schedule.every(bing_interval).minutes.do(
            run_once, active_engines=["bing"], device_profiles=device_profiles
        )

    # Run all active engines immediately on startup, then follow schedule.
    # device_profiles must be passed explicitly: omitting it makes run_once fall
    # back to DEVICE_PROFILES (both devices), so a --device mobile schedule would
    # still open a desktop context on its very first run, the one run an
    # operator is most likely to be watching.
    run_once(active_engines=active_engines, device_profiles=device_profiles)

    while True:
        schedule.run_pending()
        time.sleep(60)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=(
            "Brand Protection — Multi-Engine, Multi-Device Sponsored Ad Monitor v6\n"
            "Checks Google and/or Bing sponsored ad results for brand-term ads, using a "
            "desktop and/or mobile browser fingerprint (see --device) so mobile-only ad "
            "campaigns are not missed."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Single run — both engines, both device profiles (desktop + mobile)
  python serp_monitor.py

  # Single run, Google only (still runs both desktop and mobile passes)
  python serp_monitor.py --engine google

  # Single run, Bing only (still runs both desktop and mobile passes)
  python serp_monitor.py --engine bing

  # Desktop fingerprint only — skip the mobile pass for this run
  python serp_monitor.py --device desktop

  # Mobile fingerprint only — useful for confirming a mobile-only campaign
  python serp_monitor.py --device mobile

  # Google, mobile fingerprint only
  python serp_monitor.py --engine google --device mobile

  # Scheduled, both engines, default intervals (Google 240m = 4h, Bing 120m = 2h)
  python serp_monitor.py --schedule

  # Scheduled with custom intervals in minutes — sub-hour values supported
  python serp_monitor.py --schedule --google-interval 360 --bing-interval 30

  # Bing only on a 30-minute schedule
  python serp_monitor.py --schedule --engine bing --bing-interval 30

  # Bing every hour, Google every 4 hours
  python serp_monitor.py --schedule --google-interval 240 --bing-interval 60

  # Mark a false positive domain as triaged (suppressed everywhere)
  python serp_monitor.py --triage example-partner.org

  # List every domain currently on the triage suppression list
  python serp_monitor.py --list-triage

Notes:
  - --engine and --device are independent — combine them freely. The four
    corners are: both engines/both devices (default, recommended for
    production), one engine/both devices, both engines/one device, or one
    engine/one device for fast targeted checks.
  - --device desktop or --device mobile also applies to --schedule, so a
    scheduled run can be restricted to a single device fingerprint for the
    life of the process.
  - --schedule runs Google and Bing on independent timers in the same
    process; without --schedule the script performs a single run and exits.
  - --triage and --list-triage are one-shot utility actions: the script
    performs the requested action and exits without running ad detection.
        """
    )
    parser.add_argument(
        "--schedule",
        action="store_true",
        help=(
            "Run continuously on independent per-engine schedules instead of a single pass. "
            "Google and Bing each run on their own timer (see --google-interval / "
            "--bing-interval) within the same process. Each scheduled firing checks both "
            "the desktop and mobile device profiles. Without this flag, the script performs "
            "one run covering all active engines and device profiles, then exits."
        ),
    )
    parser.add_argument(
        "--google-interval",
        type=int,
        default=240,
        metavar="MINUTES",
        help=(
            "Google check interval in minutes when running with --schedule "
            "(default: 240 = 4h, minimum recommended: 240). Ignored without --schedule. "
            "Google session fingerprinting can suppress ad delivery if checked too frequently."
        ),
    )
    parser.add_argument(
        "--bing-interval",
        type=int,
        default=120,
        metavar="MINUTES",
        help=(
            "Bing check interval in minutes when running with --schedule "
            "(default: 120 = 2h, minimum recommended: 30). Ignored without --schedule. "
            "Bing has no observed consent wall or frequency capping comparable to Google, "
            "so shorter intervals are supported."
        ),
    )
    parser.add_argument(
        "--engine",
        choices=["google", "bing", "both"],
        default="both",
        help=(
            "Search engine(s) to check (default: both). Does not affect device coverage — "
            "by default both the desktop and mobile fingerprint are still checked for "
            "whichever engine(s) are selected here. Use --device to restrict device coverage."
        ),
    )
    parser.add_argument(
        "--device",
        choices=["desktop", "mobile", "both"],
        default="both",
        help=(
            "Browser device fingerprint(s) to use (default: both). 'desktop' checks only "
            "the Windows/Chrome desktop fingerprint — the ad auction your script ran "
            "exclusively before v6. 'mobile' checks only the Pixel 8/Android Chrome Mobile "
            "fingerprint — useful for confirming a mobile-only campaign without spending "
            "time on the desktop pass. 'both' (default) runs both passes every time, which "
            "is recommended for production monitoring since the two auctions are independent "
            "and a campaign visible on one may not appear on the other."
        ),
    )
    parser.add_argument(
        "--triage",
        metavar="DOMAIN",
        help=(
            "Mark a domain as analyst-confirmed benign and suppress future alerts for it. "
            "Applies across both Google and Bing and across both desktop and mobile device "
            "profiles — a domain triaged once is suppressed everywhere. This is a one-shot "
            "action: the domain is added to triaged_domains.json and the script exits "
            "without running ad detection. "
            "Example: python serp_monitor.py --triage example-partner.org"
        ),
    )
    parser.add_argument(
        "--list-triage",
        action="store_true",
        help=(
            "Print every domain currently on the triage suppression list and exit. "
            "One-shot action — does not run ad detection."
        ),
    )
    args = parser.parse_args()

    # Resolve active engines from --engine flag
    if args.engine == "both":
        active = list(SEARCH_ENGINES.keys())
    else:
        active = [args.engine]

    # Resolve active device profiles from --device flag
    if args.device == "both":
        devices = DEVICE_PROFILES
    elif args.device == "desktop":
        devices = [DESKTOP_PROFILE]
    else:  # "mobile"
        devices = [MOBILE_PROFILE]

    if args.list_triage:
        domains = load_triaged_domains()
        if domains:
            print(f"\nTriaged domains ({len(domains)}) — alerts suppressed on Google and Bing:")
            for d in sorted(domains):
                print(f"  {d}")
        else:
            print("\nNo domains currently triaged.")
        print(f"\nTriage file: {TRIAGE_FILE}\n")

    elif args.triage:
        stored = save_triaged_domain(args.triage)
        if stored is None:
            print(f"\nCould not triage '{args.triage}' — not a parseable host.")
            print("Pass a domain or URL, e.g. --triage example.com\n")
        else:
            print(f"\nHost '{stored}' added to triage list.")
            print("Future alerts for this exact host will be suppressed on Google and Bing.")
            print(f"Triage file: {TRIAGE_FILE}\n")

    elif args.schedule:
        run_scheduled(
            google_interval=args.google_interval,  # already in minutes
            bing_interval=args.bing_interval,       # already in minutes
            active_engines=active,
            device_profiles=devices,
        )

    else:
        run_once(active_engines=active, device_profiles=devices)
