"""
Tests for the Google /sorry rate-block detection + cooldown (serp_monitor).

The design and its numbers come from brand_monitor.log: ~3 hourly runs from a
datacenter IP trip Google's /sorry reCAPTCHA, continuing to query while blocked
sustains it for hours, and stopping clears it in minutes-to-hours. So on
detection we PAUSE Google for a cooldown and back off if it re-blocks, while
Bing keeps running.

State is exercised by seeding the JSON state file directly (no datetime
mocking): cooldown_until in the past/future drives google_cooldown_remaining()
and the run_once engine-filtering.
"""
import json
import os
import sys
import time
from datetime import datetime, timezone, timedelta

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import serp_monitor as C


@pytest.fixture
def state_file(tmp_path, monkeypatch):
    """Point cooldown state at a temp file, isolated per test."""
    p = tmp_path / "cooldown_state.json"
    monkeypatch.setattr(C, "COOLDOWN_STATE_FILE", str(p))
    return p


def _seed(state_file, cooldown_until=None, consecutive=0):
    g = {"consecutive_blocks": consecutive}
    if cooldown_until is not None:
        g["cooldown_until"] = cooldown_until.isoformat()
    state_file.write_text(json.dumps({"google": g}), encoding="utf-8")


# --- classify_wall ---------------------------------------------------------

def test_classify_healthy_dom_is_none():
    assert C.classify_wall(500_000, "contoso login - Google Search", "https://www.google.com/search?q=x") is None


def test_classify_sorry_by_sei_token():
    # The captured wall shape: tiny DOM, URL/title carrying a sei= token.
    url = "https://www.google.com/search?q=contoso+login&sei=AbCdEf123456"
    assert C.classify_wall(6_628, url, url) == "rate_block"


def test_classify_sorry_by_path():
    assert C.classify_wall(4_000, "", "https://www.google.com/sorry/index?continue=x") == "rate_block"


def test_classify_consent_wall_routes_separately():
    assert C.classify_wall(8_000, "Before you continue", "https://consent.google.com/m?continue=x") == "consent"


def test_classify_unknown_tiny_dom():
    # Tiny DOM, no distinguishing marker -> unknown (fail safe: still cools down).
    assert C.classify_wall(3_000, "weird", "https://www.google.com/") == "unknown"


# --- cooldown state --------------------------------------------------------

def test_no_state_means_no_cooldown(state_file):
    assert C.google_cooldown_remaining() == 0.0


def test_future_cooldown_reports_remaining(state_file):
    _seed(state_file, cooldown_until=datetime.now(timezone.utc) + timedelta(minutes=90), consecutive=1)
    remaining = C.google_cooldown_remaining()
    assert 89 * 60 < remaining <= 90 * 60


def test_past_cooldown_reports_zero(state_file):
    _seed(state_file, cooldown_until=datetime.now(timezone.utc) - timedelta(minutes=5), consecutive=1)
    assert C.google_cooldown_remaining() == 0.0


def test_register_uses_base_on_first_block(state_file, monkeypatch):
    monkeypatch.setattr(C, "GOOGLE_COOLDOWN_BASE_MIN", 180)
    monkeypatch.setattr(C, "GOOGLE_COOLDOWN_MAX_MIN", 720)
    C.register_google_block("rate_block", "http://x/sorry")
    remaining = C.google_cooldown_remaining()
    assert 179 * 60 < remaining <= 180 * 60
    assert json.loads(state_file.read_text())["google"]["consecutive_blocks"] == 1


def test_register_backs_off_exponentially(state_file, monkeypatch):
    monkeypatch.setattr(C, "GOOGLE_COOLDOWN_BASE_MIN", 180)
    monkeypatch.setattr(C, "GOOGLE_COOLDOWN_MAX_MIN", 720)
    C.register_google_block("rate_block")   # 180
    C.register_google_block("rate_block")   # 360
    remaining = C.google_cooldown_remaining()
    assert 359 * 60 < remaining <= 360 * 60
    assert json.loads(state_file.read_text())["google"]["consecutive_blocks"] == 2


def test_register_caps_at_max(state_file, monkeypatch):
    monkeypatch.setattr(C, "GOOGLE_COOLDOWN_BASE_MIN", 180)
    monkeypatch.setattr(C, "GOOGLE_COOLDOWN_MAX_MIN", 360)
    for _ in range(6):          # would blow past 360 without the cap
        C.register_google_block("rate_block")
    remaining = C.google_cooldown_remaining()
    assert remaining <= 360 * 60


def test_note_google_ok_clears_cooldown(state_file):
    _seed(state_file, cooldown_until=datetime.now(timezone.utc) + timedelta(minutes=90), consecutive=2)
    C.note_google_ok()
    assert C.google_cooldown_remaining() == 0.0
    assert "google" not in json.loads(state_file.read_text())


def test_corrupt_state_fails_open(state_file):
    state_file.write_text("{ not valid json", encoding="utf-8")
    # Fail OPEN: a corrupt file must never block a run.
    assert C.google_cooldown_remaining() == 0.0


def test_missing_state_dir_fails_open(monkeypatch, tmp_path):
    monkeypatch.setattr(C, "COOLDOWN_STATE_FILE", str(tmp_path / "nope" / "state.json"))
    assert C.google_cooldown_remaining() == 0.0


# --- run_once engine filtering --------------------------------------------

def _stub_run_once_env(monkeypatch):
    """Neutralize the heavy machinery so we can observe engine filtering."""
    started = {"display": False}

    class _Display:
        def __init__(self, *a, **k):
            pass

        def start(self):
            started["display"] = True

        def stop(self):
            pass

    monkeypatch.setattr(C, "Display", _Display)
    monkeypatch.setattr(C, "ensure_evidence_dir", lambda: None)
    return started


def test_run_once_skips_entirely_when_google_only_and_cooled_down(state_file, monkeypatch):
    _seed(state_file, cooldown_until=datetime.now(timezone.utc) + timedelta(minutes=90), consecutive=1)
    started = _stub_run_once_env(monkeypatch)

    # If the gate works, we never reach the health check or display.
    monkeypatch.setattr(C, "run_google_health_check",
                        lambda: pytest.fail("health check should not run"))
    C.run_once(active_engines=["google"], device_profiles=[C.DESKTOP_PROFILE])
    assert started["display"] is False


# --- run_google_health_check routing --------------------------------------
# The security-relevant branch: consent must NOT enter the cooldown path, or a
# real profile problem hides behind escalating cooldowns while the operator is
# never alerted to run setup_profile.py.

def _stub_health_env(monkeypatch, probe_result):
    """Stub cookie check, probe, and alert; return the recorded alert calls."""
    alerts = []
    monkeypatch.setattr(C, "check_cookie_expiry", lambda: (True, "cookies ok"))
    monkeypatch.setattr(C, "_send_profile_alert",
                        lambda cookie_msg, dom_msg: alerts.append((cookie_msg, dom_msg)))

    async def fake_probe():
        return probe_result

    monkeypatch.setattr(C, "probe_dom_size", fake_probe)
    return alerts


def test_health_healthy_returns_true_and_clears(state_file, monkeypatch):
    _seed(state_file, cooldown_until=datetime.now(timezone.utc) + timedelta(minutes=90), consecutive=1)
    alerts = _stub_health_env(monkeypatch, (600_000, "contoso - Google Search", "https://www.google.com/search?q=x"))
    assert C.run_google_health_check() is True
    assert C.google_cooldown_remaining() == 0.0    # note_google_ok cleared it
    assert alerts == []


def test_health_rate_block_cools_down_without_alert(state_file, monkeypatch):
    url = "https://www.google.com/sorry/index?continue=x&sei=abc"
    alerts = _stub_health_env(monkeypatch, (6_000, url, url))
    assert C.run_google_health_check() is False
    assert C.google_cooldown_remaining() > 0        # cooldown registered
    assert alerts == []                             # rate block does NOT alert


def test_health_consent_alerts_and_does_not_cool_down(state_file, monkeypatch):
    url = "https://consent.google.com/m?continue=x"
    alerts = _stub_health_env(monkeypatch, (8_000, "Before you continue", url))
    assert C.run_google_health_check() is False
    assert C.google_cooldown_remaining() == 0.0     # consent must NOT cool down
    assert len(alerts) == 1                         # operator IS alerted


def test_health_unknown_cools_down_and_alerts(state_file, monkeypatch):
    alerts = _stub_health_env(monkeypatch, (3_000, "weird", "https://www.google.com/"))
    assert C.run_google_health_check() is False
    assert C.google_cooldown_remaining() > 0        # fail-safe cooldown
    assert len(alerts) == 1                         # but still surfaces to a human


def test_run_once_registers_cooldown_on_midrun_block(state_file, monkeypatch):
    _stub_run_once_env(monkeypatch)
    monkeypatch.setattr(C, "run_google_health_check", lambda: True)  # clean at start
    monkeypatch.setattr(C, "_report_attribution_health", lambda: None)

    async def fake_run_checks(active_engines, device_profiles=None):
        return [], 0, "", True   # block appeared mid-run

    monkeypatch.setattr(C, "run_checks", fake_run_checks)

    assert C.google_cooldown_remaining() == 0.0
    C.run_once(active_engines=["google"], device_profiles=[C.DESKTOP_PROFILE])
    assert C.google_cooldown_remaining() > 0   # mid-run block registered a cooldown


def test_run_once_keeps_bing_when_google_cooled_down(state_file, monkeypatch):
    _seed(state_file, cooldown_until=datetime.now(timezone.utc) + timedelta(minutes=90), consecutive=1)
    _stub_run_once_env(monkeypatch)

    seen = {}

    async def fake_run_checks(active_engines, device_profiles=None):
        seen["engines"] = list(active_engines)
        return [], 0, "", False

    monkeypatch.setattr(C, "run_checks", fake_run_checks)
    monkeypatch.setattr(C, "run_google_health_check",
                        lambda: pytest.fail("Google is cooled down; health check must be skipped"))
    monkeypatch.setattr(C, "_report_attribution_health", lambda: None)

    C.run_once(active_engines=["google", "bing"], device_profiles=[C.DESKTOP_PROFILE])
    assert seen["engines"] == ["bing"]   # Google filtered, Bing survives


# --- traffic-shaping jitter + resume-probe ---------------------------------

def test_jittered_interval_within_bounds(monkeypatch):
    monkeypatch.setattr(C, "SCHEDULE_JITTER_FRAC", 0.20)
    # 240 min ±20% -> [192, 288] min, in seconds.
    for _ in range(200):
        secs = C._jittered_interval(240, 0.20)
        assert 192 * 60 <= secs <= 288 * 60


def test_jittered_interval_zero_frac_is_exact():
    assert C._jittered_interval(240, 0.0) == 240 * 60


def test_jittered_interval_floored_at_60s():
    # A tiny base with jitter must never schedule faster than 60s.
    assert C._jittered_interval(0.5, 0.5) >= 60


def test_next_fire_bing_uses_jittered_interval(state_file, monkeypatch):
    monkeypatch.setattr(C, "SCHEDULE_JITTER_FRAC", 0.20)
    before = time.time()
    fire = C._next_fire_for("bing", 120)
    # 120 min ±20% -> [96, 144] min ahead.
    assert before + 96 * 60 <= fire <= before + 144 * 60 + 1


def test_next_fire_google_normal_when_not_cooled_down(state_file, monkeypatch):
    monkeypatch.setattr(C, "SCHEDULE_JITTER_FRAC", 0.20)
    assert C.google_cooldown_remaining() == 0.0
    before = time.time()
    fire = C._next_fire_for("google", 240)
    assert before + 192 * 60 <= fire <= before + 288 * 60 + 1


def test_next_fire_google_resume_probe_after_cooldown(state_file, monkeypatch):
    # The visibility guarantee: after a block, Google resumes just after the
    # cooldown expires — NOT a full interval later.
    monkeypatch.setattr(C, "GOOGLE_RESUME_JITTER_MIN", 15)
    _seed(state_file, cooldown_until=datetime.now(timezone.utc) + timedelta(minutes=90), consecutive=1)
    before = time.time()
    fire = C._next_fire_for("google", 240)
    # ~90 min (remaining) + [0, 15] min jitter — well short of the 240m interval.
    assert before + 90 * 60 <= fire <= before + 105 * 60 + 1


def test_ignore_cooldown_forces_google_probe(state_file, monkeypatch):
    _seed(state_file, cooldown_until=datetime.now(timezone.utc) + timedelta(minutes=90), consecutive=1)
    _stub_run_once_env(monkeypatch)

    seen = {}

    async def fake_run_checks(active_engines, device_profiles=None):
        seen["engines"] = list(active_engines)
        return [], 0, "", False

    monkeypatch.setattr(C, "run_checks", fake_run_checks)
    monkeypatch.setattr(C, "run_google_health_check", lambda: True)  # pretend the block lifted
    monkeypatch.setattr(C, "_report_attribution_health", lambda: None)

    # Manual override: Google must be probed despite the active cooldown.
    C.run_once(active_engines=["google"], device_profiles=[C.DESKTOP_PROFILE],
               ignore_cooldown=True)
    assert seen["engines"] == ["google"]
