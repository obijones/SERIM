"""
Regression tests for run_scheduled() — the startup run must honour --device.

The bug: run_scheduled registered every scheduled firing with
device_profiles=device_profiles, but called the immediate startup run as
run_once(active_engines=active_engines) with no device_profiles. run_once then
fell back to DEVICE_PROFILES (both devices), so `--device mobile --schedule`
opened a desktop browser context on its very first run — the one run an
operator is most likely to be watching. Every later firing was correct, which
is exactly what made it easy to miss.

These tests drive the real run_scheduled() with run_once and schedule stubbed
out, so they assert on what the scheduler actually passes.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import serp_monitor as C


class _StopLoop(Exception):
    """Raised by the run_once stub to break out of the scheduler's while True."""


@pytest.fixture
def calls(monkeypatch):
    """Capture the startup run_once call and abort before the polling loop."""
    recorded = {}

    def fake_run_once(**kwargs):
        recorded.update(kwargs)
        raise _StopLoop

    monkeypatch.setattr(C, "run_once", fake_run_once)
    # The startup run_once fires first and raises _StopLoop, so the scheduling
    # loop is never reached — no scheduler stubbing needed.
    return recorded


def _run(engines, devices, calls):
    with pytest.raises(_StopLoop):
        C.run_scheduled(
            google_interval=60,
            bing_interval=30,
            active_engines=engines,
            device_profiles=devices,
        )
    return calls


def test_startup_run_honours_mobile_only(calls):
    """--device mobile --schedule must NOT open a desktop context on run one."""
    got = _run(["bing"], [C.MOBILE_PROFILE], calls)
    assert got["device_profiles"] == [C.MOBILE_PROFILE]
    assert C.DESKTOP_PROFILE not in got["device_profiles"]


def test_startup_run_honours_desktop_only(calls):
    got = _run(["google"], [C.DESKTOP_PROFILE], calls)
    assert got["device_profiles"] == [C.DESKTOP_PROFILE]
    assert C.MOBILE_PROFILE not in got["device_profiles"]


def test_startup_run_defaults_to_both_devices(calls):
    """No --device -> run_scheduled resolves None to both profiles."""
    got = _run(["google", "bing"], None, calls)
    assert got["device_profiles"] == C.DEVICE_PROFILES


def test_startup_run_passes_active_engines(calls):
    got = _run(["bing"], [C.MOBILE_PROFILE], calls)
    assert got["active_engines"] == ["bing"]


def test_scheduled_loop_fires_and_reschedules(monkeypatch):
    """
    Drive one iteration of the scheduling loop: after the startup run, a due
    engine must fire a single-engine run_once and get a fresh next-fire time.
    """
    engine_runs = []

    def fake_run_once(active_engines=None, device_profiles=None):
        engine_runs.append(list(active_engines))

    monkeypatch.setattr(C, "run_once", fake_run_once)
    monkeypatch.setattr(C.time, "sleep", lambda *_: None)   # don't actually wait

    # Force the engine immediately due so the loop fires on its first pass, and
    # stop on the reschedule that follows the fire (the 2nd next-fire call).
    reschedules = []

    def fake_next_fire(engine, interval_min):
        reschedules.append(engine)
        if len(reschedules) >= 2:      # initial schedule, then post-fire reschedule
            raise _StopLoop
        return C.time.time() - 1       # in the past -> due now

    monkeypatch.setattr(C, "_next_fire_for", fake_next_fire)

    with pytest.raises(_StopLoop):
        C.run_scheduled(
            google_interval=240,
            bing_interval=120,
            active_engines=["google"],
            device_profiles=[C.DESKTOP_PROFILE],
        )

    # Startup run (both/active), then a single-engine scheduled fire for google.
    assert engine_runs[0] == ["google"]
    assert engine_runs[1] == ["google"]
    # Rescheduled at least twice: initial next_fire + after the fire.
    assert reschedules.count("google") >= 2
