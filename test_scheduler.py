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

    # Neutralize the scheduler registration — .do() would otherwise bind the
    # real run_once, and we never let the loop run anyway.
    class _Job:
        def do(self, *a, **kw):
            return self

    class _Every:
        minutes = property(lambda self: _Job())

    monkeypatch.setattr(C.schedule, "every", lambda *a, **kw: _Every())
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
