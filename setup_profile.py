"""
setup_profile.py — One-Time Browser Profile Setup

Run this ONCE before first use of serp_monitor.py.
Opens a real visible Chromium browser so you can:
  1. Accept Google's consent / cookie dialog
  2. Confirm a normal SERP with ads is visible
  3. Press ENTER to save the profile and exit

The saved profile preserves cookies and consent state so serp_monitor.py
can run headlessly via PyVirtualDisplay without hitting consent walls.

Usage:
    python setup_profile.py

Requirements:
    - Must be run from a session with a real display (DISPLAY=:1 or similar)
    - Do NOT run via xvfb or PyVirtualDisplay you need to see the browser
    - Run from within your venv: source venv/bin/activate first
"""

import asyncio
import os
import sys
from pathlib import Path
from dotenv import load_dotenv
from playwright.async_api import async_playwright

load_dotenv()

PROFILE_DIR = os.getenv("PROFILE_DIR", "/path/to/project/browser_profile")
USER_AGENT  = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/148.0.7778.96 Safari/537.36"
)

TEST_QUERY = "contoso online portal"


def check_display() -> None:
    """Warn if DISPLAY is not set browser won't open without it."""
    display = os.getenv("DISPLAY", "")
    if not display:
        print(
            "\n[ERROR] DISPLAY environment variable is not set.\n"
            "This script must run in a desktop session (not headless SSH).\n"
            "If you are on SSH, reconnect with: ssh -X user@host\n"
        )
        sys.exit(1)
    print(f"[OK] DISPLAY={display}")


def check_existing_profile() -> None:
    """Warn if a profile already exists offer to abort."""
    if Path(PROFILE_DIR).exists():
        print(f"\n[WARNING] Profile already exists at: {PROFILE_DIR}")
        answer = input("Overwrite / re-run setup? This clears saved cookies. [y/N]: ")
        if answer.strip().lower() != "y":
            print("Aborted. Existing profile unchanged.")
            sys.exit(0)


async def run_setup() -> None:
    print(f"\nLaunching browser — profile will be saved to:\n  {PROFILE_DIR}\n")

    async with async_playwright() as p:
        context = await p.chromium.launch_persistent_context(
            user_data_dir=PROFILE_DIR,
            headless=False,  # Must be visible so you can interact
            args=[
                "--disable-blink-features=AutomationControlled",
                "--no-sandbox",
                "--disable-dev-shm-usage",
            ],
            user_agent=USER_AGENT,
            viewport={"width": 1366, "height": 768},
            locale="en-US",
        )

        page = await context.new_page()
        await page.goto(
            f"https://www.google.com/search?q={TEST_QUERY}",
            wait_until="networkidle",
            timeout=30_000,
        )

        print("=" * 60)
        print("Browser is open. Please do the following:")
        print()
        print("  1. Accept any Google consent or cookie dialog")
        print("  2. Confirm you can see a normal SERP with sponsored ads")
        print("  3. Return to this terminal and press ENTER")
        print()
        print("  DO NOT close the browser manually — press ENTER here instead")
        print("=" * 60)
        input("\nPress ENTER when ready to save and exit...")

        # Capture a quick DOM size check before closing
        dom_size = len(await page.content())
        print(f"\nDOM size at save time: {dom_size:,} bytes")
        if dom_size < 50_000:
            print(
                "[WARNING] DOM is very small — Google may not have served a real SERP.\n"
                "Check that you accepted the consent dialog and retry if needed."
            )
        else:
            print("[OK] DOM size looks healthy — real SERP was served.")

        await context.close()

    print(f"\n[DONE] Profile saved to: {PROFILE_DIR}")
    print("You can now run serp_monitor.py normally.\n")

    # Show profile size as confirmation
    total = sum(
        f.stat().st_size for f in Path(PROFILE_DIR).rglob("*") if f.is_file()
    )
    print(f"Profile size: {total / 1_048_576:.1f} MB")


if __name__ == "__main__":
    check_display()
    check_existing_profile()
    asyncio.run(run_setup())
