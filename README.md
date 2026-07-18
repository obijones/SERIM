# SERIM (Search Engine Results Integrity Monitor)

Serim watches Google and Bing search results and flags ads and pages that pretend to be your brand. It is built for brand protection and phishing teams who want early warning when someone bids on your name or poisons search results to steal logins.

## What it does

* Runs your brand terms through Google and Bing on every check.
* Uses both a desktop and a mobile browser fingerprint, so campaigns that only show on phones are not missed.
* Flags any result whose title claims your brand but whose destination is a domain you do not own.
* Labels each result as a paid ad or an organic (ranked) page, because the two need different takedown routes.
* Captures evidence for each finding: a full page screenshot, the ad screenshot, the page source, the tracking or click id, and, for Google ads, the advertiser details from the My Ad Center panel.
* Looks up flagged domains in the Google Ads Transparency Center to recover a durable advertiser and ad id.
* Stores every finding in a small SQLite database, so repeat sightings are grouped into one case with a first seen and last seen date.
* Emails an alert with all of the above plus step by step takedown guidance.

## How it decides what is a problem

A result is treated as impersonation when the title claims your brand and the landing domain is not on your allowlist. The search terms are meant to be broad, so an unrelated business that happens to share a word with your brand is expected and is not counted as an offense. The matching logic lives in `brandmatch.py` and is covered by unit tests.

## Requirements

* Python 3.10 or newer.
* Chromium, installed through Playwright.
* The `xvfb` system package, used to run the browser on a headless server.
* The Python packages listed in `requirements.txt`.

## Install

```
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
playwright install chromium
sudo apt install xvfb
```

## Configure

1. Copy the example environment file and fill in your values:

   ```
   cp env.example .env
   ```

   The file sets the paths for the browser profile, evidence folder, triage list, log file, and database, plus the SMTP details used to send alerts.

2. Open `serp_monitor.py` and set two things near the top:

   * `BRAND_TERMS`: the search terms you want to watch.
   * `ALLOWLIST_DOMAINS`: the domains you own, so your own ads are never flagged.

## First time setup

Google needs a saved browser profile that has accepted the cookie consent dialog. Run the setup script once on a machine with a real display:

```
python setup_profile.py
```

Accept the dialog, confirm you can see a normal results page, then press ENTER to save. Bing needs no profile.

## Run it

A single check across both engines and both devices:

```
python serp_monitor.py
```

Some common variations:

```
python serp_monitor.py --engine google      # Google only
python serp_monitor.py --device mobile       # mobile fingerprint only
python serp_monitor.py --schedule            # keep running on a timer
python serp_monitor.py --schedule --google-interval 240 --bing-interval 120
python serp_monitor.py --triage example.com  # mark a domain as reviewed and benign
python serp_monitor.py --list-triage         # show the triage list
python serp_monitor.py --help                # full list of options
```

When you mark a domain with `--triage`, it is suppressed on both engines and both devices from then on.

## Reports

`report.py` builds a metrics report from the database:

```
python report.py --format html
python report.py --summary
```

Two helper scripts backfill history into a fresh database:

* `backfill_findings.py` replays saved evidence so past campaigns keep their real first seen date.
* `backfill_channels.py` labels older findings as paid or organic.

## Tests

The pure logic is covered by offline unit tests. No browser or network is needed:

```
pytest
```

## Project layout

* `serp_monitor.py`: main monitor. Scans results, flags impersonation, captures evidence, sends alerts.
* `brandmatch.py`: decides whether a title claims your brand while pointing to a domain you do not own.
* `domainmatch.py`: host extraction and domain matching for the allowlist and triage list.
* `url_resolve.py`: works out the real landing page behind an ad link.
* `findings_store.py`: SQLite store for grouping repeat sightings and tracking first and last seen.
* `report.py` and `report_data.py`: build the metrics report from the database.
* `setup_profile.py`: one time browser profile setup for Google.
* `backfill_findings.py` and `backfill_channels.py`: seed and label historical data.
* `test_*.py`: unit tests.

## Notes

* The live monitor never imports `matplotlib`. It is used only by `report.py`, so you can remove it if you do not need reports.
* Nothing is committed that holds secrets or captured data. Copy `env.example` to `.env` for your own settings, and keep `.env`, the evidence folder, and the database out of version control (see `.gitignore`).

## License

Released under the MIT License. See the `LICENSE` file for the full text.
