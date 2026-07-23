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

   The five path settings — `PROFILE_DIR`, `EVIDENCE_DIR`, `TRIAGE_FILE`, `FINDINGS_DB`, and `LOG_FILE` — are **required and have no built-in defaults**. They are read only from the environment (`.env`), and `serp_monitor.py` exits at startup, naming any that are missing, rather than falling back to a placeholder path. Set all five.

   The database itself needs no setup. `FINDINGS_DB` just names a file path, and the store creates the file and its schema on the first run. If that path is left unset or points somewhere unwritable, the run still completes and alerts still send, but you will see `Campaign store update failed (continuing without dedup)` and that run gets no first seen or last seen grouping.

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
python serp_monitor.py --schedule            # keep running on a timer (jittered)
python serp_monitor.py --schedule --google-interval 240 --bing-interval 120
python serp_monitor.py --engine google --ignore-cooldown  # force a Google check during a cooldown
python serp_monitor.py --triage example.com  # mark a domain as reviewed and benign
python serp_monitor.py --list-triage         # show the triage list
python serp_monitor.py --help                # full list of options
```

When you mark a domain with `--triage`, it is suppressed on both engines and both devices from then on.

In `--schedule` mode, Google auto-pauses on a rate block and each run is jittered — see [Google rate limiting](#google-rate-limiting) below. Use `--ignore-cooldown` for a one-off manual check of whether a Google block has lifted. The cooldown and jitter behaviour is tuned with the `GOOGLE_COOLDOWN_*`, `SCHEDULE_JITTER_FRAC`, `WITHIN_RUN_JITTER_*`, and `GOOGLE_RESUME_JITTER_MIN` variables in `.env` (see `env.example`).

## Reports

`report.py` builds a metrics report from the database:

```
python report.py --format html
python report.py --summary
```

Two helper scripts backfill history into a fresh database:

* `backfill_findings.py` replays saved evidence so past campaigns keep their real first seen date.
* `backfill_channels.py` labels older findings as paid or organic.

## Merging findings from more than one machine

If you have run the monitor on more than one host (say a lab machine and a production VM) you will have two `findings.db` files, and you may want a single combined view.

Do **not** merge the databases at the row level. The rows are aggregates (run counts, seen-sets), and if the two databases share history — for example one started as a copy of the other — summing those counts double-counts every shared run and can falsely escalate cases to persistent.

Instead merge by replaying the combined evidence, which reconstructs the counts from the ground-truth per-run `*_flagged.json` files:

```
python merge_findings.py --output merged.db /path/to/machine_a/evidence /path/to/machine_b/evidence
```

This considers every evidence file across all the directories you list, de-duplicates runs that are byte-identical copies so a shared run is not counted twice, and replays the rest in chronological order into a fresh `merged.db`. Run counts, first seen, and last seen come out correct, and duplicate input is idempotent.

Check coverage first with `--dry-run` (reports files found, duplicate copies collapsed, and the run date range without writing anything). The method is only as complete as the evidence you still have: runs whose `*_flagged.json` was pruned cannot be reconstructed.

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
* `merge_findings.py`: merge findings from multiple machines by replaying their combined evidence into one database.
* `test_*.py`: unit tests.

## Google rate limiting

Google shows a `/sorry` "unusual traffic" reCAPTCHA when it sees automated queries from a low-reputation IP — datacenter and cloud IPs (a VM whose IP resolves to a cloud provider's own network is the worst case) trip it after only a few runs. Two things matter, both borne out by the logs:

* **Stopping is the fix.** Once blocked, the IP clears on its own in minutes to a few hours *if you stop querying*. Continuing to query on a timer keeps the block alive indefinitely.
* **It is not a profile problem.** Re-running `setup_profile.py` does not help a rate block; that only fixes the separate GDPR consent wall.

The monitor handles this automatically. On detecting the `/sorry` wall it pauses **Google only** (Bing keeps running), waits out a cooldown, and backs off exponentially if the next probe is still blocked. The cooldown is tunable via `GOOGLE_COOLDOWN_BASE_MIN` / `GOOGLE_COOLDOWN_MAX_MIN` and persists across restarts in `cooldown_state.json`.

While a cooldown is active, a normal `python serp_monitor.py --engine google` is skipped with a log line rather than run. To manually check whether the block has lifted, force a probe with `--ignore-cooldown`:

```
python serp_monitor.py --engine google --ignore-cooldown
```

`--schedule` always respects the cooldown, since a timer that ignored it would just keep the block alive.

### Traffic-shaping jitter

In `--schedule` mode the monitor also spreads its traffic out so it reads less like a bot. This adds no extra requests — it only changes *when* the existing runs fire:

* **Interval jitter** — each run's interval is offset by a random ±`SCHEDULE_JITTER_FRAC` of the base (default ±20%), so runs are not on a machine-perfect clock.
* **Within-run jitter** — brand terms are shuffled and separated by a random `WITHIN_RUN_JITTER_MIN`–`WITHIN_RUN_JITTER_MAX` second gap, instead of firing as a burst.
* **Resume-probe** — after a Google cooldown expires, Google is retried within `GOOGLE_RESUME_JITTER_MIN` minutes rather than waiting for the next full interval, so visibility returns as soon as the IP is likely clear. Because the cooldown is an absolute floor checked at run time, jitter can never fire Google *before* the cooldown ends — an early tick is simply skipped.

Adding decoy searches (e.g. random weather queries) does **not** help and tends to hurt: Google's rate limiter keys on IP reputation and request volume, not on what you search, so extra queries only push an already-stressed IP further over its budget. Less, slower, and more randomly-timed traffic is the direction that buys headroom; the durable fix remains the IP.

If you need more Google runs than the cooldown allows, the durable fix is the IP, not the code: run the collector from a residential connection (for example a small always-on box behind your home network) rather than a cloud VM. That removes the trigger without any proxy service.

## Notes

* The live monitor never imports `matplotlib`. It is used only by `report.py`, so you can remove it if you do not need reports.

## License

Released under the MIT License. See the `LICENSE` file for the full text.
