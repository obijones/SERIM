# SERIM (Search Engine Results Integrity Monitor)

Serim watches Google and Bing search results and flags ads and pages that pretend to be your brand. It is built for brand protection and phishing teams who want early warning when someone bids on your name or poisons search results to steal logins.

## What it does

* Runs your brand terms through Google and Bing on every check.
* Uses both a desktop and a mobile browser fingerprint, so campaigns that only show on phones are not missed.
* Flags any result whose title claims your brand but whose destination is a domain you do not own.
* Labels each result as a paid ad or an organic (ranked) page, because the two need different takedown routes.
* Captures evidence for each finding: a full page screenshot, the ad screenshot, the page source, the tracking or click id, and, for Google ads, the advertiser details from the My Ad Center panel.
* Looks up flagged domains in the Google Ads Transparency Center to recover a durable advertiser and ad id, and links the domain's Transparency Center page on every Google ad finding so there is always an advertiser route that outlives the ad.
* Stores every finding in a small SQLite database, so repeat sightings are grouped into one case with a first seen and last seen date.
* Emails an alert with all of the above plus step by step takedown guidance.

## How it decides what is a problem

A result is treated as impersonation when the title claims your brand and the landing domain is not on your allowlist. The search terms are meant to be broad, so an unrelated business that happens to share a word with your brand is expected and is not counted as an offense. The matching logic lives in `brandmatch.py` and is covered by unit tests.

Because the terms are broad, real financial institutions show up too. They are kept out of the report metrics through a registry of vetted institutions, and anything nobody has adjudicated is reported as its own number rather than counted as a threat — see [Legitimate institutions and the three review states](#legitimate-institutions-and-the-three-review-states).

## Why you cannot re-find the ad by hand

The natural first move on receiving an alert is to run the same query yourself and click the ad's three dot menu to see who paid for it. That will usually fail, and it is not a bug in the monitor. Search ads are auction served and targeted by audience, location, device and budget, and impersonators additionally rotate creatives and cloak their landing pages, so the impression the monitor caught is often not served to you minutes later. The three dot menu and the My Ad Center panel behind it exist only while an ad is actually rendering. An empty re-search is not evidence that the ad stopped running.

Everything the monitor can only get while the ad is live is therefore captured at detection time: the screenshots, the page source, the resolved landing page, the campaign or click id, and the My Ad Center panel when it opens. Those artifacts are the record, and a takedown can be filed from them alone — the engine complaint forms ask for the ad's urls, the query and screenshots, not for a creative id.

When you do want advertiser identity after the fact, use the Ads Transparency Center, which is searchable by **landing domain** rather than by an ad you have to catch live, and which retains records for months after an ad stops serving. Every Google ad finding in the alert carries that domain link, whether or not the lookup found a creative. A domain with zero retained ads is a real answer rather than a failed lookup: it is what a suspended or withdrawn advertiser account looks like, and it is worth screenshotting.

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

   `FI_REGISTRY_FILE` is optional — see [Legitimate institutions](#legitimate-institutions-and-the-three-review-states). Leaving it unset is safe: every non-infringing finding is then reported as unreviewed rather than quietly cleared.

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
python serp_monitor.py --list-legitimate     # show the known-institution registry
python serp_monitor.py --help                # full list of options

# record a real financial institution so it stops counting toward the metrics
python serp_monitor.py --mark-legitimate examplebank.com \
    --institution "Example Bank, N.A." --basis "FDIC cert 12345" --analyst jdoe
```

When you mark a domain with `--triage`, it is suppressed on both engines and both devices from then on.

In `--schedule` mode, Google auto-pauses on a rate block and each run is jittered — see [Google rate limiting](#google-rate-limiting) below. Use `--ignore-cooldown` for a one-off manual check of whether a Google block has lifted. The cooldown and jitter behaviour is tuned with the `GOOGLE_COOLDOWN_*`, `SCHEDULE_JITTER_FRAC`, `WITHIN_RUN_JITTER_*`, and `GOOGLE_RESUME_JITTER_MIN` variables in `.env` (see `env.example`).

## Legitimate institutions and the three review states

The search terms are deliberately generic ("account login", "online portal"), so real licensed financial institutions bid and rank on them. They are not offences, but they were still being counted as campaigns in every report metric — on one 113-case store, 90 cases (80%) were non-infringing, and most of that was legitimate competitors.

Every finding now lands in exactly one of three states:

| State | What it means | Counts as a threat |
|---|---|---|
| **threat** | The title claims a brand term and the destination is not a domain you own | Yes |
| **legitimate** | The host is on the known-institution registry | No — excluded, and reported as a named exclusion |
| **unreviewed** | Neither of the above | No — reported as an analyst work queue |

**Unreviewed is not an all-clear.** It means only that the title did not claim a brand term, so it holds legitimate businesses nobody has adjudicated yet *and* any real threat that left your name out of its title. It is reported as its own number rather than folded in with the legitimate results, so a gap in detection stays visible instead of being buried.

### The registry

Record an institution once, with the reason you trust it:

```
python serp_monitor.py --mark-legitimate examplebank.com \
    --institution "Example Bank, N.A." --basis "FDIC cert 12345" --analyst jdoe

python serp_monitor.py --list-legitimate
```

The domain **and its subdomains** stop counting toward the metrics, because a real institution serves `www.`, `secure.` and `locator.` hosts off one registered domain. Matching is on label boundaries, so `evilexamplebank.com` and `examplebank.com.evil.ru` do not inherit that legitimacy.

Registered institutions keep being collected. Only the metrics change — a real institution's domain can be compromised later, and if collection stopped you would never see it.

This is a third list, deliberately separate from the two that already existed:

| | Means | Matching | Records why |
|---|---|---|---|
| `ALLOWLIST_DOMAINS` | "we own this" | subdomains | — |
| `triaged_domains.json` | "an analyst looked at this exact host once" | exact host | no |
| `known_fi.json` | "this organization is a legitimate institution" | subdomains | yes — basis, analyst, date |

Two safety properties are deliberate. **A registry entry never suppresses infringement**: a registered host that claims a brand term is still counted as a threat and is flagged `** CONFLICT **` in the alert, because that combination means either the title match misfired or a legitimate domain has been compromised. And **a missing or corrupt registry file fails open** — it yields no institutions, so everything falls back to unreviewed and stays visible. Legitimacy requires positive membership, so a broken registry can never hide a finding.

The rule itself lives in `fi_registry.py` and is imported by both the monitor and the report, so the verdict in an alert email and the scope of a manager metric cannot drift apart. The state is computed when a report is generated rather than stored on the case, so registering an institution retroactively cleans up historical numbers with no change to the database.

## Reports

`report.py` builds an executive pack from the database — slide-ready PNG charts, a single self-contained `report.html`, and CSV aggregates:

```
python report.py                 # full pack to ./reports/ (monthly trend)
python report.py --period week   # finer detail for operational review
python report.py --summary       # census + KPIs to stdout, no files
```

The charts, all scoped to confirmed threats by default:

* **Impersonation over time** — campaigns live per period. Monthly by default (`--period month`), which reads a 13–14 month history cleanly; partial edge months are marked, never dropped, so a short month cannot read as a decline.
* **Paid ads vs SEO poisoning** — the same trend split by how each campaign reached customers, because the two need different takedowns.
* **Engine and device** — a donut, two blues for Bing and two oranges for Google; cases with no device recorded are counted in the caption rather than dropped.
* **Longest-lived threats** — the campaigns that stayed live longest, coloured by attack type (paid / SEO / both). The span is exposure observed while monitoring — a minimum, not a time-to-takedown, since Serim tracks detection, not remediation.
* **Search-term and top-domain breakdowns.**

The report does **not** draw the triage funnel. Executives use a Microsoft funnel graphic (PowerPoint SmartArt, Excel or Power BI), so `report.py` emits the funnel stage figures — all findings → legitimate institutions set aside → real campaigns, with the unreviewed queue alongside — as `funnel.csv` to paste straight in.

Charts and KPIs cover **threats only** by default, since a chart captioned "fraudulent ads" that counted legitimate competitors would be lying. The three-state census is printed whatever the scope, so nothing is dropped silently:

```
Review states across 113 case(s): 23 threat, 12 known institution, 78 unreviewed
Reporting scope: threats (23 case(s)).
```

Change what the figures cover with `--scope`:

```
python report.py --scope threats      # default — confirmed brand infringement
python report.py --scope unreviewed   # the analyst work queue
python report.py --scope legitimate   # what was excluded, and why
python report.py --scope all          # every case, as before
```

`--infringing-only` still works as a deprecated alias for `--scope threats`. In `--format csv` / `all`, `kpis.csv` carries the census and the scope, and `review_queue.csv` lists the unreviewed cases ranked by how often they were seen — the shortest path to shrinking that bucket.

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
* `fi_registry.py`: the known-legitimate institution registry, and the one rule that assigns a finding its review state. Shared by the monitor and the report.
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
