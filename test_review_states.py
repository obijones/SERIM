"""
Tests for the three-state review model as report_data.py applies it.

fi_registry owns the rule (test_fi_registry.py covers it directly). This file
covers the wiring, where the failure modes are different:
  * load_cases ANNOTATES with review_state and never drops on it — scoping is
    the caller's decision, so a report can still show what it excluded.
  * The registry is applied at READ time, so registering an institution
    retroactively cleans historical metrics without touching the store.
  * The census partitions the population: threats + legitimate + unreviewed
    equals the total, whatever the registry says.
  * With no registry, nothing is legitimate and no case is lost.

Offline: temp findings.db + temp registry file, no matplotlib, no browser.
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import fi_registry as fr        # noqa: E402
import findings_store as fs     # noqa: E402
import report_data as rd        # noqa: E402


@pytest.fixture
def db(tmp_path):
    """Four cases: one infringing, one registered FI, one FI subdomain, one unknown."""
    path = str(tmp_path / "findings.db")
    conn = fs.connect(path)

    def add(fp, engine, host, infringing):
        conn.execute(
            "INSERT INTO findings (fingerprint, engine, primary_host, first_seen, "
            "last_seen, times_seen, raw_detections, devices_seen, queries_seen, "
            "infringing, status) VALUES (?,?,?,?,?,?,?,?,?,?, 'open')",
            (fp, engine, host, "2026-07-01T10:00:00Z", "2026-07-05T10:00:00Z",
             3, 6, json.dumps(["desktop"]), json.dumps(["contoso login"]),
             int(infringing)),
        )

    add("google:phish-example-1.com", "google", "phish-example-1.com", True)
    add("bing:examplebank.com",       "bing",   "examplebank.com",     False)
    add("bing:secure.examplebank.com","bing",   "secure.examplebank.com", False)
    add("google:unknown-site.example","google", "unknown-site.example", False)
    conn.commit()
    conn.close()
    return path


@pytest.fixture
def registry(tmp_path):
    p = tmp_path / "known_fi.json"
    p.write_text(json.dumps({"known_financial_institutions": [
        {"domain": "examplebank.com", "institution": "Example Bank, N.A.",
         "basis": "FDIC cert 12345", "added_by": "jdoe"},
    ]}), encoding="utf-8")
    return fr.load_hosts(str(p))


# --------------------------------------------------------------------------- #
# annotation, not filtering
# --------------------------------------------------------------------------- #

def test_load_cases_annotates_but_never_drops(db, registry):
    cases = rd.load_cases(db, fi_hosts=registry)
    assert len(cases) == 4                      # nothing removed by the registry
    assert all("review_state" in c for c in cases)


def test_states_are_assigned_correctly(db, registry):
    by_host = {c["host"]: c["review_state"] for c in rd.load_cases(db, fi_hosts=registry)}
    assert by_host["phish-example-1.com"]    == fr.THREAT
    assert by_host["examplebank.com"]        == fr.LEGITIMATE
    assert by_host["secure.examplebank.com"] == fr.LEGITIMATE   # subdomain
    assert by_host["unknown-site.example"]   == fr.UNREVIEWED


def test_by_state_selects_the_right_subset(db, registry):
    cases = rd.load_cases(db, fi_hosts=registry)
    assert [c["host"] for c in rd.by_state(cases, fr.THREAT)] == ["phish-example-1.com"]
    assert len(rd.by_state(cases, fr.LEGITIMATE)) == 2
    assert [c["host"] for c in rd.by_state(cases, fr.UNREVIEWED)] == ["unknown-site.example"]


# --------------------------------------------------------------------------- #
# the census adds up
# --------------------------------------------------------------------------- #

def test_census_partitions_the_population(db, registry):
    review = rd.review_summary(rd.load_cases(db, fi_hosts=registry))
    assert review["threats"] == 1
    assert review["legitimate"] == 2
    assert review["unreviewed"] == 1
    assert review["total"] == 4
    assert review["threats"] + review["legitimate"] + review["unreviewed"] == review["total"]


def test_no_registry_means_nothing_is_legitimate(db):
    """Fail open: with no registry every non-infringing case stays visible."""
    review = rd.review_summary(rd.load_cases(db))
    assert review["legitimate"] == 0
    assert review["threats"] == 1
    assert review["unreviewed"] == 3
    assert review["total"] == 4


def test_registering_an_institution_retroactively_cleans_metrics(db, tmp_path):
    """
    The reason the state is computed at read time rather than stored: adding an
    institution must fix historical numbers without rewriting the store.
    """
    before = rd.review_summary(rd.load_cases(db))
    assert before["unreviewed"] == 3

    p = str(tmp_path / "reg.json")
    fr.add_entry(p, "examplebank.com", basis="FDIC cert 12345")
    after = rd.review_summary(rd.load_cases(db, fi_hosts=fr.load_hosts(p)))

    assert after["legitimate"] == 2       # parent + subdomain, no store change
    assert after["unreviewed"] == 1
    assert after["threats"] == before["threats"]   # threat count is untouched


# --------------------------------------------------------------------------- #
# conflicts stay counted as threats
# --------------------------------------------------------------------------- #

def test_infringing_registered_host_stays_a_threat_and_is_flagged(tmp_path):
    path = str(tmp_path / "conflict.db")
    conn = fs.connect(path)
    conn.execute(
        "INSERT INTO findings (fingerprint, engine, primary_host, first_seen, "
        "last_seen, times_seen, raw_detections, devices_seen, queries_seen, "
        "infringing, status) VALUES (?,?,?,?,?,?,?,?,?,?, 'open')",
        ("bing:examplebank.com", "bing", "examplebank.com",
         "2026-07-01T10:00:00Z", "2026-07-02T10:00:00Z", 2, 2,
         json.dumps(["desktop"]), json.dumps(["contoso login"]), 1),
    )
    conn.commit()
    conn.close()

    p = str(tmp_path / "reg.json")
    fr.add_entry(p, "examplebank.com", basis="FDIC cert 12345")
    cases = rd.load_cases(path, fi_hosts=fr.load_hosts(p))

    assert cases[0]["review_state"] == fr.THREAT   # registry did NOT suppress it
    assert cases[0]["conflict"] is True
    review = rd.review_summary(cases)
    assert review["threats"] == 1
    assert review["legitimate"] == 0
    assert review["conflicts"] == 1


# --------------------------------------------------------------------------- #
# interaction with the existing triage exclusion
# --------------------------------------------------------------------------- #

def test_report_scope_names_map_onto_real_states(db, registry):
    """
    report.py's --scope reads as a plural ("threats"); the stored state is
    singular ("threat"). The first cut of that mapping was a silent no-match:
    the census reported 23 threats while the scoped report selected 0 cases and
    printed "no cases match". Pin every scope name to a state that exists, and
    pin the selected count to the census, so a renamed state cannot bring it
    back as an empty report instead of an error.
    """
    import report

    cases  = rd.load_cases(db, fi_hosts=registry)
    review = rd.review_summary(cases)

    assert set(report.SCOPE_TO_STATE.values()) == set(fr.STATES)
    for scope, key in (("threats", "threats"), ("legitimate", "legitimate"),
                       ("unreviewed", "unreviewed")):
        selected = rd.by_state(cases, report.SCOPE_TO_STATE[scope])
        assert len(selected) == review[key], f"--scope {scope} selected the wrong population"


def test_triage_exclusion_still_removes_cases_entirely(db, registry):
    """Triage drops the row; the registry only labels it. They are not the same."""
    cases = rd.load_cases(db, exclude_hosts={"unknown-site.example"}, fi_hosts=registry)
    assert "unknown-site.example" not in {c["host"] for c in cases}
    assert rd.review_summary(cases)["total"] == 3
