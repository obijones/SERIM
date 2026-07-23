"""
Tests for fi_registry.py and the three-state review model.

The behaviours under test are the ones that are easy to get subtly wrong and
expensive to get wrong:
  * FAIL CLOSED — a registry entry must never suppress an infringing case.
  * Subdomain matching — a real institution serves www./secure./locator., and
    exact-host matching would strand all of them in `unreviewed`.
  * Label-boundary safety — the suffix match must not let a lookalike host
    ("evilexamplebank.com", "examplebank.com.evil.ru") inherit legitimacy.
  * FAIL OPEN — a missing or corrupt registry yields `unreviewed`, never
    `legitimate`, so a broken file can never hide a finding.
  * The three states partition the population, so the census always adds up.

Offline: temp files only, no browser, no network, no DB.
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import fi_registry as fr  # noqa: E402


@pytest.fixture
def registry(tmp_path):
    """A registry file holding one institution."""
    p = tmp_path / "known_fi.json"
    p.write_text(json.dumps({"known_financial_institutions": [
        {"domain": "examplebank.com", "institution": "Example Bank, N.A.",
         "basis": "FDIC cert 12345", "added_by": "jdoe", "added": "2026-07-23T00:00:00Z"},
    ]}), encoding="utf-8")
    return str(p)


# --------------------------------------------------------------------------- #
# the rule — fail closed
# --------------------------------------------------------------------------- #

def test_registry_never_suppresses_infringement(registry):
    """A registered host that claims a brand term stays a THREAT."""
    hosts = fr.load_hosts(registry)
    assert fr.review_state(True, "examplebank.com", hosts) == fr.THREAT


def test_infringing_registered_host_is_flagged_as_a_conflict(registry):
    hosts = fr.load_hosts(registry)
    assert fr.is_conflict(True, "examplebank.com", hosts) is True
    # Not a conflict when it is merely legitimate, or merely infringing.
    assert fr.is_conflict(False, "examplebank.com", hosts) is False
    assert fr.is_conflict(True, "phish-example-1.com", hosts) is False


def test_non_infringing_registered_host_is_legitimate(registry):
    hosts = fr.load_hosts(registry)
    assert fr.review_state(False, "examplebank.com", hosts) == fr.LEGITIMATE


def test_unknown_host_is_unreviewed_not_legitimate(registry):
    """The bucket that holds missed threats must never read as cleared."""
    hosts = fr.load_hosts(registry)
    assert fr.review_state(False, "some-other-site.example", hosts) == fr.UNREVIEWED


def test_unparseable_host_is_unreviewed(registry):
    assert fr.review_state(False, None, fr.load_hosts(registry)) == fr.UNREVIEWED


# --------------------------------------------------------------------------- #
# matching — subdomains in, lookalikes out
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("host", [
    "examplebank.com",
    "www.examplebank.com",
    "secure.examplebank.com",
    "locator.online.examplebank.com",
])
def test_subdomains_of_a_registered_institution_are_legitimate(registry, host):
    hosts = fr.load_hosts(registry)
    assert fr.review_state(False, host, hosts) == fr.LEGITIMATE


@pytest.mark.parametrize("host", [
    "evilexamplebank.com",        # substring, not a label boundary
    "examplebank.com.evil.ru",    # brand-as-subdomain evasion
    "examplebank.co",             # neighbouring TLD
    "notexamplebank.com",
])
def test_lookalike_hosts_do_not_inherit_legitimacy(registry, host):
    hosts = fr.load_hosts(registry)
    assert fr.review_state(False, host, hosts) == fr.UNREVIEWED


# --------------------------------------------------------------------------- #
# fail open — a broken registry may never mark anything legitimate
# --------------------------------------------------------------------------- #

def test_missing_registry_yields_no_hosts(tmp_path):
    assert fr.load_hosts(str(tmp_path / "nope.json")) == set()
    assert fr.load_entries(str(tmp_path / "nope.json")) == []


def test_unset_registry_path_yields_no_hosts():
    assert fr.load_hosts(None) == set()


def test_corrupt_registry_yields_no_hosts(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{not json at all", encoding="utf-8")
    assert fr.load_hosts(str(p)) == set()


def test_wrong_shape_registry_yields_no_hosts(tmp_path):
    p = tmp_path / "wrong.json"
    p.write_text(json.dumps({"known_financial_institutions": "not-a-list"}), encoding="utf-8")
    assert fr.load_hosts(str(p)) == set()


def test_broken_registry_leaves_everything_unreviewed(tmp_path):
    """The safety property: a broken file downgrades to visible, never hidden."""
    hosts = fr.load_hosts(str(tmp_path / "missing.json"))
    assert fr.review_state(False, "examplebank.com", hosts) == fr.UNREVIEWED
    assert fr.review_state(True, "phish-example-1.com", hosts) == fr.THREAT


def test_entries_without_a_domain_are_dropped(tmp_path):
    p = tmp_path / "partial.json"
    p.write_text(json.dumps({"known_financial_institutions": [
        {"institution": "No Domain Bank"},
        {"domain": "goodbank.example"},
    ]}), encoding="utf-8")
    assert fr.load_hosts(str(p)) == {"goodbank.example"}


# --------------------------------------------------------------------------- #
# writing entries
# --------------------------------------------------------------------------- #

def test_add_entry_records_the_basis(tmp_path):
    p = str(tmp_path / "reg.json")
    entry = fr.add_entry(p, "newbank.example", institution="New Bank",
                         basis="charter 999", added_by="asmith")
    assert entry["domain"] == "newbank.example"
    assert entry["basis"] == "charter 999"
    assert entry["added_by"] == "asmith"
    assert entry["added"].endswith("Z")
    assert fr.load_hosts(p) == {"newbank.example"}


def test_add_entry_canonicalizes_url_input(tmp_path):
    p = str(tmp_path / "reg.json")
    fr.add_entry(p, "https://www.newbank.example/personal/login")
    assert fr.load_hosts(p) == {"newbank.example"}


def test_add_entry_rejects_duplicates(tmp_path):
    p = str(tmp_path / "reg.json")
    assert fr.add_entry(p, "newbank.example") is not None
    assert fr.add_entry(p, "https://www.newbank.example") is None   # same host
    assert len(fr.load_entries(p)) == 1


def test_add_entry_rejects_unparseable(tmp_path):
    p = str(tmp_path / "reg.json")
    assert fr.add_entry(p, "not a host") is None
    assert fr.add_entry(p, "") is None


def test_add_entry_creates_missing_parent_directory(tmp_path):
    p = str(tmp_path / "nested" / "dir" / "reg.json")
    assert fr.add_entry(p, "newbank.example") is not None
    assert fr.load_hosts(p) == {"newbank.example"}


def test_add_entry_preserves_existing(tmp_path):
    p = str(tmp_path / "reg.json")
    fr.add_entry(p, "first.example", basis="a")
    fr.add_entry(p, "second.example", basis="b")
    assert fr.load_hosts(p) == {"first.example", "second.example"}
    assert [e["basis"] for e in fr.load_entries(p)] == ["a", "b"]  # sorted by domain


# --------------------------------------------------------------------------- #
# the states partition the population
# --------------------------------------------------------------------------- #

def test_every_case_lands_in_exactly_one_state(registry):
    hosts = fr.load_hosts(registry)
    observations = [
        (True,  "phish-example-1.com"),
        (False, "examplebank.com"),
        (False, "unknown-site.example"),
        (True,  "examplebank.com"),      # conflict — still a threat
        (False, None),
    ]
    states = [fr.review_state(i, h, hosts) for i, h in observations]
    assert all(s in fr.STATES for s in states)
    assert states.count(fr.THREAT) == 2
    assert states.count(fr.LEGITIMATE) == 1
    assert states.count(fr.UNREVIEWED) == 2
    assert len(states) == len(observations)   # no case counted twice or lost
