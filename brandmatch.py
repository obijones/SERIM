"""
brandmatch.py — does a search result CLAIM our brand while pointing somewhere
we do not own?

This is the analyst's own rule, stated plainly:

    "An advertisement with a [Headline] of 'Contoso Online Portal' that does
     not have a url with 'contosologin.com' or 'contosoaccount.com/ui'
     is infringing on our brand."

Two axes, kept deliberately separate (see serp_monitor for the channel axis):

    channel      HOW it appeared        sponsored_ad | organic
    infringement WHAT it claims to be   brand-claiming title + non-brand host

They are orthogonal, and the combinations are all real:

    sponsored + infringing  -> classic paid-search brand hijacking (advertiser-example.one)
    organic   + infringing  -> SEO poisoning (phish-example-1.com, contoso-login.com)
    either    + legitimate  -> an unrelated business ranking or bidding on the same
                               generic search term. The terms are generic, so this
                               is EXPECTED and is not an offence.

IMPORTANT — infringement is a SIGNAL, not a suppression gate. Nothing here
decides whether an ad is reported; it decides how it is LABELLED and ranked.
The monitor deliberately looks for "any SEO poisoning and sponsored
advertisements", so detection stays broad and this narrows only the verdict.

A title claims the brand if EITHER rule fires. Both are needed; each covers a
real evasion the other misses.

  1. Collapsed containment — strip everything but letters and digits, then test
     for containment. This survives punctuation and spacing games:

         "Contoso Account - Log In"  ->  contosoaccountlogin   MATCHES "contoso account login"

  2. Ordered token subsequence — every word of a brand term appears in the
     title, in order, as a whole word. This survives PADDING, where the attacker
     interleaves extra words:

         "contoso account online portal login - phish-example-1.com"
              ^contoso        ^online ^portal          MATCHES "contoso online portal"

     Rule 1 alone misses this, because "account" breaks the contiguous run — and
     it is the title of the single most-detected phishing site in the evidence
     set (phish-example-1.com, 62 detections). Precision-first was too strict.

Whole-word matching is what keeps rule 2 honest. The shared-word false positives
this brand genuinely lives with all fail, because none of them contains every
word of a brand term:

    "Contoso Gelato"                     no online/portal, no account/login
    "City of Contoso, Texas"             same
    "Contoso — Enterprise Software"      contoso.com is an unrelated real business
    "Fabrikam — Online Account Portal"   no "contoso"
    "Contoso Corporation" (Wikipedia)    no full brand term present

Detection stays broad regardless; this only decides the verdict and the ranking.
"""

from __future__ import annotations

import re

from domainmatch import host_in

_NON_ALNUM = re.compile(r"[^a-z0-9]+")


def collapse(text: str | None) -> str:
    """'Contoso Account - Log In' -> 'contosoaccountlogin'. None/'N/A' -> ''."""
    if not text or text.strip().upper() == "N/A":
        return ""
    return _NON_ALNUM.sub("", text.lower())


def tokens(text: str | None) -> list[str]:
    """'Contoso Account - Log In' -> ['contoso', 'account', 'log', 'in']."""
    if not text or text.strip().upper() == "N/A":
        return []
    return [t for t in _NON_ALNUM.split(text.lower()) if t]


def _is_ordered_subsequence(needles: list[str], haystack: list[str]) -> bool:
    """Do all needle words appear in haystack, in order, as whole words?"""
    if not needles:
        return False
    it = iter(haystack)
    return all(any(word == h for h in it) for word in needles)


def claimed_brand_term(title: str | None, brand_terms) -> str | None:
    """The first brand term the title asserts, or None. See module docstring."""
    collapsed = collapse(title)
    if not collapsed:
        return None
    title_tokens = tokens(title)
    for term in brand_terms:
        ct = collapse(term)
        if ct and ct in collapsed:                                    # rule 1
            return term
        if _is_ordered_subsequence(tokens(term), title_tokens):       # rule 2
            return term
    return None


def assess(title: str | None, host: str | None, brand_terms, allowlist) -> dict:
    """
    Verdict for one result. Channel-agnostic: apply to sponsored ads AND to
    organic results alike.

    Returns:
        claims_brand  the result's title asserts a brand term verbatim
        matched_term  which one
        brand_owned   the destination is a domain we own
        infringing    claims the brand but does not land on a domain we own

    Fails CLOSED on an unknown host: a result that claims the brand and whose
    destination we could not resolve is treated as infringing, because we
    cannot show it is ours. An unknown host that does NOT claim the brand is
    not infringing — absence of a claim is not evidence of one.
    """
    term = claimed_brand_term(title, brand_terms)
    if term is None:
        return {"claims_brand": False, "matched_term": None,
                "brand_owned": bool(host) and host_in(host, allowlist),
                "infringing": False}

    brand_owned = host_in(host, allowlist) if host else False
    return {"claims_brand": True, "matched_term": term,
            "brand_owned": brand_owned, "infringing": not brand_owned}
