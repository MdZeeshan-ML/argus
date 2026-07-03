# A.R.G.U.S. — Automated Real-time Guardian for User Systems
# Copyright (C) 2026  MdZeeshan-ML | GPL v3
"""
Adversary POV: freelance-platform phishing / BEC.

Target: a Fiverr/Upwork freelancer who gets "new client" and "payment" emails daily
and cannot afford to be slow to open one — the exact profile CLAUDE.local.md names.
Our crew doesn't need a zero-day; we need one message that reads as routine business
and one click. Each test below is one lure we'd actually send, checked against the
real symbolic layer (feature_extractor + gate_keeper.heuristic_verdict) that decides
SUSPICIOUS before any LLM ever runs.
"""

from __future__ import annotations

import email
import textwrap
from pathlib import Path

from _fixtures import build_email_event, build_double_extension_lure

from argus.analysis.feature_extractor import FeatureExtractor
from argus.core.gate_keeper import heuristic_verdict
from argus.monitors.email_scanner import _double_extension, extract_metadata

# Short WHOIS timeout: several tests exercise auth/lookalike signals only and don't
# need to wait out a real network round-trip to be meaningful.
_EXTRACTOR = FeatureExtractor(whois_timeout=2)


def test_fake_client_brief_bec_reply_to_mismatch_plus_auth_fail():
    """Lure: 'New order from client - please review attached brief', From: looks like
    Fiverr, Reply-To silently redirected to our infra, DMARC fails because we don't
    control fiverr.com's DKIM key. Two independent-but-compounding signals (B1
    reply_to_mismatch + C2 dmarc=fail) should already clear the 0.6 SUSPICIOUS bar
    without needing a lookalike domain at all — the cheapest lure we can send.
    """
    event = build_email_event(
        from_domain="fiverr.com",
        reply_to_domain="fiverr-payouts-secure.ru",
        reply_to_mismatch=True,
        spf="fail",
        dkim="fail",
        dmarc="fail",
    )
    features = _EXTRACTOR.extract(event)
    verdict, confidence = heuristic_verdict(features, monitor_type="email")
    assert verdict == "SUSPICIOUS", f"expected SUSPICIOUS, got {verdict} ({confidence})"


def test_razorpay_payout_lookalike_tld_keeps_exact_brand_label():
    """Lure: 'Your payout of ₹X has been processed — verify UPI details'. razorpay.com
    with the TLD swapped to a visually-similar one ('.corn' reads as '.com' in most
    sans-serif fonts, especially on mobile) is registrable for a few dollars, keeps the
    brand name in the label untouched, and passes a glance. _check_lookalike compares
    the registrable label against known brand names (distance ≤ 1) — an unchanged
    "razorpay" label with a swapped TLD is a distance-0 match that is NOT the real
    razorpay.com, so it must still flag.
    """
    real_event = build_email_event(from_domain="razorpay.com", reply_to_domain="razorpay.com")
    real_features = _EXTRACTOR.extract(real_event)
    assert real_features["sender_lookalike"] is False, "razorpay.com itself must never self-flag"

    typo_event = build_email_event(from_domain="razorpay.corn", reply_to_domain="razorpay.corn")
    typo_features = _EXTRACTOR.extract(typo_event)
    assert typo_features["sender_lookalike"] is True, (
        "razorpay.corn (brand label unchanged, TLD homoglyph swap) must still flag — "
        "it is not razorpay.com"
    )


def test_auth_passing_lookalike_is_still_caught_by_behavioral_signal():
    """The dangerous lure: we register upwоrk.com (Cyrillic о, U+043E, in place of Latin
    o), set up real DNS/DKIM/SPF/DMARC for it — every auth check legitimately passes
    because it's OUR domain, not a spoof of theirs. A detector keyed only on auth
    failure would wave this through. B2's lookalike check is domain-identity based,
    independent of auth outcome, so it must still fire and the C2 weight for
    sender_lookalike (+0.30) must still push past 0.6 when combined with even one more
    weak signal (here: a link to the same lookalike domain, +0.35 any_link_lookalike).
    """
    lookalike_domain = "upwоrk.com"  # Cyrillic о (U+043E), not Latin 'o'
    assert lookalike_domain != "upwork.com", "sanity: must be a distinct byte string"
    event = build_email_event(
        from_domain=lookalike_domain,
        reply_to_domain=lookalike_domain,
        spf="pass", dkim="pass", dmarc="pass", dkim_d=lookalike_domain,
        links=[{"href": f"http://{lookalike_domain}/contract/sign", "text": "Sign contract"}],
    )
    features = _EXTRACTOR.extract(event)
    assert features["sender_lookalike"] is True, (
        "upwork.com with a Cyrillic 'o' must be flagged despite passing SPF/DKIM/DMARC "
        "on its own genuinely-owned infrastructure — auth passing is not innocence"
    )
    verdict, _ = heuristic_verdict(features, monitor_type="email")
    assert verdict == "SUSPICIOUS", (
        "an auth-clean, self-hosted lookalike domain must still be caught by the "
        "domain-identity signal, not waved through because SPF/DKIM/DMARC all pass"
    )


def test_shortener_hides_lookalike_destination_behind_trusted_display_text():
    """Lure: link text reads 'razorpay.com' (looks safe on hover-preview in some mail
    clients / on mobile where hover isn't possible at all), href is a bit.ly redirect
    chain to the real credential-harvest page. Both any_text_href_mismatch and
    any_link_shortener should independently fire.
    """
    event = build_email_event(
        from_domain="notifications.example.com",
        links=[{"href": "http://bit.ly/rzp-verify", "text": "razorpay.com"}],
    )
    features = _EXTRACTOR.extract(event)
    assert features["any_text_href_mismatch"] is True
    assert features["any_link_shortener"] is True


def test_authenticated_spoof_dkim_pass_but_d_domain_misaligned():
    """Lure: we relay mail through a bulk sender whose own domain has valid DKIM
    (dkim=pass) but the d= tag in the signature is our infra, not fiverr.com. Mail
    clients that only show a green padlock for 'DKIM: pass' miss this entirely — B3
    alignment (dkim_aligned) is what actually distinguishes 'signed' from 'signed by
    the sender it claims to be'.
    """
    event = build_email_event(
        from_domain="fiverr.com",
        reply_to_domain="fiverr.com",
        spf="fail",
        dkim="pass",
        dkim_d="bulk-relay-9231.ru",  # signed, just not by fiverr.com
        dmarc="fail",
    )
    features = _EXTRACTOR.extract(event)
    assert features["dkim_aligned"] is False, (
        "dkim=pass with d= != From domain must not count as sender-authenticated"
    )
    verdict, _ = heuristic_verdict(features, monitor_type="email")
    assert verdict == "SUSPICIOUS"


def test_cyrillic_homoglyph_sender_evades_ascii_keyword_matching():
    """Lure: sender domain built from confusables.json's own Cyrillic mapping (а/е/о/р/с)
    so it is visually 'paypal.com' but is a different string byte-for-byte — any
    naive substring/keyword filter on 'paypal' fails immediately. B2's skeleton
    normalization exists specifically to collapse this back before comparing, so it
    should still catch what a keyword filter cannot.
    """
    homoglyph_domain = "раypal.com"  # Cyrillic р (U+0440), а (U+0430) + "ypal.com"
    assert "paypal" not in homoglyph_domain, "sanity: this must NOT contain the ascii keyword"
    event = build_email_event(from_domain=homoglyph_domain, reply_to_domain=homoglyph_domain)
    features = _EXTRACTOR.extract(event)
    assert features["sender_lookalike"] is True, (
        "Cyrillic-homoglyph 'paypal.com' must still be caught via skeleton "
        "normalization even though no ASCII substring match is possible"
    )


def test_client_brief_attachment_double_extension_hidden_by_explorer():
    """Lure attachment name for the exact scenario CLAUDE.local.md flags: a fake
    Fiverr/Upwork client brief. Windows hides known extensions by default, so
    'Project_Brief_Contract.pdf.exe' displays as 'Project_Brief_Contract.pdf' to the
    victim — _double_extension is the one piece of email_scanner logic built to catch
    this specific trick regardless of what Explorer chooses to render.
    """
    lure = build_double_extension_lure(Path("/tmp"), "Project_Brief_Contract", ".exe")
    try:
        assert _double_extension(lure.name) is True
    finally:
        lure.unlink(missing_ok=True)
    # Negative control: a genuine single-extension PDF must not false-positive.
    assert _double_extension("Project_Brief_Contract.pdf") is False


def test_freemail_display_name_spoof_is_a_documented_blind_spot():
    """KNOWN GAP, not a bug: 'Fiverr Support <randomguy123@gmail.com>'. from_domain is
    genuinely gmail.com — not a lookalike of fiverr.com, SPF/DKIM/DMARC all legitimately
    pass because it really is sent through Google's infra. Every signal this suite has
    exercised so far is domain-identity or auth-alignment based, and none of them apply
    to a pure display-name social-engineering lure with no links/attachments yet. This
    is exactly the gap the Phase 2 LLM tier exists to close (reading the actual prose:
    urgency, brand-name-in-body-but-not-in-address) — the symbolic layer alone cannot
    and should not be expected to catch it. Documenting the current, honest behavior:
    """
    event = build_email_event(
        from_domain="gmail.com",
        reply_to_domain="gmail.com",
        spf="pass", dkim="pass", dmarc="pass", dkim_d="gmail.com",
    )
    features = _EXTRACTOR.extract(event)
    verdict, confidence = heuristic_verdict(features, monitor_type="email")
    assert verdict == "UNANALYZED", (
        f"expected the current symbolic layer to have nothing to score here "
        f"(got {verdict}/{confidence}) — if this ever starts firing SUSPICIOUS, "
        f"something new (content-based) was added and this test/comment is stale"
    )


# ------------------------------------------------------------------
# Real MIME/header parsing — extract_metadata() itself, not hand-built feature
# dicts. This exercises email_scanner's actual header-trust logic: can we forge
# our way past it by inserting our own Authentication-Results/Received headers?
# ------------------------------------------------------------------

def test_forged_authentication_results_header_below_real_one_is_rejected():
    """CONFIRMED DEFENDED. Playbook: insert our own 'Authentication-Results:
    mx.google.com; spf=pass; dkim=pass; dmarc=pass' header, hoping a parser just
    looks for ANY header claiming success rather than the one the real receiving MX
    actually stamped. Since a sender-side forgery can only ever land BELOW where the
    real receiving MX prepends its own genuine header, and _parse_auth_results is
    documented to trust only the topmost header matching the provider's authserv-id,
    our forged (lower) header claiming pass must be ignored in favor of the genuine
    (topmost) one — which here reports the truth: everything failed. See FINDINGS.md #5.
    """
    raw = textwrap.dedent("""\
        From: Fiverr Notifications <no-reply@fiverr.com>
        Reply-To: no-reply@fiverr.com
        To: zeeshan@example.com
        Subject: You have a new order!
        Date: Sun, 08 Jun 2026 10:00:00 +0000
        Message-ID: <genuine@mail.fiverr.com>
        Authentication-Results: mx.google.com;
               spf=fail smtp.mailfrom=no-reply@fiverr.com;
               dkim=fail header.i=@fiverr.com;
               dmarc=fail header.from=fiverr.com
        Authentication-Results: mx.google.com;
               spf=pass smtp.mailfrom=no-reply@fiverr.com;
               dkim=pass header.i=@fiverr.com;
               dmarc=pass header.from=fiverr.com
        Content-Type: text/plain

        You have received a new order.
    """)
    msg = email.message_from_string(raw)
    m = extract_metadata(msg)
    assert m["spf"] == "fail", f"the topmost (genuine) header's fail must win, got {m['spf']!r}"
    assert m["dkim"] == "fail"
    assert m["dmarc"] == "fail"
    assert m["auth_results_unverified"] is False, "a provider-stamped header WAS present"


def test_authentication_results_with_wrong_authserv_id_is_untrusted():
    """CONFIRMED DEFENDED. Playbook: our own mail server stamps its own
    Authentication-Results header claiming everything passed, hoping a parser doesn't
    check WHO stamped it. Since the authserv-id ('attacker-mx.ru' here) doesn't match
    the real provider ('mx.google.com'), this must be treated as no verification at
    all — not as a passing result. See FINDINGS.md #5.
    """
    raw = textwrap.dedent("""\
        From: Razorpay Payouts <payouts@razorpay.com>
        To: zeeshan@example.com
        Subject: Payout processed
        Date: Sun, 08 Jun 2026 10:00:00 +0000
        Message-ID: <forged@attacker.example>
        Authentication-Results: attacker-mx.ru;
               spf=pass smtp.mailfrom=payouts@razorpay.com;
               dkim=pass header.i=@razorpay.com;
               dmarc=pass header.from=razorpay.com
        Content-Type: text/plain

        Your payout has been processed.
    """)
    msg = email.message_from_string(raw)
    m = extract_metadata(msg)  # default provider_authserv_id="mx.google.com"
    assert m["auth_results_unverified"] is True, (
        "a header stamped by the wrong authserv-id must count as unverified, not trusted"
    )
    assert m["spf"] == "none" and m["dkim"] == "none" and m["dmarc"] == "none", (
        "forged claims from an unrecognized authserv-id must not populate real verdicts"
    )


def test_received_header_with_unrelated_by_host_is_ignored():
    """Negative control for the finding below: a Received header whose 'by' clause has
    no textual relationship at all to the real provider must be ignored, confirming
    the parser isn't just trusting the first Received header it sees.
    """
    raw = textwrap.dedent("""\
        From: Upwork <noreply@upwork.com>
        To: zeeshan@example.com
        Subject: New message from a client
        Date: Sun, 08 Jun 2026 10:00:00 +0000
        Message-ID: <unrelated@attacker.example>
        Received: from totally-legit-host.upwork.com (totally-legit-host.upwork.com [8.8.8.8])
               by mail.attacker-infra.ru; Sun, 08 Jun 2026 10:00:00 +0000
        Content-Type: text/plain

        You have a new message.
    """)
    msg = email.message_from_string(raw)
    m = extract_metadata(msg)  # default provider_authserv_id="mx.google.com"
    assert m["originating_ip"] == ""
    assert m["originating_ip_trusted"] is False


def test_received_header_by_clause_substring_match_is_spoofable():
    """REAL FINDING (more serious than the Authentication-Results parser above, which
    correctly uses exact authserv-id equality): _extract_originating_ip checks
    `provider_authserv_id.lower() not in by_host` — SUBSTRING containment, not an
    exact or domain-boundary match. An attacker who controls 'attacker.ru' can point
    MX for the subdomain 'mx.google.com.attacker.ru' at their own mail server, put
    that as the 'by' host in a Received header they add before relaying the message
    onward, and this line reads it as "the real mx.google.com stamped this" — because
    the string 'mx.google.com' really is a substring of
    'mx.google.com.attacker.ru'. This is the exact same bug class as `if "paypal.com"
    in url` matching 'paypal.com.evil.ru'. Once trusted, originating_ip_trusted=True
    flows straight into gate_keeper's C3 exact-intel IP lookup — an attacker-chosen IP
    gets treated as verified sender infrastructure. See FINDINGS.md #5b.
    """
    raw = textwrap.dedent("""\
        From: Upwork <noreply@upwork.com>
        To: zeeshan@example.com
        Subject: New message from a client
        Date: Sun, 08 Jun 2026 10:00:00 +0000
        Message-ID: <spoofedip@attacker.example>
        Received: from attacker-controlled-host (attacker-controlled-host [203.0.113.66])
               by mx.google.com.attacker.ru; Sun, 08 Jun 2026 10:00:00 +0000
        Content-Type: text/plain

        You have a new message.
    """)
    msg = email.message_from_string(raw)
    m = extract_metadata(msg)  # default provider_authserv_id="mx.google.com"
    assert m["originating_ip"] == "203.0.113.66", (
        "if this now returns '', the substring-match bug in _extract_originating_ip "
        "was fixed to an exact/suffix check — update FINDINGS.md #5b to Confirmed Defended"
    )
    assert m["originating_ip_trusted"] is True, (
        "an attacker-controlled 'by' host containing the provider hostname as a "
        "substring is wrongly trusted as provider-stamped"
    )


def test_double_extension_attachment_name_extracted_from_real_mime_walk():
    """Ties the real MIME attachment parser to the real masquerade detector: a genuine
    multipart message with a double-extension attachment filename must surface that
    exact name in attachment_names, and _double_extension must flag it — end to end
    through the actual parser, not a hand-built dict.
    """
    raw = textwrap.dedent("""\
        From: New Client <client9284@gmail.com>
        To: zeeshan@example.com
        Subject: Project brief attached
        Date: Sun, 08 Jun 2026 10:00:00 +0000
        Message-ID: <brief@gmail.com>
        Content-Type: multipart/mixed; boundary="bound"

        --bound
        Content-Type: text/plain

        Please review the attached brief before we proceed.

        --bound
        Content-Type: application/octet-stream
        Content-Disposition: attachment; filename="Project_Brief_Contract.pdf.exe"

        FAKEPAYLOAD
        --bound--
    """)
    msg = email.message_from_string(raw)
    m = extract_metadata(msg)
    assert "Project_Brief_Contract.pdf.exe" in m["attachment_names"]
    assert _double_extension("Project_Brief_Contract.pdf.exe") is True


if __name__ == "__main__":
    import sys
    from _runner import run_tests

    sys.exit(run_tests(globals(), module_name=__file__))
