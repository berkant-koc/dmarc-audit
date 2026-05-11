"""Rendering: per-mailbox + aggregate must surface critical fail records."""
from datetime import datetime, timezone

from dmarc_audit import Record, Report, render_aggregate, render_mailbox


def _report(records=None, domain="example.com"):
    return Report(
        org="org",
        report_id="r1",
        domain=domain,
        begin=datetime.fromtimestamp(0, tz=timezone.utc),
        end=datetime.fromtimestamp(1, tz=timezone.utc),
        records=records or [],
    )


def _record(disposition="none", dkim="pass", spf="pass", count=1, ip="1.1.1.1"):
    return Record(
        source_ip=ip,
        count=count,
        disposition=disposition,
        dkim_eval=dkim,
        spf_eval=spf,
        dkim_auth=[],
        spf_auth=[],
    )


def test_render_mailbox_empty_reports():
    out = render_mailbox("primary", "dmarc@example.com", [])
    assert "no new reports" in out
    assert "primary" in out
    assert "dmarc@example.com" in out


def test_render_mailbox_includes_disposition_label_and_ok_marker():
    out = render_mailbox(
        "primary", "dmarc@example.com",
        [_report(records=[_record(disposition="none", dkim="pass", spf="pass")])]
    )
    assert "DELIVERED" in out
    assert "OK " in out
    assert "DKIM-align:pass" in out


def test_render_mailbox_flags_failing_record_with_bang():
    out = render_mailbox(
        "primary", "dmarc@example.com",
        [_report(records=[_record(disposition="reject", dkim="fail", spf="fail")])]
    )
    assert "!! " in out
    assert "REJECTED" in out


def test_render_aggregate_sums_counts_across_mailboxes():
    out = render_aggregate({
        "a": [_report(records=[_record(count=10)])],
        "b": [_report(records=[_record(count=5, disposition="quarantine",
                                       dkim="fail", spf="fail")])],
    })
    assert "delivered=10" in out
    assert "quarantined=5" in out
    assert "rejected=0" in out
    # The quarantined-with-fail record must show up in problematic list
    assert "problematic: 1 record" in out


def test_render_aggregate_clean_run_says_no_critical():
    out = render_aggregate({"a": [_report(records=[_record(count=42)])]})
    assert "delivered=42" in out
    assert "no critical records" in out
