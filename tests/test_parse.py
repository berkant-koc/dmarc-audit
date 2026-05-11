"""Parser must handle minimal, populated, and malformed RFC-7489 XML."""
from datetime import datetime, timezone

from dmarc_audit import parse_report


def test_parse_minimal_envelope():
    xml = b"""<?xml version="1.0"?>
<feedback>
  <report_metadata>
    <org_name>Sender Inc</org_name>
    <report_id>abc-123</report_id>
    <date_range><begin>0</begin><end>3600</end></date_range>
  </report_metadata>
  <policy_published>
    <domain>example.com</domain>
  </policy_published>
</feedback>"""
    r = parse_report(xml)
    assert r is not None
    assert r.org == "Sender Inc"
    assert r.report_id == "abc-123"
    assert r.domain == "example.com"
    assert r.records == []
    assert r.begin == datetime.fromtimestamp(0, tz=timezone.utc)
    assert r.end == datetime.fromtimestamp(3600, tz=timezone.utc)


def test_parse_invalid_xml_returns_none():
    assert parse_report(b"<not-closed") is None


def test_parse_record_with_auth_results():
    xml = b"""<?xml version="1.0"?>
<feedback>
  <report_metadata>
    <org_name>google.com</org_name>
    <report_id>r1</report_id>
    <date_range><begin>1714521600</begin><end>1714608000</end></date_range>
  </report_metadata>
  <policy_published><domain>example.com</domain></policy_published>
  <record>
    <row>
      <source_ip>209.85.220.69</source_ip>
      <count>147</count>
      <policy_evaluated>
        <disposition>none</disposition>
        <dkim>pass</dkim>
        <spf>pass</spf>
      </policy_evaluated>
    </row>
    <auth_results>
      <dkim><domain>example.com</domain><result>pass</result><selector>mailgun</selector></dkim>
      <spf><domain>example.com</domain><result>pass</result></spf>
    </auth_results>
  </record>
</feedback>"""
    r = parse_report(xml)
    assert r is not None
    assert len(r.records) == 1
    rec = r.records[0]
    assert rec.source_ip == "209.85.220.69"
    assert rec.count == 147
    assert rec.disposition == "none"
    assert rec.dkim_eval == "pass"
    assert rec.spf_eval == "pass"
    assert rec.dkim_auth == [("example.com", "pass", "mailgun")]
    assert rec.spf_auth == [("example.com", "pass")]


def test_parse_record_with_failing_alignment():
    xml = b"""<?xml version="1.0"?>
<feedback>
  <report_metadata>
    <org_name>fail-test</org_name><report_id>r2</report_id>
    <date_range><begin>0</begin><end>1</end></date_range>
  </report_metadata>
  <policy_published><domain>example.com</domain></policy_published>
  <record>
    <row>
      <source_ip>192.0.2.1</source_ip>
      <count>3</count>
      <policy_evaluated>
        <disposition>reject</disposition>
        <dkim>fail</dkim>
        <spf>fail</spf>
      </policy_evaluated>
    </row>
  </record>
</feedback>"""
    r = parse_report(xml)
    assert r is not None
    rec = r.records[0]
    assert rec.disposition == "reject"
    assert rec.dkim_eval == "fail"
    assert rec.spf_eval == "fail"
    assert rec.dkim_auth == []
    assert rec.spf_auth == []
