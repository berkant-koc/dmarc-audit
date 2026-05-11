#!/usr/bin/env python3
"""
DMARC aggregate-report inspector.

Reads RFC-7489 DMARC aggregate XML reports out of a IMAP mailbox (the
one you publish as `rua=mailto:` in your DMARC record), parses .gz / .zip
attachments transparently, and prints a compact per-record verdict plus
a cross-mailbox aggregate. Useful as a daily cron to spot SPF/DKIM
alignment drift before it becomes a delivery problem.

Configuration is environment-only — no hardcoded credentials:

    DMARC_IMAP_HOST       IMAP-SSL host             (required)
    DMARC_IMAP_PORT       default 993
    DMARC_MAILBOXES       JSON list of mailbox configs; each entry:
                            {"user": "dmarc@example.com",
                             "password_file": "/path/to/pwfile",
                             "label":    "primary",
                             "domain":   "example.com"}
                          OR set DMARC_USER + DMARC_PASSWORD_FILE for
                          a single-mailbox quick run.

Modes:
    python3 dmarc_audit.py                 only UNSEEN messages
    python3 dmarc_audit.py --all           all messages in INBOX
    python3 dmarc_audit.py --label primary scope to one mailbox label

Output is plain-text, ASCII-only, designed to be piped into mail or a
log file. Returns 0 on success, 1 on partial failure, 2 on config error.
"""
from __future__ import annotations

import argparse
import email
import gzip
import imaplib
import io
import json
import os
import sys
import zipfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


# ────────────────────────── data shapes ──────────────────────────────


@dataclass
class Record:
    source_ip: str
    count: int
    disposition: str
    dkim_eval: str   # DMARC alignment verdict (pass/fail)
    spf_eval: str
    dkim_auth: list  # raw auth_results: (domain, result, selector)
    spf_auth: list   # (domain, result)


@dataclass
class Report:
    org: str
    report_id: str
    domain: str
    begin: datetime
    end: datetime
    records: list


@dataclass
class Mailbox:
    user: str
    password_file: Path
    label: str
    domain: str


# ────────────────────────── config loading ───────────────────────────


def load_mailboxes() -> list[Mailbox]:
    raw = os.environ.get("DMARC_MAILBOXES")
    if raw:
        data = json.loads(raw)
        return [
            Mailbox(
                user=m["user"],
                password_file=Path(m["password_file"]),
                label=m.get("label", m["user"].split("@")[0]),
                domain=m.get("domain", m["user"].split("@", 1)[1]),
            )
            for m in data
        ]
    user = os.environ.get("DMARC_USER")
    pwfile = os.environ.get("DMARC_PASSWORD_FILE")
    if user and pwfile:
        return [
            Mailbox(
                user=user,
                password_file=Path(pwfile),
                label=user.split("@")[0],
                domain=user.split("@", 1)[1],
            )
        ]
    raise SystemExit(
        "error: set DMARC_MAILBOXES (JSON) or DMARC_USER + DMARC_PASSWORD_FILE"
    )


# ────────────────────────── IMAP fetching ────────────────────────────


def fetch_messages(box: Mailbox, only_unseen: bool, host: str, port: int) -> list[bytes]:
    pw = box.password_file.read_text().strip()
    imap = imaplib.IMAP4_SSL(host, port)
    imap.login(box.user, pw)
    imap.select("INBOX")
    crit = "UNSEEN" if only_unseen else "ALL"
    typ, data = imap.search(None, crit)
    if typ != "OK":
        imap.logout()
        return []
    ids = data[0].split()
    out: list[bytes] = []
    for mid in ids:
        typ, msg_data = imap.fetch(mid, "(BODY.PEEK[])")
        if typ != "OK" or not msg_data or not msg_data[0]:
            continue
        out.append(msg_data[0][1])
    imap.logout()
    return out


def extract_xml_payloads(raw: bytes) -> list[bytes]:
    msg = email.message_from_bytes(raw)
    xmls: list[bytes] = []
    for part in msg.walk():
        ctype = (part.get_content_type() or "").lower()
        fname = (part.get_filename() or "").lower()
        payload = part.get_payload(decode=True)
        if not payload:
            continue
        if fname.endswith(".gz") or "gzip" in ctype:
            try:
                xmls.append(gzip.decompress(payload))
            except Exception as e:
                print(f"  [gz-decode-fail] {fname}: {e}", file=sys.stderr)
        elif fname.endswith(".zip") or "zip" in ctype:
            try:
                with zipfile.ZipFile(io.BytesIO(payload)) as z:
                    for name in z.namelist():
                        if name.lower().endswith(".xml"):
                            xmls.append(z.read(name))
            except Exception as e:
                print(f"  [zip-decode-fail] {fname}: {e}", file=sys.stderr)
        elif fname.endswith(".xml") or "xml" in ctype:
            xmls.append(payload)
    return xmls


# ────────────────────────── XML parsing ──────────────────────────────


def parse_report(xml_bytes: bytes) -> Report | None:
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError as e:
        print(f"  [xml-parse-fail] {e}", file=sys.stderr)
        return None
    md = root.find("report_metadata")
    pp = root.find("policy_published")
    org = (md.findtext("org_name") or "").strip() if md is not None else ""
    rid = (md.findtext("report_id") or "").strip() if md is not None else ""
    domain = (pp.findtext("domain") or "").strip() if pp is not None else ""
    begin_ts = int(md.findtext("date_range/begin") or 0) if md is not None else 0
    end_ts = int(md.findtext("date_range/end") or 0) if md is not None else 0
    begin = datetime.fromtimestamp(begin_ts, tz=timezone.utc)
    end = datetime.fromtimestamp(end_ts, tz=timezone.utc)

    records: list[Record] = []
    for rec in root.findall("record"):
        row = rec.find("row")
        eval_node = row.find("policy_evaluated") if row is not None else None
        auth = rec.find("auth_results")

        ip = (row.findtext("source_ip") or "").strip() if row is not None else ""
        cnt = int(row.findtext("count") or 0) if row is not None else 0
        disp = (eval_node.findtext("disposition") or "").strip() if eval_node is not None else ""
        dkim_eval = (eval_node.findtext("dkim") or "").strip() if eval_node is not None else ""
        spf_eval = (eval_node.findtext("spf") or "").strip() if eval_node is not None else ""

        dkim_auth: list[tuple[str, str, str]] = []
        spf_auth: list[tuple[str, str]] = []
        if auth is not None:
            for d in auth.findall("dkim"):
                dkim_auth.append((
                    (d.findtext("domain") or "").strip(),
                    (d.findtext("result") or "").strip(),
                    (d.findtext("selector") or "").strip(),
                ))
            for s in auth.findall("spf"):
                spf_auth.append((
                    (s.findtext("domain") or "").strip(),
                    (s.findtext("result") or "").strip(),
                ))
        records.append(Record(ip, cnt, disp, dkim_eval, spf_eval, dkim_auth, spf_auth))
    return Report(org, rid, domain, begin, end, records)


# ────────────────────────── rendering ────────────────────────────────


DISPOSITION_LABEL = {
    "none": "DELIVERED",
    "quarantine": "QUARANTINED",
    "reject": "REJECTED",
}


def render_mailbox(label: str, user: str, reports: list[Report]) -> str:
    if not reports:
        return f"[{label}] {user}: no new reports."
    lines = [f"=== mailbox: {user}  ({len(reports)} report(s)) ==="]
    for r in reports:
        lines.append("")
        lines.append(f"  org:        {r.org}")
        lines.append(f"  report id:  {r.report_id}")
        lines.append(f"  domain:     {r.domain}")
        lines.append(f"  range:      {r.begin.isoformat()}  ->  {r.end.isoformat()}")
        if not r.records:
            lines.append("  -> no records")
            continue
        for rec in r.records:
            tag = DISPOSITION_LABEL.get(rec.disposition, rec.disposition.upper())
            ok = rec.dkim_eval == "pass" or rec.spf_eval == "pass"
            flag = "OK " if ok else "!! "
            dkim_str = ", ".join(
                f"{d}={res}" + (f"/sel={sel}" if sel else "")
                for d, res, sel in rec.dkim_auth
            ) or "-"
            spf_str = ", ".join(f"{d}={res}" for d, res in rec.spf_auth) or "-"
            lines.append(
                f"    {flag}IP {rec.source_ip:<18} "
                f"count={rec.count:<3} "
                f"disposition={tag:<12} "
                f"DKIM-align:{rec.dkim_eval}  SPF-align:{rec.spf_eval}"
            )
            lines.append(f"        DKIM-auth: {dkim_str}")
            lines.append(f"        SPF-auth : {spf_str}")
    return "\n".join(lines)


def render_aggregate(reports_by_label: dict[str, list[Report]]) -> str:
    totals = {"DELIVERED": 0, "QUARANTINED": 0, "REJECTED": 0}
    fails: list[tuple[str, str, int, str, str, list, list]] = []
    for reports in reports_by_label.values():
        for r in reports:
            for rec in r.records:
                tag = DISPOSITION_LABEL.get(rec.disposition, rec.disposition.upper())
                totals[tag] = totals.get(tag, 0) + rec.count
                ok = rec.dkim_eval == "pass" or rec.spf_eval == "pass"
                if not ok:
                    fails.append((
                        r.domain, rec.source_ip, rec.count,
                        rec.dkim_eval, rec.spf_eval,
                        rec.dkim_auth, rec.spf_auth,
                    ))
    lines = ["=== aggregate ==="]
    lines.append(
        f"  totals: delivered={totals['DELIVERED']} "
        f"quarantined={totals['QUARANTINED']} rejected={totals['REJECTED']}"
    )
    if fails:
        lines.append(f"  problematic: {len(fails)} record(s) with full DKIM+SPF fail:")
        for dom, ip, cnt, dk, sp, dk_auth, sp_auth in fails:
            dkim_str = ", ".join(f"{d}={res}" for d, res, *_ in dk_auth) or "-"
            spf_str = ", ".join(f"{d}={res}" for d, res in sp_auth) or "-"
            lines.append(
                f"    {dom}  IP={ip}  count={cnt}  "
                f"DKIM-align={dk} SPF-align={sp}"
            )
            lines.append(f"      DKIM-auth: {dkim_str}")
            lines.append(f"      SPF-auth : {spf_str}")
    else:
        lines.append("  no critical records (no full DKIM+SPF fail).")
    return "\n".join(lines)


# ────────────────────────── entry ────────────────────────────────────


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--label", help="restrict to one mailbox label")
    ap.add_argument("--all", action="store_true", help="all messages (not only UNSEEN)")
    args = ap.parse_args()

    host = os.environ.get("DMARC_IMAP_HOST")
    if not host:
        print("error: set DMARC_IMAP_HOST", file=sys.stderr)
        return 2
    port = int(os.environ.get("DMARC_IMAP_PORT", "993"))

    try:
        mailboxes = load_mailboxes()
    except (KeyError, json.JSONDecodeError, ValueError) as e:
        print(f"error: malformed mailbox config: {e}", file=sys.stderr)
        return 2

    if args.label:
        mailboxes = [m for m in mailboxes if m.label == args.label]
        if not mailboxes:
            print(f"error: no mailbox with label '{args.label}'", file=sys.stderr)
            return 2

    reports_by_label: dict[str, list[Report]] = {}
    exit_code = 0
    for box in mailboxes:
        try:
            raws = fetch_messages(box, only_unseen=not args.all, host=host, port=port)
        except Exception as e:
            print(f"[{box.label}] IMAP error: {e}", file=sys.stderr)
            reports_by_label[box.label] = []
            exit_code = 1
            continue
        reports: list[Report] = []
        print(f"[{box.label}] {len(raws)} message(s) fetched.", file=sys.stderr)
        for raw in raws:
            for xml in extract_xml_payloads(raw):
                rep = parse_report(xml)
                if rep is not None:
                    reports.append(rep)
        reports_by_label[box.label] = reports
        print(render_mailbox(box.label, box.user, reports))
        print()

    print(render_aggregate(reports_by_label))
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
