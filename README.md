# dmarc-audit

[![test](https://github.com/berkant-koc/dmarc-audit/actions/workflows/test.yml/badge.svg)](https://github.com/berkant-koc/dmarc-audit/actions/workflows/test.yml)

Pulls [RFC 7489](https://www.rfc-editor.org/rfc/rfc7489) DMARC aggregate
reports out of an IMAP mailbox, parses the `.gz` / `.zip` / `.xml`
attachments transparently, and prints a per-record verdict plus an
across-mailbox aggregate. Spots SPF/DKIM alignment drift before it
becomes a delivery problem.

Designed for daily cron / systemd-timer use. Stdlib-only — no external
dependencies. ASCII output, pipe-friendly.

## Quickstart

Single mailbox:

```bash
git clone https://github.com/YOU/dmarc-audit.git
cd dmarc-audit

export DMARC_IMAP_HOST=imap.example.com
export DMARC_USER=dmarc@example.com
export DMARC_PASSWORD_FILE=~/.secrets/dmarc-pass

python3 dmarc_audit.py
```

Multiple mailboxes (e.g. one per domain you own):

```bash
export DMARC_IMAP_HOST=imap.example.com
export DMARC_MAILBOXES='[
  {"user": "dmarc@example.com",  "password_file": "/secrets/example",     "label": "example",  "domain": "example.com"},
  {"user": "dmarc@otherdom.de",  "password_file": "/secrets/otherdom",    "label": "otherdom", "domain": "otherdom.de"}
]'

python3 dmarc_audit.py            # both mailboxes, only UNSEEN
python3 dmarc_audit.py --all      # both mailboxes, all messages
python3 dmarc_audit.py --label example
```

## Configuration (env vars)

| Variable | Default | Description |
|---|---|---|
| `DMARC_IMAP_HOST` | *(required)* | IMAP-SSL hostname |
| `DMARC_IMAP_PORT` | `993` | IMAP-SSL port |
| `DMARC_MAILBOXES` | — | JSON array of mailbox configs *(takes precedence)* |
| `DMARC_USER` | — | Single-mailbox quick-config |
| `DMARC_PASSWORD_FILE` | — | Path to file containing the IMAP password |

Passwords are read from files (not env vars) so they do not leak in
`ps aux` / process listings. `chmod 600` recommended.

## Output sample

```
[primary] 3 message(s) fetched.
=== mailbox: dmarc@example.com  (3 report(s)) ===

  org:        google.com
  report id:  19283746
  domain:     example.com
  range:      2026-05-01T00:00:00+00:00  ->  2026-05-02T00:00:00+00:00
    OK IP 209.85.220.69     count=147  disposition=DELIVERED    DKIM-align:pass  SPF-align:pass
        DKIM-auth: example.com=pass/sel=mailgun
        SPF-auth : example.com=pass

=== aggregate ===
  totals: delivered=147 quarantined=0 rejected=0
  no critical records (no full DKIM+SPF fail).
```

When something fails, the verdict marker switches to `!!` and the IP
appears in the aggregate's `problematic` list — that is your cue to
investigate whether a third-party sender (Mailchimp, Mailgun, your
SaaS-of-the-month) is mis-configured or whether someone is spoofing your
domain.

## systemd-timer example

`~/.config/systemd/user/dmarc-audit.service`:

```ini
[Unit]
Description=DMARC aggregate-report audit

[Service]
Type=oneshot
Environment="DMARC_IMAP_HOST=imap.example.com"
Environment="DMARC_USER=dmarc@example.com"
Environment="DMARC_PASSWORD_FILE=%h/.secrets/dmarc-pass"
ExecStart=/usr/bin/python3 %h/dmarc-audit/dmarc_audit.py
StandardOutput=append:%h/.local/share/dmarc-audit.log
```

`~/.config/systemd/user/dmarc-audit.timer`:

```ini
[Unit]
Description=Run dmarc-audit daily

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
```

## What you publish in DNS

The corresponding DMARC TXT record on each domain you monitor:

```
_dmarc.example.com.  IN  TXT  "v=DMARC1; p=reject; pct=100; adkim=s; aspf=s;
                                rua=mailto:dmarc@example.com;
                                ruf=mailto:dmarc@example.com; fo=1;"
```

Aggregate reports (RUA) go to the mailbox this tool reads. Failure
reports (RUF) are out of scope here — they require per-message handling
and contain PII; treat carefully.

## License

MIT. See `LICENSE`.
