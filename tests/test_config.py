"""load_mailboxes() supports both JSON-multi and single-mailbox shortcut envs."""
import json

import pytest

from dmarc_audit import load_mailboxes


def test_load_mailboxes_from_json_env(monkeypatch, tmp_path):
    pwfile = tmp_path / "pw"
    pwfile.write_text("secret")
    monkeypatch.setenv(
        "DMARC_MAILBOXES",
        json.dumps([
            {"user": "dmarc@a.com", "password_file": str(pwfile),
             "label": "first",  "domain": "a.com"},
            {"user": "dmarc@b.com", "password_file": str(pwfile),
             "label": "second", "domain": "b.com"},
        ])
    )
    boxes = load_mailboxes()
    assert len(boxes) == 2
    assert boxes[0].user == "dmarc@a.com"
    assert boxes[0].label == "first"
    assert boxes[1].domain == "b.com"


def test_load_mailboxes_single_shortcut(monkeypatch, tmp_path):
    monkeypatch.delenv("DMARC_MAILBOXES", raising=False)
    pwfile = tmp_path / "pw"
    pwfile.write_text("secret")
    monkeypatch.setenv("DMARC_USER", "dmarc@solo.example")
    monkeypatch.setenv("DMARC_PASSWORD_FILE", str(pwfile))
    boxes = load_mailboxes()
    assert len(boxes) == 1
    assert boxes[0].user == "dmarc@solo.example"
    assert boxes[0].label == "dmarc"            # default label = local-part
    assert boxes[0].domain == "solo.example"    # default domain = host-part


def test_load_mailboxes_missing_config_raises(monkeypatch):
    monkeypatch.delenv("DMARC_MAILBOXES", raising=False)
    monkeypatch.delenv("DMARC_USER", raising=False)
    monkeypatch.delenv("DMARC_PASSWORD_FILE", raising=False)
    with pytest.raises(SystemExit):
        load_mailboxes()


def test_load_mailboxes_json_overrides_single(monkeypatch, tmp_path):
    """If both shapes are set, the JSON config wins."""
    pwfile = tmp_path / "pw"
    pwfile.write_text("secret")
    monkeypatch.setenv("DMARC_USER", "should-be-ignored@x.com")
    monkeypatch.setenv("DMARC_PASSWORD_FILE", str(pwfile))
    monkeypatch.setenv(
        "DMARC_MAILBOXES",
        json.dumps([{"user": "real@x.com", "password_file": str(pwfile)}])
    )
    boxes = load_mailboxes()
    assert len(boxes) == 1
    assert boxes[0].user == "real@x.com"
