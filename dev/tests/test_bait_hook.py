from types import SimpleNamespace

import pytest
from twisted.internet import defer

from vulnmaze.cowrie_ext import escalation

BAIT = {"path": "/var/www/portal/config/database.php", "content": "define('DB_PASS', 'x');\n"}


def _session(monkeypatch, mode, reply):
    """A fake Cowrie session in the given mode whose gateway answers every assess with reply."""
    monkeypatch.setattr(escalation, "CONFIG", escalation.Config(mode, "http://gw", "t" * 16, 5.0))
    posts, files, events = [], [], []

    def post(url, json, timeout, headers):
        posts.append(json)
        return defer.fail(reply) if isinstance(reply, Exception) else defer.succeed(SimpleNamespace(code=reply[0]))

    monkeypatch.setattr(escalation.treq, "post", post)
    monkeypatch.setattr(escalation.treq, "json_content", lambda r: defer.succeed(reply[1]))
    monkeypatch.setattr(escalation, "materialise", lambda fs, path, content, uid, gid: files.append((path, content)) or True)
    protocol = SimpleNamespace(
        events=SimpleNamespace(identity={"session": "s1", "src_ip": "198.51.100.9"}, dispatch=lambda *a, **kw: events.append(kw)),
        user=SimpleNamespace(username="root", uid=0, gid=0),
        historyLines=[b"uname -a", b"id", b"ls"],
        fs=object(),
    )
    for _ in range(8):
        escalation.assess(protocol)
    return posts, files, events


def test_learned_session_asks_at_the_third_and_every_fifth_line_and_gets_its_bait(monkeypatch):
    """In learned mode the 3rd and 8th typed lines ask the gateway, and the bait it returns lands in the session with an event."""
    posts, files, events = _session(monkeypatch, "learned", (200, [BAIT]))
    assert len(posts) == 2 and posts[0] == {"session": "s1", "src_ip": "198.51.100.9", "username": "root", "history": ["uname -a", "id", "ls"]}
    assert files == [(BAIT["path"], BAIT["content"])] * 2 and events == [{"paths": [BAIT["path"]]}] * 2


@pytest.mark.parametrize(
    "mode, reply, asked",
    [("all", (200, [BAIT]), 0), ("off", (200, [BAIT]), 0), ("learned", RuntimeError("gateway down"), 2), ("learned", (500, None), 2), ("learned", (200, []), 2)],
)
def test_other_modes_and_failed_or_empty_replies_add_nothing(monkeypatch, mode, reply, asked):
    """off and all never ask; a gateway error, an HTTP error or no bait add no file and no event, and the next trigger asks again."""
    posts, files, events = _session(monkeypatch, mode, reply)
    assert len(posts) == asked and files == [] and events == []
