"""Fixed handlers for privilege-boundary commands Cowrie 3.1.2 does not ship.

Without these, `usermod -aG sudo bob` would print "command not found", which
is both a fingerprint (every Ubuntu box has usermod) and a
candidate for LLM escalation. The router already marks them PRIVILEGE; these
handlers make sure the answer is fixed and plausible.

Outputs mirror Debian 12 run as root (the persona; see persona/README.md). Keep them boring: silent success is
what the real tools print.
"""

from __future__ import annotations

import os
import posixpath
from pathlib import Path

from cowrie.commands.find import Command_find as _CowrieFind
from cowrie.commands.sudo import Command_sudo as _CowrieSudo
from cowrie.shell.command import HoneyPotCommand
from cowrie.shell.fs import A_CONTENTS, A_NAME, A_TYPE, T_DIR


class _SilentSuccess(HoneyPotCommand):
    """Root-run admin tools print nothing on success."""

    usage = ""

    def call(self) -> None:
        if not self.args and self.usage:
            self.errorWrite(self.usage)
            self.exit(2)
            return
        self.exit(0)


class Command_usermod(_SilentSuccess):
    usage = "Usage: usermod [options] LOGIN\n"


class Command_userdel(_SilentSuccess):
    usage = "Usage: userdel [options] LOGIN\n"


class Command_groupadd(_SilentSuccess):
    usage = "Usage: groupadd [options] GROUP\n"


class Command_groupdel(_SilentSuccess):
    usage = "Usage: groupdel [options] GROUP\n"


class Command_gpasswd(_SilentSuccess):
    usage = "Usage: gpasswd [option] GROUP\n"


class Command_chage(_SilentSuccess):
    usage = "Usage: chage [options] LOGIN\n"


class Command_setcap(_SilentSuccess):
    usage = "usage: setcap [-h] [-q] [-v] [-n <rootid>] (-r|-|<caps>) <filename> [ ... (-r|-|<capsN>) <filenameN> ]\n"


class Command_pkexec(HoneyPotCommand):
    def call(self) -> None:
        self.errorWrite(
            "Error executing command as another user: Not authorized\n\nThis incident has been reported.\n"
        )
        self.exit(127)


def persona_text(name: str, **fmt: str) -> str:
    """Read a fixed persona output (see persona/README.md)."""
    directory = Path(os.environ.get("VULNMAZE_PERSONA_DIR", Path(__file__).parent / "persona"))
    text = (directory / name).read_text()
    for key, value in fmt.items():
        text = text.replace("{" + key + "}", value)
    return text


class Command_sudo(_CowrieSudo):
    """Cowrie's sudo rejects `sudo -l` ("illegal option") and reports version
    1.8.5p2 from 2012; both are easy fingerprints. We answer those two from
    the persona files and leave everything else to Cowrie."""

    def start(self) -> None:
        opts = [a for a in self.args if a.startswith("-")]
        rest = [a for a in self.args if not a.startswith("-")]
        if opts and not rest and set(opts) <= {"-l", "-n", "-ln", "-nl"}:
            self.write(persona_text("sudo-l.txt", hostname=self.protocol.hostname))
            self.exit(0)
            return
        if opts == ["-V"] and not rest:
            self.write(persona_text("sudo-V.txt"))
            self.exit(0)
            return
        super().start()


class Command_find(_CowrieFind):
    def find_recursive(self, path: str, depth: int) -> None:
        """Descend only into real directories, like find without -L, and list each directory once.

        Cowrie's find follows symlinks while descending, so the links in its
        filesystem that point at their own directory (/proc/1/cwd and
        /proc/1/root) make `find /` branch exponentially and freeze every session.
        """
        if depth > self.maxdepth:
            return
        try:
            node = self.fs.getfile(path, follow_symlinks=False)
            if node is None:
                return
            if self._match(path):
                self.write(f"{path}\n")
            if node[A_TYPE] == T_DIR:
                for child in node[A_CONTENTS]:
                    self.find_recursive(posixpath.join(path, child[A_NAME]), depth + 1)
        except Exception as e:
            self.errorWrite(f"find: error accessing {path}: {e}\n")


def _register() -> dict[str, type[HoneyPotCommand]]:
    table: dict[str, type[HoneyPotCommand]] = {}
    for name, cls, directory in [
        ("usermod", Command_usermod, "/usr/sbin"),
        ("userdel", Command_userdel, "/usr/sbin"),
        ("groupadd", Command_groupadd, "/usr/sbin"),
        ("groupdel", Command_groupdel, "/usr/sbin"),
        ("gpasswd", Command_gpasswd, "/usr/bin"),
        ("chage", Command_chage, "/usr/bin"),
        ("setcap", Command_setcap, "/usr/sbin"),
        ("pkexec", Command_pkexec, "/usr/bin"),
        ("sudo", Command_sudo, "/usr/bin"),
        ("find", Command_find, "/bin"),
    ]:
        table[name] = cls
        table[f"{directory}/{name}"] = cls
    return table


commands = _register()
