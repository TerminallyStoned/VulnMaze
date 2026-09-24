"""Deterministic command router.

Every command stage is put in exactly one class:

* PRIVILEGE           crosses a privilege/identity boundary or touches a
                      sensitive path. Always answered by a fixed handler and
                      never by the LLM. This is the security floor.
* DETERMINISTIC       a command Cowrie (or the state store) already answers.
* ESCALATE_CANDIDATE  anything else. By default it gets Cowrie's normal
                      behaviour; an escalation policy may send it to the LLM.

The rules are deliberately conservative: a false PRIVILEGE only costs LLM
coverage, while a false ESCALATE_CANDIDATE could put the LLM in front of a
privilege boundary.

Two entry points:

* ``classify_argv`` takes one already-expanded command (a list of words). The
  Cowrie hook uses it, because Cowrie has already removed quotes, expanded
  variables and run command substitutions by the time it calls us, so
  obfuscation such as ``c'a't`` or ``$(echo cat)`` is gone.
* ``classify_line`` takes a raw input line and splits it itself. It is for
  offline work on datasets, where there is no shell to do the expansion.
"""

from __future__ import annotations

import posixpath
import re
import shlex
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from enum import StrEnum
from fnmatch import fnmatchcase

from .known_commands import KNOWN_COMMANDS
from .rules import PRIVILEGE_COMMANDS, SENSITIVE_PATHS, SENSITIVE_SEGMENTS, SHELL_BUILTINS


class Route(StrEnum):
    PRIVILEGE = "privilege"
    DETERMINISTIC = "deterministic"
    ESCALATE_CANDIDATE = "escalate_candidate"


@dataclass(frozen=True)
class Decision:
    route: Route
    command: str            # effective command name (basename, wrappers removed)
    argv: tuple[str, ...]   # the stage as classified
    reason: str

    def as_dict(self) -> dict:
        return {
            "route": self.route.value,
            "command": self.command,
            "argv": list(self.argv),
            "reason": self.reason,
        }


IsKnown = Callable[[str], bool]

_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_GLOB_CHARS = set("*?[")
# Path-looking substrings inside a larger word, e.g. the code in
# `python -c "open('/etc/shadow')"` or `dd if=/dev/mem`.
_EMBEDDED_PATH = re.compile(r"(?:~|/)[A-Za-z0-9_.*?\[\]/+-]*")
_CONTROL_OPERATORS = {";", "&&", "||", "|", "&", "\n", "|&", ";;"}
# Wrappers whose real command is one of their arguments.
_WRAPPERS = {"env", "nohup", "command", "builtin", "exec", "time", "nice",
             "timeout", "stdbuf", "busybox", "setsid", "xargs"}


def _default_is_known(cmd: str) -> bool:
    return posixpath.basename(cmd) in KNOWN_COMMANDS


# --------------------------------------------------------------------------
# Path matching
# --------------------------------------------------------------------------

def _segments(path: str) -> list[str]:
    return [s for s in path.split("/") if s]


def _seg_match(name: str, pattern: str) -> bool:
    """Shell-style match of one path segment: wildcards never match a
    leading dot, as in bash without dotglob."""
    if name.startswith(".") and not pattern.startswith("."):
        return False
    return fnmatchcase(name, pattern)


def _glob_hits_sensitive(pattern: str) -> bool:
    """True if a glob could expand to a sensitive path. Wildcards never cross
    a '/'. For a sensitive directory the glob must reach inside it."""
    pat = _segments(pattern)
    for entry in SENSITIVE_PATHS:
        ent = _segments(entry)
        is_dir = entry.endswith("/")
        if is_dir and len(pat) <= len(ent):
            continue
        if not is_dir and len(pat) != len(ent):
            continue
        if all(_seg_match(e, p) for e, p in zip(ent, pat, strict=False)):
            return True
    return False


def normalise_path(word: str, cwd: str, home: str) -> str:
    if word == "~" or word.startswith("~/"):
        word = home + word[1:]
    if not word.startswith("/"):
        word = posixpath.join(cwd or "/", word)
    norm = posixpath.normpath(word)
    return "/" + norm.lstrip("/")  # normpath keeps a leading '//'


def is_sensitive_path(word: str, cwd: str = "/root", home: str = "/root") -> bool:
    path = normalise_path(word, cwd, home)
    for seg in _segments(path):
        if seg in SENSITIVE_SEGMENTS or (_GLOB_CHARS & set(seg) and any(
                _seg_match(s, seg) for s in SENSITIVE_SEGMENTS)):
            return True
    if _GLOB_CHARS & set(path):
        return _glob_hits_sensitive(path)
    for entry in SENSITIVE_PATHS:
        if entry.endswith("/"):
            if path == entry.rstrip("/") or path.startswith(entry):
                return True
        elif path == entry:
            return True
    return False


def _words_touching_sensitive(argv: Iterable[str], cwd: str, home: str) -> str | None:
    for pos, word in enumerate(argv):
        if not word or word in _CONTROL_OPERATORS:
            continue
        if "://" in word:
            # A URL names a remote resource: `wget http://x/etc/shadow` does
            # not read the local file.
            continue
        if pos == 0 and "/" not in word:
            continue  # a bare command name is not a path
        candidates = [word]
        if "=" in word:                       # --file=/etc/shadow, if=/dev/mem
            candidates.append(word.split("=", 1)[1])
        candidates.extend(_EMBEDDED_PATH.findall(word))
        for cand in candidates:
            if not cand or cand.startswith("-"):
                continue
            # Plain relative words ("shadow" with cwd=/etc) only count when
            # they are a whole argument, not a fragment of code.
            if cand is not word and not cand.startswith(("/", "~")):
                continue
            if is_sensitive_path(cand, cwd, home):
                return cand
    return None


def _grants_setuid(argv: list[str]) -> bool:
    for arg in argv[1:]:
        if re.fullmatch(r"[0-7]{4,5}", arg) and int(arg[-4]) & 6:
            return True
        if re.fullmatch(r"[ugoa]*[+=][rwxXst]*s[rwxXst]*", arg):
            return True
    return False


# --------------------------------------------------------------------------
# Classification
# --------------------------------------------------------------------------

def _unwrap(argv: list[str]) -> list[str]:
    """Drop leading assignments and wrapper commands so `env X=1 nohup cat f`
    is classified as `cat f`."""
    out = list(argv)
    for _ in range(8):  # bounded, wrappers can nest
        while out and _ASSIGNMENT.match(out[0]):
            out.pop(0)
        if not out:
            return out
        name = posixpath.basename(out[0])
        if name not in _WRAPPERS or len(out) == 1:
            return out
        out.pop(0)
        # skip wrapper options and their numeric/assignment arguments
        while out and (out[0].startswith("-") or _ASSIGNMENT.match(out[0])
                       or (name in {"timeout", "nice"} and re.fullmatch(r"[\d.]+[smhd]?", out[0]))):
            opt = out.pop(0)
            if name == "nice" and opt == "-n" and out:
                out.pop(0)
    return out


def classify_argv(
    argv: list[str] | tuple[str, ...],
    cwd: str = "/root",
    home: str = "/root",
    is_known: IsKnown | None = None,
) -> Decision:
    is_known = is_known or _default_is_known
    original = tuple(argv)
    inner = _unwrap(list(argv))
    if not inner:
        return Decision(Route.DETERMINISTIC, "", original, "assignment only")

    raw_cmd = inner[0]
    cmd = posixpath.basename(raw_cmd)

    if cmd in PRIVILEGE_COMMANDS:
        return Decision(Route.PRIVILEGE, cmd, original, f"privilege command '{cmd}'")

    # Check every word of the original stage, wrappers included, so a path
    # given to a wrapper (e.g. `env -S "cat /etc/shadow"`) still counts.
    hit = _words_touching_sensitive(original, cwd, home)
    if hit is not None:
        return Decision(Route.PRIVILEGE, cmd, original, f"sensitive path '{hit}'")

    if cmd == "chmod" and _grants_setuid(inner):
        return Decision(Route.PRIVILEGE, cmd, original, "setuid/setgid mode")

    if "$" in raw_cmd or "`" in raw_cmd:
        return Decision(Route.ESCALATE_CANDIDATE, cmd, original, "dynamic command name")

    if cmd in SHELL_BUILTINS:
        return Decision(Route.DETERMINISTIC, cmd, original, "shell builtin")
    if is_known(raw_cmd):
        return Decision(Route.DETERMINISTIC, cmd, original, "implemented by Cowrie")
    return Decision(Route.ESCALATE_CANDIDATE, cmd, original, "not implemented")


def split_pipeline(tokens: list[str]) -> list[list[str]]:
    """Split an expanded token list on '|' into stages (Cowrie passes one
    pipeline at a time; ';' and '&&' are already handled by its parser)."""
    stages: list[list[str]] = [[]]
    for tok in tokens:
        if tok in ("|", "|&"):
            stages.append([])
        else:
            stages[-1].append(tok)
    return [s for s in stages if s]


# ---- offline splitting of raw lines --------------------------------------

def _extract_substitutions(line: str) -> tuple[str, list[str]]:
    """Replace $(...) and `...` with a placeholder and return their contents
    so they can be classified as commands in their own right."""
    subs: list[str] = []
    out: list[str] = []
    i = 0
    in_single = False
    while i < len(line):
        ch = line[i]
        if ch == "'" and not in_single:
            in_single = True
        elif ch == "'" and in_single:
            in_single = False
        if not in_single and line.startswith("$(", i):
            depth, j = 1, i + 2
            while j < len(line) and depth:
                if line.startswith("$(", j):
                    depth += 1
                    j += 1
                elif line[j] == ")":
                    depth -= 1
                j += 1
            subs.append(line[i + 2 : j - 1])
            out.append("$__SUBST__")
            i = j
            continue
        if not in_single and ch == "`":
            j = line.find("`", i + 1)
            if j == -1:
                j = len(line)
            subs.append(line[i + 1 : j])
            out.append("$__SUBST__")
            i = j + 1
            continue
        out.append(ch)
        i += 1
    return "".join(out), subs


def _tokenise(line: str) -> list[str]:
    try:
        lex = shlex.shlex(line, posix=True, punctuation_chars=";&|")
        lex.whitespace_split = True
        lex.commenters = ""
        return list(lex)
    except ValueError:  # unbalanced quotes: fall back to whitespace
        return line.split()


def classify_line(
    line: str,
    cwd: str = "/root",
    home: str = "/root",
    is_known: IsKnown | None = None,
    _depth: int = 0,
) -> list[Decision]:
    """Classify every command in a raw input line (offline use)."""
    decisions: list[Decision] = []
    body, subs = _extract_substitutions(line.replace("\r", ""))
    if _depth < 4:
        for sub in subs:
            decisions.extend(classify_line(sub, cwd, home, is_known, _depth + 1))

    tokens: list[str] = []
    for physical in body.split("\n"):
        tokens.extend(_tokenise(physical))
        tokens.append(";")
    stage: list[str] = []
    for tok in tokens + [";"]:
        if tok in _CONTROL_OPERATORS:
            if stage:
                decisions.append(classify_argv(stage, cwd, home, is_known))
                # `bash -c "..."` / `sh -c "..."`: classify the inner script too
                inner = _unwrap(stage)
                if (_depth < 4 and inner and posixpath.basename(inner[0]) in {"bash", "sh", "dash", "zsh"}
                        and "-c" in inner):
                    idx = inner.index("-c")
                    if idx + 1 < len(inner):
                        decisions.extend(classify_line(inner[idx + 1], cwd, home, is_known, _depth + 1))
            stage = []
        else:
            stage.append(tok)
    return decisions


def strictest(decisions: Iterable[Decision]) -> Route:
    """The route for a whole line: PRIVILEGE beats ESCALATE beats DETERMINISTIC."""
    routes = {d.route for d in decisions}
    if Route.PRIVILEGE in routes:
        return Route.PRIVILEGE
    if Route.ESCALATE_CANDIDATE in routes:
        return Route.ESCALATE_CANDIDATE
    return Route.DETERMINISTIC
