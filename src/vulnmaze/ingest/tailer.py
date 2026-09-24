"""Follow cowrie.json across restarts and daily rotation.

Cowrie's `rotating` log type renames cowrie.json to cowrie.json.YYYY-MM-DD at
midnight and opens a fresh file. We track (inode, offset): if the inode at
the path changes, we finish the old file through the handle we still hold,
then switch. Only complete lines (ending in '\\n') are returned, so a line
Cowrie is half-way through writing is picked up on the next poll.
"""

from __future__ import annotations

import glob
import os
from dataclasses import dataclass


@dataclass
class Checkpoint:
    inode: int
    offset: int


class FileTailer:
    def __init__(self, path: str, checkpoint: Checkpoint | None = None, max_bytes: int = 4 << 20):
        self.path = path
        self.max_bytes = max_bytes
        self._fh = None
        self._inode: int | None = None
        self._resume = checkpoint

    def _open_rotated_resume(self) -> bool:
        """After a restart across midnight the checkpoint may point at a file
        that has since been renamed to cowrie.json.<date>. Drain it first."""
        cp = self._resume
        if cp is None:
            return False
        try:
            if os.stat(self.path).st_ino == cp.inode:
                return False
        except FileNotFoundError:
            pass
        for candidate in glob.glob(self.path + ".*"):
            try:
                if os.stat(candidate).st_ino == cp.inode:
                    fh = open(candidate, "rb")  # noqa: SIM115
                    fh.seek(cp.offset)
                    self._fh, self._inode = fh, cp.inode
                    self._resume = None
                    return True
            except OSError:
                continue
        return False

    def _open_current(self) -> bool:
        try:
            fh = open(self.path, "rb")  # noqa: SIM115 (kept open while tailing)
        except FileNotFoundError:
            return False
        inode = os.fstat(fh.fileno()).st_ino
        offset = 0
        if self._resume and self._resume.inode == inode:
            offset = min(self._resume.offset, os.fstat(fh.fileno()).st_size)
        self._resume = None
        fh.seek(offset)
        if self._fh:
            self._fh.close()
        self._fh, self._inode = fh, inode
        return True

    def _rotated(self) -> bool:
        try:
            return os.stat(self.path).st_ino != self._inode
        except FileNotFoundError:
            return False

    def poll(self) -> list[str]:
        """Return complete new lines (possibly empty)."""
        if self._fh is None and not self._open_rotated_resume() and not self._open_current():
            return []
        lines = self._read_complete()
        if not lines and self._rotated():
            # Old file is drained (we just read to EOF); move to the new one.
            self._open_current()
            lines = self._read_complete()
        return lines

    def _read_complete(self) -> list[str]:
        assert self._fh is not None
        start = self._fh.tell()
        chunk = self._fh.read(self.max_bytes)
        if not chunk:
            return []
        end = chunk.rfind(b"\n")
        if end == -1:
            self._fh.seek(start)  # no complete line yet
            return []
        self._fh.seek(start + end + 1)
        return chunk[: end + 1].decode("utf-8", "replace").splitlines()

    @property
    def checkpoint(self) -> Checkpoint | None:
        if self._fh is None or self._inode is None:
            return None
        return Checkpoint(self._inode, self._fh.tell())
