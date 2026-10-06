"""Mark set used to raise a fire alarm only once per event key."""

from __future__ import annotations

import threading


class MarkSet:
    """Remembers event keys that have already produced an alarm."""

    def __init__(self) -> None:
        self._marks: set[str] = set()
        self._lock = threading.RLock()

    def record(self, key: str) -> bool:
        """Return ``True`` the first time a key is seen."""

        with self._lock:
            if key in self._marks:
                return False
            self._marks.add(key)
            return True

    def has(self, key: str) -> bool:
        with self._lock:
            return key in self._marks

    def clear(self, key: str = "") -> None:
        """Forget one key, or every key when called without one."""

        with self._lock:
            if key:
                self._marks.discard(key)
            else:
                self._marks = set()

    def count(self) -> int:
        with self._lock:
            return len(self._marks)

    def describe(self) -> str:
        return f"marks={len(self._marks)}"
