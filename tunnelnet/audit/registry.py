"""Append only audit registry."""

from __future__ import annotations

import threading
import uuid

from .model import Record
from .report import AuditState
from .summary import count_by_event, summary


class AuditRegistry:
    """Keeps every linkage audit record in the order it was written."""

    def __init__(self) -> None:
        self._records: list[Record] = []
        self._lock = threading.RLock()

    def append(self, record: Record) -> Record:
        with self._lock:
            self._records.append(record)
        return record

    def append_by_ref(self, event: str, at: str, ref: str = "") -> Record:
        """Append an entry that references the object the event acted on."""

        return self.append(Record(id=uuid.uuid4().hex, event=event, at=at, ref=ref))

    def records(self) -> list[Record]:
        with self._lock:
            return list(self._records)

    def list(self) -> list[Record]:
        """Records sorted by identifier, for stable console output."""

        return sorted(self.records(), key=lambda record: record.id)

    def count(self) -> int:
        with self._lock:
            return len(self._records)

    def clear(self) -> int:
        with self._lock:
            self._records = []
        return 0

    def latest_id(self) -> str:
        with self._lock:
            if not self._records:
                return ""
            return self._records[-1].id

    def state(self) -> AuditState:
        return AuditState(entries=[record.as_dict() for record in self.list()], count=self.count())

    def count_by_event(self) -> dict[str, int]:
        return count_by_event(self.records())

    def summary(self) -> dict[str, int]:
        return summary(self.records())

    def describe(self) -> str:
        return f"audit records={self.count()}"
