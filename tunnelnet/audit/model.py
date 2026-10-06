"""Audit records written for every linkage event."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Record:
    """One linkage audit entry.

    ``ref`` points at the single object the judgement produced (a fire
    decision id), so the audit trail and the persisted adjudication reference
    the same source of truth.
    """

    id: str
    event: str
    at: str
    ref: str = ""

    def as_dict(self) -> dict[str, str]:
        return {"id": self.id, "event": self.event, "at": self.at, "ref": self.ref}
