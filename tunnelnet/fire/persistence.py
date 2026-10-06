"""Durable fire cases, decision history and immutable linkage records.

Three record kinds sit behind the file store:

``fire_case``      one document per detector holding the *live* case; it is
                   rewritten as the case advances and deleted on withdrawal.
``fire_decision``  one append-only document per adjudication, including
                   no-op replays and expiries; never rewritten or deleted.
``fire_linkage``   one append-only document per linkage that took full effect
                   (escalation or a withdrawal rollback); never rewritten.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from tunnelnet.store import Store

from .adjudication import Case, Decision
from .linkage import LinkageStep

CASE_KIND = "fire_case"
DECISION_KIND = "fire_decision"
LINKAGE_KIND = "fire_linkage"


def save_case(store: Store, case: Case) -> None:
    store.save(CASE_KIND, case.detector_id, case.as_dict())


def load_case(store: Store, detector_id: str) -> Case | None:
    payload = store.load(CASE_KIND, detector_id)
    if payload is None:
        return None
    case = Case.from_dict(payload)
    return case if case.active() else None


def delete_case(store: Store, detector_id: str) -> None:
    store.delete(CASE_KIND, detector_id)


def live_cases(store: Store) -> list[Case]:
    cases = []
    for detector_id in store.list(CASE_KIND):
        case = load_case(store, detector_id)
        if case is not None:
            cases.append(case)
    return sorted(cases, key=lambda case: case.detector_id)


def save_decision(store: Store, decision: Decision) -> str:
    record_id = decision.id
    if not store.exists(DECISION_KIND, record_id):
        store.save(DECISION_KIND, record_id, decision.as_dict())
    return record_id


def load_decisions(store: Store) -> list[Decision]:
    return [Decision.from_dict(store.load(DECISION_KIND, record_id) or {}) for record_id in store.list(DECISION_KIND)]


@dataclass(frozen=True)
class LinkageRecord:
    """Proof that a linkage took full effect. Immutable once written."""

    id: str
    decision_id: str
    kind: str
    at: str
    steps: list[LinkageStep]

    def as_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "decision_id": self.decision_id,
            "kind": self.kind,
            "at": self.at,
            "steps": [step.as_dict() for step in self.steps],
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "LinkageRecord":
        return cls(
            id=str(payload.get("id", "")),
            decision_id=str(payload.get("decision_id", "")),
            kind=str(payload.get("kind", "")),
            at=str(payload.get("at", "")),
            steps=[LinkageStep(str(item["action"]), str(item["target"])) for item in payload.get("steps", [])],
        )


def save_linkage(store: Store, record: LinkageRecord) -> None:
    """Write an effective linkage record, refusing to overwrite an existing one."""

    if store.exists(LINKAGE_KIND, record.id):
        raise ValueError(f"linkage record {record.id} is immutable")
    store.save(LINKAGE_KIND, record.id, record.as_dict())


def linkage_exists(store: Store, record_id: str) -> bool:
    return store.exists(LINKAGE_KIND, record_id)


def load_linkages(store: Store) -> list[LinkageRecord]:
    return [
        LinkageRecord.from_dict(store.load(LINKAGE_KIND, record_id) or {})
        for record_id in store.list(LINKAGE_KIND)
    ]
