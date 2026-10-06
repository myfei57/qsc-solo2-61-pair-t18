"""Fire detectors, dampers, incidents and immutable linkage records."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Detector:
    """One smoke detector bound to a zone."""

    id: str
    zone: str

    def as_dict(self) -> dict[str, str]:
        return {"id": self.id, "zone": self.zone}


@dataclass(frozen=True)
class DamperState:
    """Whether the fire damper of a zone is closed."""

    zone: str
    closed: bool

    def as_dict(self) -> dict[str, object]:
        return {"zone": self.zone, "closed": self.closed}


@dataclass(frozen=True)
class Observation:
    """One de-duplicated detector report that entered the confirmation policy.

    ``event_id`` is the upstream report identifier used for idempotency; a
    retransmitted event id is accepted with 200 semantics but never evaluated
    twice.  ``restored`` distinguishes a smoke-cleared report from an alarm.
    """

    id: str
    event_id: str
    point_id: str
    zone: str
    at: float
    restored: bool
    decision_id: str

    def as_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "event_id": self.event_id,
            "point_id": self.point_id,
            "zone": self.zone,
            "at": self.at,
            "restored": self.restored,
            "decision_id": self.decision_id,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, object]) -> "Observation":
        return cls(
            id=str(payload.get("id", "")),
            event_id=str(payload.get("event_id", "")),
            point_id=str(payload.get("point_id", "")),
            zone=str(payload.get("zone", "")),
            at=float(payload.get("at", 0.0)),
            restored=bool(payload.get("restored", False)),
            decision_id=str(payload.get("decision_id", "")),
        )


@dataclass(frozen=True)
class Incident:
    """The durable lifecycle of one point's suspected/confirmed episode."""

    id: str
    point_id: str
    zone: str
    opened_at: float
    state: str
    updated_at: float
    window_started_at: float | None
    last_report_at: float | None
    distinct_reports: int = 0
    confirmed_at: float | None = None
    closed_at: float | None = None
    close_reason: str = ""
    plan_id: str = ""
    escalated: bool = False
    suspected_occurrences: int = 0
    observation_ids: list[str] = field(default_factory=list)
    decision_ids: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "point_id": self.point_id,
            "zone": self.zone,
            "opened_at": self.opened_at,
            "state": self.state,
            "updated_at": self.updated_at,
            "window_started_at": self.window_started_at,
            "last_report_at": self.last_report_at,
            "distinct_reports": self.distinct_reports,
            "confirmed_at": self.confirmed_at,
            "closed_at": self.closed_at,
            "close_reason": self.close_reason,
            "plan_id": self.plan_id,
            "escalated": self.escalated,
            "suspected_occurrences": self.suspected_occurrences,
            "observation_ids": list(self.observation_ids),
            "decision_ids": list(self.decision_ids),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, object]) -> "Incident":
        return cls(
            id=str(payload.get("id", "")),
            point_id=str(payload.get("point_id", "")),
            zone=str(payload.get("zone", "")),
            opened_at=float(payload.get("opened_at", 0.0)),
            state=str(payload.get("state", "normal")),
            updated_at=float(payload.get("updated_at", 0.0)),
            window_started_at=_optional_float(payload.get("window_started_at")),
            last_report_at=_optional_float(payload.get("last_report_at")),
            distinct_reports=int(payload.get("distinct_reports", 0)),
            confirmed_at=_optional_float(payload.get("confirmed_at")),
            closed_at=_optional_float(payload.get("closed_at")),
            close_reason=str(payload.get("close_reason", "")),
            plan_id=str(payload.get("plan_id", "")),
            escalated=bool(payload.get("escalated", False)),
            suspected_occurrences=int(payload.get("suspected_occurrences", 0)),
            observation_ids=[str(item) for item in payload.get("observation_ids", [])],  # type: ignore[arg-type]
            decision_ids=[str(item) for item in payload.get("decision_ids", [])],  # type: ignore[arg-type]
        )


def _optional_float(value: object) -> float | None:
    if value is None:
        return None
    return float(value)  # type: ignore[arg-type]


@dataclass(frozen=True)
class LinkRecord:
    """Append-only, immutable record of one physical linkage effect.

    A record that became effective (``engaged``) is never rewritten.  Rollback
    and disengagement append further records (``compensated``/``disengaged``)
    rather than editing the original.  ``order`` is the monotonic append
    position within a plan, so effects stay ordered even when several share a
    timestamp.
    """

    id: str
    plan_id: str
    incident_id: str
    seq: int
    step_key: str
    op: str
    target: str
    reverse_op: str
    status: str
    at: float
    detail: str = ""
    order: int = 0

    def as_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "plan_id": self.plan_id,
            "incident_id": self.incident_id,
            "seq": self.seq,
            "step_key": self.step_key,
            "op": self.op,
            "target": self.target,
            "reverse_op": self.reverse_op,
            "status": self.status,
            "at": self.at,
            "detail": self.detail,
            "order": self.order,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, object]) -> "LinkRecord":
        return cls(
            id=str(payload.get("id", "")),
            plan_id=str(payload.get("plan_id", "")),
            incident_id=str(payload.get("incident_id", "")),
            seq=int(payload.get("seq", 0)),
            step_key=str(payload.get("step_key", "")),
            op=str(payload.get("op", "")),
            target=str(payload.get("target", "")),
            reverse_op=str(payload.get("reverse_op", "")),
            status=str(payload.get("status", "")),
            at=float(payload.get("at", 0.0)),
            detail=str(payload.get("detail", "")),
            order=int(payload.get("order", 0)),
        )
