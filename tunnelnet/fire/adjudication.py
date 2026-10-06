"""Pure confirmation-window adjudication for smoke reports.

A single detector report is never a fire.  Reports from one detector are
collected inside a rolling time window: a detector only reaches ``alarm``
when it reports smoke repeatedly within the window.  A ``restore`` report, or
the window expiring without further reports, withdraws a suspicion.

Every state transition is produced by :func:`adjudicate`, and the same
:class:`Decision` object is what gets persisted and what the audit trail
references, so the stored case and the audit entry can never disagree.
"""

from __future__ import annotations

import calendar
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class State(str, Enum):
    """Lifecycle of one smoke case."""

    NONE = "none"
    SUSPECTED = "suspected"
    ALARM = "alarm"


class Trigger(str, Enum):
    """What caused a transition, carried into the audit trail."""

    REPORT = "report"
    RESTORE = "restore"
    EXPIRE = "expire"
    CONFIRM = "confirm"
    RESET = "reset"
    LINKAGE_FAILED = "linkage_failed"


def parse_time(value: str) -> float:
    """Seconds-since-epoch for ISO stamps, or the fixture form ``t30``."""

    if value.startswith("t"):
        return float(value[1:] or 0.0)
    try:
        return float(value)
    except ValueError:
        return calendar.timegm(time.strptime(value, "%Y-%m-%dT%H:%M:%SZ"))


@dataclass(frozen=True)
class Policy:
    """The one confirmation policy every judgement must use.

    The window is time based, not count based: a second report only confirms
    when it arrives within ``window_seconds`` of the first.  ``required_reports``
    is how many in-window reports (including the first) escalate to an alarm.
    Expired suspicions are withdrawn automatically rather than handed to a
    human, so unattended cooking steam and dust clear themselves.
    """

    window_seconds: float = 30.0
    required_reports: int = 2

    def __post_init__(self) -> None:
        if self.window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        if self.required_reports < 2:
            raise ValueError("required_reports must be at least two")

    def as_dict(self) -> dict[str, object]:
        return {
            "window_seconds": self.window_seconds,
            "required_reports": self.required_reports,
            "expiry": "auto_withdraw",
        }


@dataclass(frozen=True)
class Case:
    """Accumulated reports for one detector."""

    detector_id: str
    state: State
    opened_at: str
    updated_at: str
    expires_at: str
    report_count: int
    event_keys: tuple[str, ...] = field(default_factory=tuple)

    def active(self) -> bool:
        return self.state is not State.NONE

    def as_dict(self) -> dict[str, object]:
        return {
            "detector_id": self.detector_id,
            "state": self.state.value,
            "opened_at": self.opened_at,
            "updated_at": self.updated_at,
            "expires_at": self.expires_at,
            "report_count": self.report_count,
            "event_keys": list(self.event_keys),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "Case":
        return cls(
            detector_id=str(payload.get("detector_id", "")),
            state=State(str(payload.get("state", "none"))),
            opened_at=str(payload.get("opened_at", "")),
            updated_at=str(payload.get("updated_at", "")),
            expires_at=str(payload.get("expires_at", "")),
            report_count=int(payload.get("report_count", 0)),
            event_keys=tuple(str(key) for key in payload.get("event_keys", [])),
        )


@dataclass(frozen=True)
class Decision:
    """Result of one adjudication; persisted and audited as one object."""

    detector_id: str
    trigger: Trigger
    before: State
    after: State
    at: str
    expires_at: str
    report_count: int
    case_id: str
    event_key: str
    window_seconds: float
    required_reports: int

    @property
    def id(self) -> str:
        """Stable durable identifier; the audit ref points at this value."""

        return decision_id_for(self.detector_id, self.at, self.event_key)

    def changed(self) -> bool:
        return self.before is not self.after

    def escalated(self) -> bool:
        return self.after is State.ALARM and self.before is not State.ALARM

    def withdrawn(self) -> bool:
        return self.after is State.NONE and self.before is not State.NONE

    def as_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "case_id": self.case_id,
            "event_key": self.event_key,
            "detector_id": self.detector_id,
            "trigger": self.trigger.value,
            "before": self.before.value,
            "after": self.after.value,
            "at": self.at,
            "expires_at": self.expires_at,
            "report_count": self.report_count,
            "window_seconds": self.window_seconds,
            "required_reports": self.required_reports,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "Decision":
        return cls(
            detector_id=str(payload.get("detector_id", "")),
            trigger=Trigger(str(payload.get("trigger", "report"))),
            before=State(str(payload.get("before", "none"))),
            after=State(str(payload.get("after", "none"))),
            at=str(payload.get("at", "")),
            expires_at=str(payload.get("expires_at", "")),
            report_count=int(payload.get("report_count", 0)),
            case_id=str(payload.get("case_id", "")),
            event_key=str(payload.get("event_key", "")),
            window_seconds=float(payload.get("window_seconds", 0.0)),
            required_reports=int(payload.get("required_reports", 0)),
        )


def case_id_for(detector_id: str, opened_at: str) -> str:
    return f"fire-case:{detector_id}:{opened_at}"


def decision_id_for(detector_id: str, at: str, event_key: str) -> str:
    return f"fire-decision:{detector_id}:{at}:{event_key}"


def _fresh(detector_id: str, at: str, expires_at: str, event_key: str) -> Case:
    return Case(
        detector_id=detector_id,
        state=State.SUSPECTED,
        opened_at=at,
        updated_at=at,
        expires_at=expires_at,
        report_count=1,
        event_keys=(event_key,),
    )


def _expiry(at: str, policy: Policy) -> str:
    stamp = parse_time(at)
    if at.startswith("t"):
        return f"t{stamp + policy.window_seconds:g}"
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(stamp + policy.window_seconds))


def _drop(case: Case, at: str) -> Case:
    return Case(
        detector_id=case.detector_id,
        state=State.NONE,
        opened_at="",
        updated_at=at,
        expires_at="",
        report_count=0,
        event_keys=(),
    )


def _decision(
    case: Case,
    before: State,
    trigger: Trigger,
    at: str,
    event_key: str,
    policy: Policy,
) -> Decision:
    return Decision(
        detector_id=case.detector_id,
        trigger=trigger,
        before=before,
        after=case.state,
        at=at,
        expires_at=case.expires_at,
        report_count=case.report_count,
        case_id=case_id_for(case.detector_id, case.opened_at) if case.active() else "",
        event_key=event_key,
        window_seconds=policy.window_seconds,
        required_reports=policy.required_reports,
    )


def adjudicate(
    detector_id: str,
    restored: bool,
    at: str,
    policy: Policy,
    current: Case | None = None,
    event_key: str = "",
) -> tuple[Case | None, Decision]:
    """Advance one detector through the confirmation window.

    Returns the new case (``None`` once withdrawn) and the :class:`Decision`
    that describes the transition.  A duplicate ``event_key`` replaying an
    already recorded report is a no-op decision.
    """

    existing = current if current is not None and current.active() else None

    if existing is not None and event_key and event_key in existing.event_keys:
        decision = _decision(existing, existing.state, Trigger.REPORT, at, event_key, policy)
        return existing, decision

    if restored:
        if existing is None:
            none_case = Case(detector_id, State.NONE, "", at, "", 0)
            return None, _decision(none_case, State.NONE, Trigger.RESTORE, at, event_key, policy)
        before = existing.state
        case = _drop(existing, at)
        return None, _decision(case, before, Trigger.RESTORE, at, event_key, policy)

    if existing is not None and parse_time(at) > parse_time(existing.expires_at):
        case = _drop(existing, at)
        _ = _decision(case, existing.state, Trigger.EXPIRE, at, event_key, policy)
        existing = None

    if existing is None:
        case = _fresh(detector_id, at, _expiry(at, policy), event_key)
        return case, _decision(case, State.NONE, Trigger.REPORT, at, event_key, policy)

    count = existing.report_count + 1
    trigger = Trigger.CONFIRM if count >= policy.required_reports else Trigger.REPORT
    state = State.ALARM if count >= policy.required_reports else State.SUSPECTED
    case = Case(
        detector_id=detector_id,
        state=state,
        opened_at=existing.opened_at,
        updated_at=at,
        expires_at=existing.expires_at,
        report_count=count,
        event_keys=(*existing.event_keys, event_key) if event_key else existing.event_keys,
    )
    return case, _decision(case, existing.state, trigger, at, event_key, policy)


def expire(case: Case, at: str, policy: Policy, event_key: str = "") -> tuple[Case | None, Decision]:
    """Auto-withdraw a suspicion whose window has elapsed.

    Only suspicions expire; an escalated alarm stays until an operator resets
    it, because a confirmed fire must never silently clear.
    """

    if case.state is State.ALARM or parse_time(at) <= parse_time(case.expires_at):
        return case, _decision(case, case.state, Trigger.EXPIRE, at, event_key, policy)
    dropped = _drop(case, at)
    return None, _decision(dropped, case.state, Trigger.EXPIRE, at, event_key, policy)


def reset(case: Case, at: str, policy: Policy, event_key: str = "") -> tuple[Case | None, Decision]:
    """Operator reset of an active case (typically after a real fire)."""

    if not case.active():
        return None, _decision(case, State.NONE, Trigger.RESET, at, event_key, policy)
    dropped = _drop(case, at)
    return None, _decision(dropped, case.state, Trigger.RESET, at, event_key, policy)
