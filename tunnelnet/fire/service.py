"""Fire alarm service with a confirmation window.

One smoke report is never a fire.  The first report from a detector opens a
*suspected* case inside a rolling time window; repeated in-window reports
escalate it to an *alarm*, while a restore or window expiry withdraws the
suspicion.  The single :class:`~tunnelnet.fire.adjudication.Decision`
produced by the pure adjudicator is what gets persisted, audited and, on
escalation, drives the physical linkage.

Ordering rules:

* confirmation precedes linkage — the decision and live case are durable
  before any physical output moves;
* an escalation linkage that partially fails is compensated in reverse and
  the case stays *suspected* so the report can be retried;
* withdrawal reverses an effective linkage first and only then removes the
  live case and writes the withdrawn decision;
* repeated reports carrying the same event key are idempotent;
* linkage records that took effect are append-only and never rewritten.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from typing import Protocol

from tunnelnet.store import ExecutionMark, Store, load_mark, save_mark

from . import persistence
from .adjudication import (
    Case,
    Decision,
    Policy,
    State,
    Trigger,
    adjudicate,
    case_id_for,
    expire,
    parse_time,
    reset,
)
from .linkage import Linkage
from .model import Detector
from .report import FireReport
from .zone import activation_order

FIRE_EVENT_PREFIX = "fire-event:"


class Deduper(Protocol):
    """Fast in-memory companion to the durable event marks."""

    def record(self, key: str) -> bool:  # pragma: no cover - structural
        ...

    def has(self, key: str) -> bool:  # pragma: no cover - structural
        ...


def utc_now() -> str:
    """Current UTC time in the compact form stored on every decision."""

    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class AuditSink(Protocol):
    """Append-only sink that records the decision behind each audit entry."""

    def append_by_ref(self, event: str, at: str, ref: str) -> object:  # pragma: no cover - structural
        ...


class FireService:
    """Confirmation-window alarms, durable cases and compensated linkage."""

    def __init__(
        self,
        store: Store,
        linkage: Linkage,
        zones: tuple[str, ...],
        audit: AuditSink | None = None,
        policy: Policy | None = None,
        clock: Callable[[], str] = utc_now,
        deduper: Deduper | None = None,
    ) -> None:
        self._store = store
        self._linkage = linkage
        self._zones = tuple(zones)
        self._audit = audit
        self._policy = policy or Policy()
        self._clock = clock
        self._deduper = deduper
        self._lock = threading.RLock()
        self._detectors: dict[str, Detector] = {}
        self._alarms: list[str] = []
        self._case_ids: dict[str, str] = {}

    @classmethod
    def with_outputs(
        cls,
        store: Store,
        dampers: object,
        vent: object,
        suppressor: object,
        zones: tuple[str, ...],
        audit: AuditSink | None = None,
        policy: Policy | None = None,
        clock: Callable[[], str] = utc_now,
        deduper: Deduper | None = None,
    ) -> "FireService":
        """Wire the service over the physical output collaborators."""

        linkage = Linkage(dampers, vent, suppressor, zones)
        return cls(store, linkage, zones, audit, policy, clock, deduper)

    @property
    def policy(self) -> Policy:
        return self._policy

    def zones(self) -> list[str]:
        return list(self._zones)

    def zone_count(self) -> int:
        return len(self._zones)

    def add_detector(self, detector: Detector) -> Detector:
        with self._lock:
            self._detectors[detector.id] = detector
            return detector

    def detectors(self) -> list[Detector]:
        with self._lock:
            return [self._detectors[key] for key in sorted(self._detectors)]

    def detector_count(self) -> int:
        with self._lock:
            return len(self._detectors)

    def zone_of_detector(self, detector_id: str) -> str:
        with self._lock:
            detector = self._detectors.get(detector_id)
            return "" if detector is None else detector.zone

    # -- confirmation window ------------------------------------------------

    def report_smoke(
        self,
        detector_id: str,
        at: str | None = None,
        event_key: str = "",
        restored: bool = False,
    ) -> Decision:
        """Feed one detector report through the confirmation window."""

        stamp = at if at is not None else self._clock()
        key = event_key or f"{detector_id}:{stamp}"
        mark_key = FIRE_EVENT_PREFIX + key
        with self._lock:
            current = persistence.load_case(self._store, detector_id)
            if current is not None and key in current.event_keys:
                return self._replay(detector_id, current, stamp, key)
            if self._deduper is not None and self._deduper.has(mark_key):
                return self._replay(detector_id, current, stamp, key)
            if load_mark(self._store, mark_key) is not None:
                return self._replay(detector_id, current, stamp, key)

            case, decision = adjudicate(
                detector_id, restored, stamp, self._policy, current=current, event_key=key
            )
            try:
                self._handle_decision(case, decision)
            except Exception:
                # Linkage failed and was rolled back; leave the key unmarked
                # so the same event can be replayed for a retry.
                if self._deduper is not None:
                    self._deduper.clear(mark_key)
                raise
            save_mark(self._store, ExecutionMark(key=mark_key, executed_at=stamp))
            if self._deduper is not None:
                self._deduper.record(mark_key)
            return decision

    def _replay(self, detector_id: str, current: Case | None, stamp: str, key: str) -> Decision:
        state = current.state if current is not None else State.NONE
        return Decision(
            detector_id=detector_id,
            trigger=Trigger.REPORT,
            before=state,
            after=state,
            at=stamp,
            expires_at=current.expires_at if current else "",
            report_count=current.report_count if current else 0,
            case_id=case_id_for(current.detector_id, current.opened_at) if current else "",
            event_key=key,
            window_seconds=self._policy.window_seconds,
            required_reports=self._policy.required_reports,
        )

    def restore(self, detector_id: str, at: str | None = None, event_key: str = "") -> Decision:
        """Detector reports its chamber clear; withdraws a suspicion."""

        return self.report_smoke(detector_id, at=at, event_key=event_key, restored=True)

    def sweep(self, at: str | None = None) -> list[Decision]:
        """Auto-withdraw every suspicion whose window has elapsed."""

        stamp = at if at is not None else self._clock()
        decisions: list[Decision] = []
        with self._lock:
            for case in persistence.live_cases(self._store):
                if case.state is not State.SUSPECTED:
                    continue
                if parse_time(stamp) <= parse_time(case.expires_at):
                    continue
                withdrawn, decision = expire(case, stamp, self._policy)
                self._handle_decision(withdrawn, decision)
                decisions.append(decision)
        return decisions

    def reset_alarm(self, detector_id: str, at: str | None = None, event_key: str = "") -> Decision:
        """Operator reset: reverse linkage and close a suspected/alarm case."""

        stamp = at if at is not None else self._clock()
        with self._lock:
            current = persistence.load_case(self._store, detector_id)
            if current is None:
                return Decision(
                    detector_id=detector_id,
                    trigger=Trigger.RESET,
                    before=State.NONE,
                    after=State.NONE,
                    at=stamp,
                    expires_at="",
                    report_count=0,
                    case_id="",
                    event_key=event_key,
                    window_seconds=self._policy.window_seconds,
                    required_reports=self._policy.required_reports,
                )
            case, decision = reset(
                current, stamp, self._policy, event_key=event_key or f"reset:{detector_id}:{stamp}"
            )
            self._handle_decision(case, decision)
            return decision

    def _handle_decision(self, case: Case | None, decision: Decision) -> None:
        """Persist the decision, then move linkage, then update the live case."""

        persistence.save_decision(self._store, decision)

        if case is not None and case.active():
            self._case_ids[case.detector_id] = case_id_for(case.detector_id, case.opened_at)

        if decision.escalated():
            self._escalate(case, decision)
        elif decision.withdrawn():
            self._withdraw(decision)

        if case is None:
            persistence.delete_case(self._store, decision.detector_id)
            self._case_ids.pop(decision.detector_id, None)
        else:
            persistence.save_case(self._store, case)
            if case.active():
                self._case_ids[case.detector_id] = decision.case_id

        self._record_audit(decision)

    def _escalate(self, case: Case, decision: Decision) -> None:
        """Drive linkage after the decision is durable; roll back on failure."""

        zone = self.zone_of_detector(decision.detector_id)
        try:
            steps = self._linkage.apply(zone)
        except Exception:
            # The confirmation stands logically, but no partial physical
            # linkage may remain: revert outputs and keep it retryable.
            rolled_case = Case(
                detector_id=case.detector_id,
                state=State.SUSPECTED,
                opened_at=case.opened_at,
                updated_at=decision.at,
                expires_at=case.expires_at,
                report_count=case.report_count,
                # the confirming event key is deliberately not kept so the
                # same report can be replayed once linkage is healthy again
                event_keys=tuple(key for key in case.event_keys if key != decision.event_key),
            )
            persistence.save_case(self._store, rolled_case)
            rollback_decision = Decision(
                detector_id=decision.detector_id,
                trigger=Trigger.LINKAGE_FAILED,
                before=State.ALARM,
                after=State.SUSPECTED,
                at=decision.at,
                expires_at=case.expires_at,
                report_count=case.report_count,
                case_id=decision.case_id,
                event_key=decision.event_key,
                window_seconds=self._policy.window_seconds,
                required_reports=self._policy.required_reports,
            )
            persistence.save_decision(self._store, rollback_decision)
            self._record_audit(rollback_decision)
            raise
        record = persistence.LinkageRecord(
            id=f"link:{decision.case_id}",
            decision_id=decision.case_id,
            kind="escalate",
            at=decision.at,
            steps=steps,
        )
        persistence.save_linkage(self._store, record)
        self._alarms.append(decision.case_id)

    def _effective_linkage(self, case_id: str) -> persistence.LinkageRecord | None:
        record_id = f"link:{case_id}"
        for record in persistence.load_linkages(self._store):
            if record.id == record_id:
                return record
        return None

    def _withdraw(self, decision: Decision) -> None:
        """Reverse an effective linkage before the live case is removed."""

        case_id = decision.case_id or self._case_ids.get(decision.detector_id, "")
        effective = self._effective_linkage(case_id) if case_id else None
        steps = self._linkage.rollback(list(effective.steps)) if effective is not None else []
        withdrawn_record = persistence.LinkageRecord(
            id=f"unlink:{case_id}:{decision.at}" if case_id else f"unlink:{decision.detector_id}:{decision.at}",
            decision_id=case_id,
            kind=decision.trigger.value,
            at=decision.at,
            steps=steps,
        )
        persistence.save_linkage(self._store, withdrawn_record)
        if case_id in self._alarms:
            self._alarms.remove(case_id)

    def _record_audit(self, decision: Decision) -> None:
        if self._audit is None:
            return
        if decision.trigger is Trigger.LINKAGE_FAILED:
            event = "fire_linkage_rolled_back"
        elif decision.trigger is Trigger.EXPIRE:
            event = "fire_withdrawn_expired"
        elif decision.trigger is Trigger.RESTORE:
            event = "fire_withdrawn_restore"
        elif decision.trigger is Trigger.RESET:
            event = "fire_withdrawn_reset"
        elif decision.escalated():
            event = "fire_alarm_confirmed"
        else:
            event = "fire_suspected"
        self._audit.append_by_ref(event, decision.at, decision.id)

    # -- live views ---------------------------------------------------------

    def cases(self) -> list[Case]:
        with self._lock:
            return persistence.live_cases(self._store)

    def suspected(self) -> list[Case]:
        return [case for case in self.cases() if case.state is State.SUSPECTED]

    def alarms(self) -> list[str]:
        with self._lock:
            return list(self._alarms)

    def alarm_count(self) -> int:
        with self._lock:
            return len(self._alarms)

    def distinct_alarms(self) -> int:
        with self._lock:
            return len(set(self._alarms))

    def clear_alarms(self) -> int:
        """Operator clear: reset every live case and reverse its linkage."""

        with self._lock:
            detector_ids = [case.detector_id for case in self.cases()]
        for detector_id in detector_ids:
            self.reset_alarm(detector_id)
        return 0

    def decisions(self) -> list[Decision]:
        with self._lock:
            return persistence.load_decisions(self._store)

    def linkage_records(self) -> list[persistence.LinkageRecord]:
        with self._lock:
            return persistence.load_linkages(self._store)

    # -- legacy linkage helpers retained for the console --------------------

    def detect(self, detector_id: str) -> bool:
        """Backwards compatible single report; returns whether it alarmed."""

        decision = self.report_smoke(detector_id)
        return decision.after is State.ALARM

    def handle_smoke(self, zone: str) -> bool:
        """Apply the full linkage for one zone without a case (legacy)."""

        self._linkage.apply(zone)
        return True

    def activate_zones(self, source: str) -> list[str]:
        """Suppress the source zone first and then the adjacent zones."""

        order = activation_order(self._zones, source)
        for zone in order:
            self._linkage._suppressor.activate(zone)
        return order

    def raise_alarm(self, event_key: str) -> bool:
        """Legacy de-duplicated alarm mark, retained for older callers."""

        mark_key = FIRE_EVENT_PREFIX + event_key
        with self._lock:
            if self._deduper is not None and not self._deduper.record(mark_key):
                return False
            if load_mark(self._store, mark_key) is not None:
                return False
            save_mark(self._store, ExecutionMark(key=mark_key, executed_at=self._clock()))
            self._alarms.append(event_key)
            return True

    def report(self) -> FireReport:
        return FireReport(
            detector_count=self.detector_count(),
            alarm_count=self.alarm_count(),
            zone_count=self.zone_count(),
            alarms=self.alarms(),
            suspected_count=len(self.suspected()),
            policy=self._policy.as_dict(),
        )

    def describe(self) -> str:
        return (
            f"fire detectors={self.detector_count()} zones={self.zone_count()} "
            f"suspected={len(self.suspected())} alarms={self.alarm_count()}"
        )
