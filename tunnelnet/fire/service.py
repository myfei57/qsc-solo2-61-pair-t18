"""Fire service with a confirmation window before any linkage engages.

A single detector report is only ever *suspected*.  The same point must keep
reporting inside a time based confirmation window (see :mod:`fire.policy` for
the fixed trade-offs) before the incident becomes a confirmed fire and linkage
engages.  A restore report inside the window withdraws the suspicion; a window
that runs out expires on its own.

Ordering guarantees:

* the policy decision and observation are persisted before any device moves;
* linkage steps run in order via :class:`fire.linkage.LinkageExecutor`, with
  reverse-order compensation when a step fails;
* restore releases linkage in the same order reversed.

Idempotency: an upstream ``event_id`` is de-duplicated durably before policy
evaluation, so retried reports never count twice and never drive linkage twice.
"""

from __future__ import annotations

import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Protocol

from tunnelnet.audit import Record
from tunnelnet.store import Store

from . import records
from .linkage import LinkageExecutor, LinkageGateway, PlanResult
from .model import DamperState, Detector, Incident, Observation
from .policy import Decision, PointView, PolicyConfig, State, Verdict, evaluate_expiry, evaluate_report
from .report import FireReport
from .zone import activation_order


def utc_clock() -> float:
    return time.time()


def new_id() -> str:
    return uuid.uuid4().hex


def _stamp(at: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(at))


class DamperStore(Protocol):
    """Persists the closed state of a zone damper."""

    def save(self, kind: str, record_id: str, value: object) -> None:  # pragma: no cover - structural
        ...


class VentStopper(Protocol):
    """Stops the ventilation bank when smoke is confirmed."""

    def stop(self) -> bool:  # pragma: no cover - structural
        ...


class Suppressor(Protocol):
    """Activates suppression for one zone."""

    def activate(self, zone: str) -> object:  # pragma: no cover - structural
        ...


class Deduper(Protocol):
    """Records an event key, reporting whether it was new."""

    def record(self, key: str) -> bool:  # pragma: no cover - structural
        ...


class AuditSink(Protocol):
    """Append-only destination for audit records referencing a decision."""

    def append(self, record: Record) -> Record:  # pragma: no cover - structural
        ...


@dataclass(frozen=True)
class ReportOutcome:
    """What happened to one incoming detector report."""

    accepted: bool
    duplicate: bool
    point_id: str
    incident_id: str
    decisions: tuple[Decision, ...]
    linkage: PlanResult | None
    escalated: bool

    @property
    def state(self) -> str:
        if not self.decisions:
            return ""
        return self.decisions[-1].view.state.value

    def as_dict(self) -> dict[str, object]:
        return {
            "accepted": self.accepted,
            "duplicate": self.duplicate,
            "point_id": self.point_id,
            "incident_id": self.incident_id,
            "state": self.state,
            "decisions": [item.decision_id for item in self.decisions],
            "verdicts": [item.verdict.value for item in self.decisions],
            "linkage": None if self.linkage is None else self.linkage.as_dict(),
            "escalated": self.escalated,
        }


class FireService:
    """Detectors, confirmation windows, durable incidents and linkage."""

    def __init__(
        self,
        dampers: DamperStore | Store,
        vent: VentStopper,
        suppressor: Suppressor,
        deduper: Deduper,
        zones: tuple[str, ...],
        store: Store | None = None,
        gateway: LinkageGateway | None = None,
        audit: AuditSink | None = None,
        config: PolicyConfig | None = None,
        clock: Callable[[], float] = utc_clock,
        id_factory: Callable[[], str] = new_id,
    ) -> None:
        self._dampers = dampers
        self._vent = vent
        self._suppressor = suppressor
        self._deduper = deduper
        self._zones = tuple(zones)
        self._store: Store | None = store if store is not None else (dampers if isinstance(dampers, Store) else None)
        self._audit = audit
        self._config = config or PolicyConfig()
        self._config.validate()
        self._clock = clock
        self._ids = id_factory
        self._alarms: list[str] = []
        self._detectors: dict[str, Detector] = {}
        self._lock = threading.RLock()
        self._escalations: dict[str, int] = {}
        adapter = gateway or DefaultGateway(dampers, vent, suppressor)  # type: ignore[arg-type]
        self._executor = LinkageExecutor(self._store or _NullStore(), adapter, clock, id_factory)

    # ------------------------------------------------------------------ setup

    def zones(self) -> list[str]:
        return list(self._zones)

    def zone_count(self) -> int:
        return len(self._zones)

    def policy_config(self) -> PolicyConfig:
        return self._config

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

    # ------------------------------------------------------ confirmation flow

    def detect(self, detector_id: str, event_id: str = "", restored: bool = False) -> ReportOutcome:
        """Feed one detector report through the confirmation window."""

        with self._lock:
            zone = self.zone_of_detector(detector_id)
            if not zone:
                raise ValueError(f"detector {detector_id} not found")
            event_id = event_id or f"{detector_id}:{self._clock()}"
            return self._report(detector_id, zone, event_id, restored)

    def report_smoke(self, detector_id: str, event_id: str = "") -> ReportOutcome:
        """Alarm report from one detector point."""

        return self.detect(detector_id, event_id, restored=False)

    def report_restore(self, detector_id: str, event_id: str = "") -> ReportOutcome:
        """Smoke-cleared report from one detector point."""

        return self.detect(detector_id, event_id, restored=True)

    def sweep_expired(self, at: float | None = None) -> list[Decision]:
        """Auto-withdraw suspected points whose confirmation window lapsed."""

        if self._store is None:
            return []
        now = self._clock() if at is None else at
        results: list[Decision] = []
        with self._lock:
            for incident in records.active_incidents(self._store):
                if incident.state != "suspected":
                    continue
                decision = evaluate_expiry(
                    f"dec-{self._ids()}",
                    incident.point_id,
                    self._view_of(incident),
                    now,
                    self._config,
                )
                if decision is None:
                    continue
                self._save_observation(incident, decision, f"sweep:{decision.decision_id}")
                records.save_decision(self._store, decision)
                self._terminate(incident, decision.verdict.value, decision.at)
                self._audit_decision(decision)
                results.append(decision)
        return results

    def recover(self) -> list[PlanResult]:
        """Resume linkage plans interrupted by a crash; call once on boot."""

        if self._store is None:
            return []
        return self._executor.recover_pending()

    def _report(self, point_id: str, zone: str, event_id: str, restored: bool) -> ReportOutcome:
        at = self._clock()

        # Idempotency: a retransmitted event id is acknowledged, never replayed.
        if self._store is not None and records.event_seen(self._store, event_id):
            marker = self._store.load(records.EVENT_KIND, records.safe_id(event_id)) or {}
            return ReportOutcome(
                accepted=False,
                duplicate=True,
                point_id=point_id,
                incident_id="",
                decisions=(),
                linkage=None,
                escalated=False,
            )

        incident = self._active_incident(point_id)
        view = PointView.normal() if incident is None else self._view_of(incident)
        decisions = evaluate_report(
            f"dec-{self._ids()}",
            point_id,
            f"inc-{self._ids()}",
            f"obs-{self._ids()}",
            view,
            at,
            restored,
            self._config,
        )
        primary = decisions[-1]
        observation_id = primary.evidence[0] if primary.evidence else f"obs-{self._ids()}"

        # Durable de-dup mark is written first, before the policy can run twice.
        if self._store is not None:
            records.mark_event(self._store, event_id, at, observation_id)

        escalated = False
        linkage: PlanResult | None = None

        if self._store is not None:
            for decision in decisions:
                incident, just_opened = self._materialise(incident, point_id, zone, decision)
                self._save_observation(incident, decision, event_id)
                records.save_decision(self._store, decision)
                self._audit_decision(decision)
                if just_opened:
                    incident = self._bump_chatter(incident)
                    escalated = escalated or incident.escalated
                if decision.terminal:
                    self._terminate(incident, decision.verdict.value, decision.at)
                    incident = None

            # Decision is durable before any physical step runs.
            if primary.verdict is Verdict.FIRE_CONFIRMED:
                assert incident is not None
                linkage = self._executor.engage(incident.id, zone, self._zones)
                self._record_linkage_state(incident, linkage, at)
                self._audit_linkage(linkage)
                if linkage.status == "engaged":
                    self._alarms.append(incident.id)
            elif primary.verdict is Verdict.FIRE_RESTORED:
                prior = self._incident_by_point(point_id)
                if prior is not None and prior.plan_id:
                    linkage = self._executor.release(prior.id)
                    self._audit_linkage(linkage)

        incident_id = incident.id if incident is not None else (
            self._incident_id_for(point_id, decisions)
        )
        return ReportOutcome(
            accepted=True,
            duplicate=False,
            point_id=point_id,
            incident_id=incident_id,
            decisions=tuple(decisions),
            linkage=linkage,
            escalated=escalated,
        )

    # ------------------------------------------------------------ persistence

    def _materialise(
        self,
        incident: Incident | None,
        point_id: str,
        zone: str,
        decision: Decision,
    ) -> tuple[Incident, bool]:
        """Apply one decision to the durable incident; returns (incident, opened)."""

        assert self._store is not None
        opened = False
        if incident is None:
            if decision.verdict in {Verdict.SUSPECT_OPENED}:
                incident = Incident(
                    id=decision.view.incident_id or f"inc-{self._ids()}",
                    point_id=point_id,
                    zone=zone,
                    opened_at=decision.at,
                    state="suspected",
                    updated_at=decision.at,
                    window_started_at=decision.at,
                    last_report_at=decision.at,
                    distinct_reports=0,
                    suspected_occurrences=self._escalations.get(point_id, 0),
                )
                opened = True
            elif decision.verdict is Verdict.NO_CHANGE:
                # Restore while normal: nothing to attach to.
                incident = Incident(
                    id=f"inc-{self._ids()}",
                    point_id=point_id,
                    zone=zone,
                    opened_at=decision.at,
                    state="normal",
                    updated_at=decision.at,
                    window_started_at=None,
                    last_report_at=None,
                )
            else:
                incident = Incident(
                    id=f"inc-{self._ids()}",
                    point_id=point_id,
                    zone=zone,
                    opened_at=decision.at,
                    state="normal",
                    updated_at=decision.at,
                    window_started_at=None,
                    last_report_at=None,
                )

        data = incident.as_dict()
        data["updated_at"] = decision.at
        data["decision_ids"] = [*incident.decision_ids, decision.decision_id]
        obs = decision.evidence[0] if decision.evidence else f"obs-{decision.decision_id}"
        data["observation_ids"] = [*incident.observation_ids, obs]

        view = decision.view
        if decision.verdict is Verdict.FIRE_CONFIRMED:
            data["state"] = "fire"
            data["confirmed_at"] = decision.at
            data["window_started_at"] = view.window_started_at
            data["last_report_at"] = view.last_report_at
            data["distinct_reports"] = view.distinct_reports
        elif decision.verdict in {Verdict.SUSPECT_OPENED, Verdict.SUSPECT_KEPT}:
            data["state"] = "suspected"
            data["window_started_at"] = view.window_started_at
            data["last_report_at"] = view.last_report_at
            data["distinct_reports"] = view.distinct_reports
        elif decision.verdict is Verdict.NO_CHANGE:
            pass

        updated = Incident.from_dict(data)
        records.save_incident(self._store, updated)
        return updated, opened

    def _terminate(self, incident: Incident, reason: str, at: float) -> None:
        assert self._store is not None
        closed = replace(
            incident,
            state="closed",
            updated_at=at,
            closed_at=at,
            close_reason=reason,
            window_started_at=None,
            last_report_at=None,
            distinct_reports=0,
        )
        records.save_incident(self._store, closed)
        # A suspected episode ending quietly counts toward chatter escalation.
        if reason in {Verdict.SUSPECT_EXPIRED.value, Verdict.SUSPECT_CLEARED.value}:
            self._escalations[incident.point_id] = self._escalations.get(incident.point_id, 0) + 1

    def _bump_chatter(self, incident: Incident) -> Incident:
        """Flag a point that keeps opening suspected windows for manual review.

        Auto-withdrawal is safe for one kitchen-steam blip, but a detector that
        produces ``escalate_after`` suspected episodes is itself suspicious:
        flag the freshly opened incident without turning that incident into a
        fire.  This is the deliberate real-fire backstop for the chosen policy.
        """

        assert self._store is not None
        total = self._escalations.get(incident.point_id, 0)
        if not incident.escalated and total + 1 >= self._config.escalate_after:
            flagged = replace(
                incident,
                escalated=True,
                suspected_occurrences=total + 1,
            )
            records.save_incident(self._store, flagged)
            return flagged
        return replace(incident, suspected_occurrences=total)

    def _record_linkage_state(self, incident: Incident, linkage: PlanResult, at: float) -> None:
        assert self._store is not None
        state = "fire" if linkage.ok else "linkage_failed"
        records.save_incident(
            self._store,
            replace(
                incident,
                state=state,
                plan_id=linkage.plan_id,
                updated_at=at,
            ),
        )

    def _save_observation(self, incident: Incident | None, decision: Decision, event_id: str) -> None:
        assert self._store is not None
        if decision.verdict is Verdict.IGNORED:
            return
        obs_id = decision.evidence[0] if decision.evidence else f"obs-{decision.decision_id}"
        records.save_observation(
            self._store,
            Observation(
                id=obs_id,
                event_id=event_id,
                point_id=decision.point_id,
                zone=incident.zone if incident is not None else "",
                at=decision.at,
                restored=decision.verdict in {Verdict.SUSPECT_CLEARED, Verdict.FIRE_RESTORED},
                decision_id=decision.decision_id,
            ),
        )

    def _active_incident(self, point_id: str) -> Incident | None:
        if self._store is None:
            return None
        for incident in records.active_incidents(self._store):
            if incident.point_id == point_id:
                return incident
        return None

    def _incident_by_point(self, point_id: str) -> Incident | None:
        if self._store is None:
            return None
        for incident in sorted(records.list_incidents(self._store), key=lambda item: item.opened_at, reverse=True):
            if incident.point_id == point_id:
                return incident
        return None

    def _incident_id_for(self, point_id: str, decisions: list[Decision]) -> str:
        for decision in decisions:
            if decision.view.incident_id:
                return decision.view.incident_id
        latest = self._incident_by_point(point_id)
        return latest.id if latest is not None else ""

    def _view_of(self, incident: Incident) -> PointView:
        state = {
            "suspected": State.SUSPECTED,
            "fire": State.FIRE,
            "linkage_failed": State.FIRE,
        }.get(incident.state, State.NORMAL)
        return PointView(
            state=state,  # type: ignore[arg-type]
            window_started_at=incident.window_started_at,
            last_report_at=incident.last_report_at,
            distinct_reports=incident.distinct_reports,
            incident_id=incident.id,
        )

    # ------------------------------------------------------------------ audit

    def _audit_decision(self, decision: Decision) -> None:
        if self._audit is None:
            return
        stamp = _stamp(decision.at)
        # The audit event names the verdict and references the exact decision
        # document, so audit and runtime provably share one judgement.
        self._audit.append(Record(id=self._ids(), event=f"fire_{decision.verdict.value}", at=stamp))
        self._audit.append(
            Record(id=self._ids(), event=f"fire_decision_ref:{decision.decision_id}", at=stamp)
        )

    def _audit_linkage(self, result: PlanResult) -> None:
        if self._audit is None:
            return
        stamp = _stamp(self._clock())
        self._audit.append(Record(id=self._ids(), event=f"fire_linkage_{result.status}", at=stamp))
        self._audit.append(Record(id=self._ids(), event=f"fire_plan_ref:{result.plan_id}", at=stamp))

    # ------------------------------------------------- legacy manual primitives

    def handle_smoke(self, zone: str) -> bool:
        """Manual smoke handling: close damper and stop ventilation immediately.

        Kept for operator-forced actions outside the confirmation window;
        automatic detector reports go through :meth:`detect` instead.
        """

        self._dampers.save("damper", zone, DamperState(zone=zone, closed=True).as_dict())
        self._vent.stop()
        return True

    def activate_zones(self, source: str) -> list[str]:
        """Suppress the source zone first and then the adjacent zones."""

        order = activation_order(self._zones, source)
        for zone in order:
            self._suppressor.activate(zone)
        return order

    def raise_alarm(self, event_key: str) -> bool:
        """Record an alarm unless the same event key was already seen."""

        if not self._deduper.record(event_key):
            return False
        self._alarms.append(event_key)
        return True

    def alarms(self) -> list[str]:
        return list(self._alarms)

    def alarm_count(self) -> int:
        return len(self._alarms)

    def distinct_alarms(self) -> int:
        return len(set(self._alarms))

    def clear_alarms(self) -> int:
        self._alarms = []
        return self.alarm_count()

    # ------------------------------------------------------------- projections

    def incidents(self) -> list[Incident]:
        if self._store is None:
            return []
        return records.list_incidents(self._store)

    def suspected_points(self) -> list[str]:
        if self._store is None:
            return []
        return [item.point_id for item in records.active_incidents(self._store) if item.state == "suspected"]

    def confirmed_incidents(self) -> list[Incident]:
        if self._store is None:
            return []
        return [item for item in records.list_incidents(self._store) if item.confirmed_at is not None]

    def linkage_records(self) -> list:
        if self._store is None:
            return []
        return records.list_link_records(self._store)

    def report(self) -> FireReport:
        return FireReport(
            detector_count=self.detector_count(),
            alarm_count=self.alarm_count(),
            zone_count=self.zone_count(),
            alarms=self.alarms(),
            suspected=len(self.suspected_points()),
            confirmed=len(self.confirmed_incidents()),
        )

    def describe(self) -> str:
        return (
            f"fire detectors={self.detector_count()} zones={self.zone_count()} "
            f"suspected={len(self.suspected_points())} alarms={self.alarm_count()}"
        )


class DefaultGateway:
    """Adapts the legacy damper/vent/suppressor devices to the linkage API."""

    def __init__(self, dampers: object, vent: VentStopper, suppressor: Suppressor) -> None:
        self._dampers = dampers
        self._vent = vent
        self._suppressor = suppressor

    def close_damper(self, zone: str) -> None:
        self._dampers.save("damper", zone, DamperState(zone=zone, closed=True).as_dict())

    def open_damper(self, zone: str) -> None:
        self._dampers.save("damper", zone, DamperState(zone=zone, closed=False).as_dict())

    def stop_ventilation(self) -> None:
        self._vent.stop()

    def start_ventilation(self) -> None:
        self._vent.start()

    def activate_suppression(self, zone: str) -> None:
        self._suppressor.activate(zone)

    def deactivate_suppression(self, zone: str) -> None:
        deactivate = getattr(self._suppressor, "deactivate", None)
        if callable(deactivate):
            deactivate(zone)

    def raise_panel_alarm(self, incident_id: str) -> None:
        raise_alarm = getattr(self._suppressor, "raise_panel_alarm", None)
        if callable(raise_alarm):
            raise_alarm(incident_id)

    def clear_panel_alarm(self, incident_id: str) -> None:
        clear = getattr(self._suppressor, "clear_panel_alarm", None)
        if callable(clear):
            clear(incident_id)


class _NullStore:
    """Stand-in used when no durable store is wired; nothing is persisted."""

    def save(self, *args: object, **kwargs: object) -> None:
        return None

    def load(self, *args: object, **kwargs: object) -> None:
        return None

    def exists(self, *args: object, **kwargs: object) -> bool:
        return False

    def list(self, *args: object, **kwargs: object) -> list[str]:
        return []
