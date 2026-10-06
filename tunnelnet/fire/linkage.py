"""Ordered fire linkage with compensating rollback.

Timing dependency between confirm, linkage and release:

1. The policy confirms a fire (decision persisted first).
2. The linkage plan engages physical steps **in order**; each effective step is
   durably recorded before the next one runs.
3. If any step fails, steps that took effect *in this attempt* are compensated
   in **reverse order** and the plan is marked ``rolled_back``.  The
   confirmed-fire decision is not rewritten; it stays on record together with
   the failed linkage and is surfaced for the operator.
4. On a confirmed restore the same steps are reversed in reverse order.

Re-driving a plan (a duplicated confirm, or recovery after a crash between the
decision write and the device calls) is idempotent: targets already effective
are skipped, and already compensated targets are not re-touched.  Effective
link records are immutable - rollback and release append new records rather
than editing an existing one; each attempt gets its own record id suffix.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from tunnelnet.store import Store

from . import records
from .model import LinkRecord
from .zone import activation_order


class LinkageGateway(Protocol):
    """Physical devices driven by the fire linkage."""

    def close_damper(self, zone: str) -> None: ...
    def open_damper(self, zone: str) -> None: ...
    def stop_ventilation(self) -> None: ...
    def start_ventilation(self) -> None: ...
    def activate_suppression(self, zone: str) -> None: ...
    def deactivate_suppression(self, zone: str) -> None: ...
    def raise_panel_alarm(self, incident_id: str) -> None: ...
    def clear_panel_alarm(self, incident_id: str) -> None: ...


@dataclass(frozen=True)
class Step:
    """One ordered physical effect and its compensating reverse action."""

    seq: int
    step_key: str
    target: str
    forward: Callable[[LinkageGateway, str], None]
    reverse: Callable[[LinkageGateway, str], None]

    def apply(self, gateway: LinkageGateway) -> None:
        self.forward(gateway, self.target)

    def compensate(self, gateway: LinkageGateway) -> None:
        self.reverse(gateway, self.target)


def _close_damper(gateway: LinkageGateway, zone: str) -> None:
    gateway.close_damper(zone)


def _open_damper(gateway: LinkageGateway, zone: str) -> None:
    gateway.open_damper(zone)


def _stop_vent(gateway: LinkageGateway, _target: str) -> None:
    gateway.stop_ventilation()


def _start_vent(gateway: LinkageGateway, _target: str) -> None:
    gateway.start_ventilation()


def _suppress(gateway: LinkageGateway, zone: str) -> None:
    gateway.activate_suppression(zone)


def _unsuppress(gateway: LinkageGateway, zone: str) -> None:
    gateway.deactivate_suppression(zone)


def _panel(gateway: LinkageGateway, incident_id: str) -> None:
    gateway.raise_panel_alarm(incident_id)


def _unpanel(gateway: LinkageGateway, incident_id: str) -> None:
    gateway.clear_panel_alarm(incident_id)


def build_steps(zones: tuple[str, ...], source: str, incident_id: str) -> list[Step]:
    """Damper, ventilation, suppression (source first), panel last.

    The panel alarm is raised last so crews are never paged for a linkage that
    then fails underneath them; dampers close before ventilation is stopped.
    """

    order = activation_order(zones, source)
    steps: list[Step] = [
        Step(0, "damper", source, _close_damper, _open_damper),
        Step(1, "ventilation", "bank", _stop_vent, _start_vent),
    ]
    for offset, zone in enumerate(order, start=2):
        steps.append(Step(offset, f"suppression", zone, _suppress, _unsuppress))
    steps.append(Step(100, "panel", incident_id, _panel, _unpanel))
    return steps


@dataclass(frozen=True)
class PlanResult:
    """Outcome of engaging or releasing one linkage plan."""

    plan_id: str
    status: str
    applied: tuple[str, ...]
    compensated: tuple[str, ...]
    failed_step: str
    detail: str

    @property
    def ok(self) -> bool:
        return self.status in {"engaged", "released"}

    def as_dict(self) -> dict[str, object]:
        return {
            "plan_id": self.plan_id,
            "status": self.status,
            "applied": list(self.applied),
            "compensated": list(self.compensated),
            "failed_step": self.failed_step,
            "detail": self.detail,
        }


class LinkageExecutor:
    """Drives a gateway durably, with reverse-order compensation."""

    def __init__(
        self,
        store: Store,
        gateway: LinkageGateway,
        clock: Callable[[], float],
        id_factory: Callable[[], str],
    ) -> None:
        self._store = store
        self._gateway = gateway
        self._clock = clock
        self._ids = id_factory
        self._lock = threading.RLock()

    def engage(self, incident_id: str, source_zone: str, zones: tuple[str, ...]) -> PlanResult:
        with self._lock:
            plan_id = f"plan-{incident_id}"
            existing = records.load_plan(self._store, plan_id)
            if existing is not None and existing.get("status") == "engaged":
                return PlanResult(plan_id, "engaged", (), (), "", "plan already engaged")
            steps = build_steps(zones, source_zone, incident_id)
            if existing is None:
                self._write_plan(plan_id, incident_id, "engaging", steps, attempt=1)
                attempt = 1
            else:
                # Either a crash mid-engage or a previous rolled-back attempt:
                # resume/retry under a fresh attempt number with unique ids.
                attempt = int(existing.get("attempt", 1)) + 1
                self._write_plan(plan_id, incident_id, "engaging", steps, attempt=attempt)
            return self._run(plan_id, incident_id, steps, attempt)

    def release(self, incident_id: str) -> PlanResult:
        """Disengage a previously engaged plan after a confirmed restore."""

        with self._lock:
            plan_id = f"plan-{incident_id}"
            existing = records.load_plan(self._store, plan_id)
            if existing is None:
                return PlanResult(plan_id, "missing", (), (), "", "no linkage plan for incident")
            if existing.get("status") == "released":
                return PlanResult(plan_id, "released", (), (), "", "plan already released")
            steps = [_step_from_row(row) for row in existing.get("steps", [])]  # type: ignore[arg-type]
            attempt = int(existing.get("release_attempt", 0)) + 1
            self._set_plan_status(plan_id, "releasing", release_attempt=attempt)
            return self._release(plan_id, incident_id, steps, attempt)

    def recover_pending(self) -> list[PlanResult]:
        """Resume plans left non-terminal by a crash, called on boot."""

        results: list[PlanResult] = []
        with self._lock:
            for plan in records.list_plans(self._store):
                status = str(plan.get("status", ""))
                if status not in {"engaging", "releasing"}:
                    continue
                plan_id = str(plan["plan_id"])
                incident_id = str(plan.get("incident_id", ""))
                steps = [_step_from_row(row) for row in plan.get("steps", [])]  # type: ignore[arg-type]
                if status == "engaging":
                    attempt = int(plan.get("attempt", 1))
                    results.append(self._run(plan_id, incident_id, steps, attempt))
                else:
                    attempt = int(plan.get("release_attempt", 1))
                    results.append(self._release(plan_id, incident_id, steps, attempt))
        return results

    # ------------------------------------------------------------------ internals

    def _run(self, plan_id: str, incident_id: str, steps: list[Step], attempt: int) -> PlanResult:
        live = records.live_link_targets(self._store, plan_id)
        applied: list[Step] = []
        for step in steps:
            if (step.step_key, step.target) in live:
                continue  # idempotent re-drive: already effective from an earlier attempt
            try:
                step.apply(self._gateway)
            except Exception as exc:  # device failure: compensate what took effect
                self._append_link(plan_id, incident_id, step, attempt, "failed", str(exc))
                compensated = self._compensate(plan_id, incident_id, attempt, applied)
                self._set_plan_status(plan_id, "rolled_back")
                return PlanResult(
                    plan_id,
                    "rolled_back",
                    tuple(step.step_key for step in applied),
                    tuple(step.step_key for step in compensated),
                    step.step_key,
                    f"{step.step_key}:{step.target} failed: {exc}",
                )
            self._append_link(plan_id, incident_id, step, attempt, "engaged", "")
            live.add((step.step_key, step.target))
            applied.append(step)
            self._set_plan_status(plan_id, "engaging", attempt=attempt)
        self._set_plan_status(plan_id, "engaged", attempt=attempt)
        return PlanResult(
            plan_id,
            "engaged",
            tuple(step.step_key for step in applied),
            (),
            "",
            "",
        )

    def _compensate(
        self,
        plan_id: str,
        incident_id: str,
        attempt: int,
        applied: list[Step],
    ) -> list[Step]:
        compensated: list[Step] = []
        # Reverse order, keyed by (step_key, target) so several suppression
        # zones sharing one step_key are compensated individually.
        for step in reversed(applied):
            try:
                step.compensate(self._gateway)
            except Exception as exc:  # best effort: record it and keep unwinding
                self._append_link(plan_id, incident_id, step, attempt, "compensate_failed", str(exc))
                continue
            self._append_link(plan_id, incident_id, step, attempt, "compensated", "")
            compensated.append(step)
        return compensated

    def _release(
        self, plan_id: str, incident_id: str, steps: list[Step], attempt: int
    ) -> PlanResult:
        live = records.live_link_targets(self._store, plan_id)
        released: list[str] = []
        for step in reversed(steps):
            if (step.step_key, step.target) not in live:
                continue
            try:
                step.compensate(self._gateway)
            except Exception as exc:
                self._append_link(plan_id, incident_id, step, attempt, "disengage_failed", str(exc))
                self._set_plan_status(plan_id, "release_failed", release_attempt=attempt)
                return PlanResult(
                    plan_id,
                    "release_failed",
                    (),
                    tuple(reversed(released)),
                    step.step_key,
                    f"{step.step_key}:{step.target} release failed: {exc}",
                )
            self._append_link(plan_id, incident_id, step, attempt, "disengaged", "")
            live.discard((step.step_key, step.target))
            released.append(step.step_key)
        self._set_plan_status(plan_id, "released", release_attempt=attempt)
        return PlanResult(plan_id, "released", (), tuple(reversed(released)), "", "")

    def _append_link(
        self,
        plan_id: str,
        incident_id: str,
        step: Step,
        attempt: int,
        status: str,
        detail: str,
    ) -> LinkRecord:
        record = LinkRecord(
            id=f"{plan_id}:a{attempt}:{step.seq}:{status}",
            plan_id=plan_id,
            incident_id=incident_id,
            seq=step.seq,
            step_key=step.step_key,
            op=step.forward.__name__,
            target=step.target,
            reverse_op=step.reverse.__name__,
            status=status,
            at=self._clock(),
            detail=detail,
            order=records.next_link_order(self._store, plan_id),
        )
        records.save_link_record(self._store, record)
        return record

    def _write_plan(
        self,
        plan_id: str,
        incident_id: str,
        status: str,
        steps: list[Step],
        attempt: int,
    ) -> None:
        now = self._clock()
        records.save_plan(
            self._store,
            plan_id,
            {
                "plan_id": plan_id,
                "incident_id": incident_id,
                "status": status,
                "attempt": attempt,
                "opened_at": now,
                "updated_at": now,
                "steps": [
                    {
                        "seq": step.seq,
                        "step_key": step.step_key,
                        "target": step.target,
                        "op": step.forward.__name__,
                        "reverse_op": step.reverse.__name__,
                    }
                    for step in steps
                ],
            },
        )

    def _set_plan_status(self, plan_id: str, status: str, **extra: object) -> None:
        plan = records.load_plan(self._store, plan_id)
        if plan is None:
            return
        plan["status"] = status
        plan["updated_at"] = self._clock()
        plan.update(extra)
        records.save_plan(self._store, plan_id, plan)


def _step_from_row(row: object) -> Step:
    data = row  # type: ignore[assignment]
    key = str(data["step_key"])  # type: ignore[index]
    target = str(data["target"])  # type: ignore[index]
    seq = int(data["seq"])  # type: ignore[index]
    forward, reverse = _STEP_ACTIONS[key]
    return Step(seq, key, target, forward, reverse)


_STEP_ACTIONS = {
    "damper": (_close_damper, _open_damper),
    "ventilation": (_stop_vent, _start_vent),
    "suppression": (_suppress, _unsuppress),
    "panel": (_panel, _unpanel),
}
