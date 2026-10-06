"""Ordered fire linkage with compensating rollback.

Escalation drives the physical outputs in a fixed order: the source zone
damper closes, the ventilation bank stops, and suppression then activates the
source zone followed by its neighbours.  If any step fails, every step that
already took effect is compensated in reverse order, so a partial linkage can
never be left standing.  Only a fully applied linkage is recorded, and an
effective linkage record is immutable.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from .model import DamperState
from .zone import activation_order


class DamperStore(Protocol):
    """Persists the closed state of a zone damper."""

    def save(self, kind: str, record_id: str, value: object) -> None:  # pragma: no cover - structural
        ...


class VentStopper(Protocol):
    """Stops and restarts the ventilation bank."""

    def stop(self) -> bool:  # pragma: no cover - structural
        ...

    def start(self) -> bool:  # pragma: no cover - structural
        ...


class Suppressor(Protocol):
    """Activates and releases suppression for one zone."""

    def activate(self, zone: str) -> object:  # pragma: no cover - structural
        ...

    def release(self, zone: str) -> object:  # pragma: no cover - structural
        ...


@dataclass(frozen=True)
class LinkageStep:
    """One physical output that took effect."""

    action: str
    target: str

    def as_dict(self) -> dict[str, str]:
        return {"action": self.action, "target": self.target}


def escalation_steps(source_zone: str, zones: tuple[str, ...]) -> list[LinkageStep]:
    """Damper, ventilation stop, then source-first suppression order."""

    steps = [LinkageStep("damper_close", source_zone), LinkageStep("vent_stop", source_zone)]
    steps.extend(LinkageStep("suppress", zone) for zone in activation_order(zones, source_zone))
    return steps


def _reverse(steps: list[LinkageStep]) -> list[LinkageStep]:
    return [LinkageStep(_compensation(step.action), step.target) for step in reversed(steps)]


def _compensation(action: str) -> str:
    return {
        "damper_close": "damper_open",
        "vent_stop": "vent_start",
        "suppress": "suppress_release",
    }[action]


class LinkageError(RuntimeError):
    """Raised when a linkage step could not take effect."""


class Linkage:
    """Applies ordered steps and rolls the applied ones back on failure."""

    def __init__(
        self,
        dampers: DamperStore,
        vent: VentStopper,
        suppressor: Suppressor,
        zones: tuple[str, ...],
    ) -> None:
        self._dampers = dampers
        self._vent = vent
        self._suppressor = suppressor
        self._zones = tuple(zones)

    def _apply_one(self, step: LinkageStep) -> None:
        if step.action == "damper_close":
            self._dampers.save("damper", step.target, DamperState(zone=step.target, closed=True).as_dict())
        elif step.action == "vent_stop":
            self._vent.stop()
        elif step.action == "suppress":
            self._suppressor.activate(step.target)
        else:  # pragma: no cover - guarded by escalation_steps
            raise LinkageError(f"unknown linkage action {step.action}")

    def _compensate_one(self, step: LinkageStep) -> None:
        if step.action == "damper_open":
            self._dampers.save("damper", step.target, DamperState(zone=step.target, closed=False).as_dict())
        elif step.action == "vent_start":
            self._vent.start()
        elif step.action == "suppress_release":
            self._suppressor.release(step.target)

    def apply(self, source_zone: str) -> list[LinkageStep]:
        """Apply every step; on failure compensate in reverse and re-raise."""

        planned = escalation_steps(source_zone, self._zones)
        applied: list[LinkageStep] = []
        for step in planned:
            try:
                self._apply_one(step)
            except Exception as exc:
                self.rollback(applied)
                raise LinkageError(f"linkage step {step.action}:{step.target} failed: {exc}") from exc
            applied.append(step)
        return applied

    def rollback(self, steps: list[LinkageStep]) -> list[LinkageStep]:
        """Compensate the given effective steps in reverse order."""

        compensations = _reverse(steps)
        for step in compensations:
            self._compensate_one(step)
        return compensations
