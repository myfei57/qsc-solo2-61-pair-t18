"""Confirmation policy: the single judgement shared by runtime and audit.

This module is deliberately pure (no IO, no storage, no side effects). Both the
live fire service and the audit/verification tooling call :func:`evaluate_report`,
so an audit entry cannot be interpreted with a different rule set than the one
that produced it.

Two design choices are fixed here on purpose:

1. The confirmation window is **time based**, not a consecutive counter.  A
   counter cannot tell one puff of cooking steam re-triggering the chamber from
   smoke that keeps coming, and a faulty detector can inflate its own count
   within seconds.  A time window plus a minimum spacing between distinct
   reports rejects chatter while still confirming a real, persistent fire.

2. An unconfirmed (suspected) observation **expires on its own** instead of
   being escalated to a human.  Manual escalation of every kitchen-steam blip
   recreates the alarm fatigue this service exists to remove, and an unattended
   queue silently turns back into a single-report alarm.  The real-fire risk of
   auto-withdrawal is bounded two ways: a fresh report after expiry starts a new
   window, and a detector that produces too many suspected incidents is itself
   escalated for manual inspection (:attr:`PolicyConfig.escalate_after`).
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum


class State(str, Enum):
    """Lifecycle state of one detector point."""

    NORMAL = "normal"
    SUSPECTED = "suspected"
    FIRE = "fire"


class Verdict(str, Enum):
    """Outcome of evaluating one report or one expiry sweep."""

    IGNORED = "ignored"
    """Duplicate report inside the de-duplication interval."""

    SUSPECT_OPENED = "suspect_opened"
    """First distinct report of an incident; confirmation window opened."""

    SUSPECT_KEPT = "suspect_kept"
    """Another report inside the window, but not enough to confirm yet."""

    FIRE_CONFIRMED = "fire_confirmed"
    """Persistent reports inside the window; linkage may engage."""

    SUSPECT_CLEARED = "suspect_cleared"
    """A restore report arrived while the point was still suspected."""

    SUSPECT_EXPIRED = "suspect_expired"
    """Confirmation window closed without enough evidence; auto withdrawn."""

    FIRE_RESTORED = "fire_restored"
    """Smoke cleared after confirmation; linkage may disengage."""

    NO_CHANGE = "no_change"
    """Report is consistent with the current state (e.g. fire re-reported)."""


@dataclass(frozen=True)
class PolicyConfig:
    """Tunables of the confirmation window.

    ``min_gap_seconds`` is the minimum spacing between two *distinct* reports
    that can confirm a fire: a burst of steam reports within the gap counts as
    one observation.  It must be smaller than ``window_seconds``.
    """

    window_seconds: float = 60.0
    min_gap_seconds: float = 10.0
    reports_to_confirm: int = 2
    dedupe_seconds: float = 2.0
    escalate_after: int = 3

    def validate(self) -> None:
        if self.window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        if self.min_gap_seconds < 0 or self.min_gap_seconds >= self.window_seconds:
            raise ValueError("min_gap_seconds must be within the confirmation window")
        if self.reports_to_confirm < 1:
            raise ValueError("reports_to_confirm must be at least 1")
        if self.dedupe_seconds < 0:
            raise ValueError("dedupe_seconds must be non-negative")
        if self.escalate_after < 1:
            raise ValueError("escalate_after must be at least 1")


@dataclass(frozen=True)
class PointView:
    """Everything the policy needs to know about one detector point.

    Times are numeric seconds on the service clock so the policy stays
    independent of clock formatting.  ``None`` means "no active incident".
    """

    state: State
    window_started_at: float | None
    last_report_at: float | None
    distinct_reports: int
    incident_id: str | None

    @classmethod
    def normal(cls) -> "PointView":
        return cls(
            state=State.NORMAL,
            window_started_at=None,
            last_report_at=None,
            distinct_reports=0,
            incident_id=None,
        )

    def as_dict(self) -> dict[str, object]:
        return {
            "state": self.state.value,
            "window_started_at": self.window_started_at,
            "last_report_at": self.last_report_at,
            "distinct_reports": self.distinct_reports,
            "incident_id": self.incident_id,
        }


@dataclass(frozen=True)
class Decision:
    """The one authoritative judgement for one report or expiry sweep.

    The runtime persists this object verbatim and the audit trail references it
    by ``decision_id``.  ``view`` is the point state after applying the verdict;
    ``evidence`` lists the observation ids supporting the judgement.
    """

    decision_id: str
    point_id: str
    verdict: Verdict
    at: float
    view: PointView
    evidence: tuple[str, ...] = field(default_factory=tuple)
    reason: str = ""

    @property
    def persisted(self) -> bool:
        """Suspected and confirmed incidents must be durably recorded."""

        return self.verdict in {
            Verdict.SUSPECT_OPENED,
            Verdict.SUSPECT_KEPT,
            Verdict.FIRE_CONFIRMED,
            Verdict.SUSPECT_CLEARED,
            Verdict.SUSPECT_EXPIRED,
            Verdict.FIRE_RESTORED,
        }

    @property
    def linkage_ready(self) -> bool:
        """Only a confirmed fire engages linkage."""

        return self.verdict is Verdict.FIRE_CONFIRMED

    @property
    def linkage_releases(self) -> bool:
        """A confirmed restore disengages linkage."""

        return self.verdict is Verdict.FIRE_RESTORED

    @property
    def terminal(self) -> bool:
        """The incident closes and the point returns to normal."""

        return self.verdict in {
            Verdict.SUSPECT_CLEARED,
            Verdict.SUSPECT_EXPIRED,
            Verdict.FIRE_RESTORED,
        }

    def as_dict(self) -> dict[str, object]:
        return {
            "decision_id": self.decision_id,
            "point_id": self.point_id,
            "verdict": self.verdict.value,
            "at": self.at,
            "view": self.view.as_dict(),
            "evidence": list(self.evidence),
            "reason": self.reason,
        }


def is_duplicate(view: PointView, at: float, config: PolicyConfig) -> bool:
    """Whether an alarm at ``at`` is a retransmission of the last one."""

    return view.last_report_at is not None and at - view.last_report_at < config.dedupe_seconds


def window_expired(view: PointView, at: float, config: PolicyConfig) -> bool:
    """Whether a still-open confirmation window has run out."""

    return (
        view.state is State.SUSPECTED
        and view.window_started_at is not None
        and at - view.window_started_at >= config.window_seconds
    )


def evaluate_report(
    decision_id: str,
    point_id: str,
    incident_id: str,
    observation_id: str,
    view: PointView,
    at: float,
    restored: bool,
    config: PolicyConfig,
) -> list[Decision]:
    """Apply one detector report to a point view.

    Returns one decision, or two when a report lands exactly as a stale window
    expires: the old incident is expired and closed first, then the report opens
    a fresh window.  Callers persist and audit every returned decision in order.
    """

    config.validate()

    if restored:
        if view.state is State.FIRE:
            return [
                Decision(
                    decision_id=decision_id,
                    point_id=point_id,
                    verdict=Verdict.FIRE_RESTORED,
                    at=at,
                    view=PointView.normal(),
                    evidence=(observation_id,),
                    reason="restore report after confirmation",
                )
            ]
        if view.state is State.SUSPECTED:
            return [
                Decision(
                    decision_id=decision_id,
                    point_id=point_id,
                    verdict=Verdict.SUSPECT_CLEARED,
                    at=at,
                    view=PointView.normal(),
                    evidence=(observation_id,),
                    reason="cleared inside the confirmation window",
                )
            ]
        return [
            Decision(
                decision_id=decision_id,
                point_id=point_id,
                verdict=Verdict.NO_CHANGE,
                at=at,
                view=view,
                evidence=(observation_id,),
                reason="already normal",
            )
        ]

    if view.state is State.FIRE:
        return [
            Decision(
                decision_id=decision_id,
                point_id=point_id,
                verdict=Verdict.NO_CHANGE,
                at=at,
                view=replace(view, last_report_at=at),
                evidence=(observation_id,),
                reason="fire already confirmed",
            )
        ]

    if view.state is State.NORMAL:
        return [
            Decision(
                decision_id=decision_id,
                point_id=point_id,
                verdict=Verdict.SUSPECT_OPENED,
                at=at,
                view=PointView(
                    state=State.SUSPECTED,
                    window_started_at=at,
                    last_report_at=at,
                    distinct_reports=1,
                    incident_id=incident_id,
                ),
                evidence=(observation_id,),
                reason="first report opens the confirmation window",
            )
        ]

    # State.SUSPECTED: the window is open.
    if window_expired(view, at, config):
        # Expire the lapsed incident first so it is closed cleanly, then let the
        # incoming report open a fresh window on the same point.
        expired = Decision(
            decision_id=f"{decision_id}:expiry",
            point_id=point_id,
            verdict=Verdict.SUSPECT_EXPIRED,
            at=at,
            view=PointView.normal(),
            reason="confirmation window elapsed before confirmation",
        )
        reopened = Decision(
            decision_id=decision_id,
            point_id=point_id,
            verdict=Verdict.SUSPECT_OPENED,
            at=at,
            view=PointView(
                state=State.SUSPECTED,
                window_started_at=at,
                last_report_at=at,
                distinct_reports=1,
                incident_id=incident_id,
            ),
            evidence=(observation_id,),
            reason="fresh report after the previous window expired",
        )
        return [expired, reopened]

    if is_duplicate(view, at, config):
        return [
            Decision(
                decision_id=decision_id,
                point_id=point_id,
                verdict=Verdict.IGNORED,
                at=at,
                view=view,
                evidence=(observation_id,),
                reason="retransmission inside the de-duplication interval",
            )
        ]

    count = view.distinct_reports + 1
    age = at - (view.window_started_at if view.window_started_at is not None else at)
    gap = at - (view.last_report_at if view.last_report_at is not None else at)
    enough = count >= config.reports_to_confirm
    spaced = gap >= config.min_gap_seconds

    if enough and spaced:
        return [
            Decision(
                decision_id=decision_id,
                point_id=point_id,
                verdict=Verdict.FIRE_CONFIRMED,
                at=at,
                view=replace(
                    view,
                    state=State.FIRE,
                    last_report_at=at,
                    distinct_reports=count,
                ),
                evidence=(observation_id,),
                reason=(
                    f"{count} distinct reports within {config.window_seconds:g}s window, "
                    f"latest {gap:g}s after the previous one"
                ),
            )
        ]

    return [
        Decision(
            decision_id=decision_id,
            point_id=point_id,
            verdict=Verdict.SUSPECT_KEPT,
            at=at,
            view=replace(view, last_report_at=at, distinct_reports=count),
            evidence=(observation_id,),
            reason=(
                f"{count} report(s) in window; need {config.reports_to_confirm} spaced "
                f">= {config.min_gap_seconds:g}s apart (age {age:g}s, gap {gap:g}s)"
            ),
        )
    ]


def evaluate_expiry(
    decision_id: str,
    point_id: str,
    view: PointView,
    at: float,
    config: PolicyConfig,
) -> Decision | None:
    """Return an expiry decision when an open window has lapsed, else ``None``."""

    if not window_expired(view, at, config):
        return None
    return Decision(
        decision_id=decision_id,
        point_id=point_id,
        verdict=Verdict.SUSPECT_EXPIRED,
        at=at,
        view=PointView.normal(),
        reason="confirmation window elapsed without confirmation; auto withdrawn",
    )
