"""Confirmation-window behaviour: pure policy and durable fire service."""

from __future__ import annotations

import tempfile
import unittest

from tunnelnet.audit import AuditRegistry, MarkSet
from tunnelnet.cabin import SuppressionLog
from tunnelnet.fire import (
    Decision,
    Detector,
    FireService,
    Incident,
    LinkRecord,
    PointView,
    PolicyConfig,
    State,
    Verdict,
    evaluate_expiry,
    evaluate_report,
)
from tunnelnet.fire import records as fire_records
from tunnelnet.store import Store
from tunnelnet.vent import VentService


def normal() -> PointView:
    return PointView.normal()


def suspected(started: float, last: float, count: int, incident: str = "inc-1") -> PointView:
    return PointView(State.SUSPECTED, started, last, count, incident)


class PolicyCase(unittest.TestCase):
    def setUp(self) -> None:
        self.config = PolicyConfig(
            window_seconds=60.0, min_gap_seconds=10.0, reports_to_confirm=2, dedupe_seconds=2.0
        )

    def test_first_report_only_suspects(self) -> None:
        [decision] = evaluate_report("d1", "p1", "inc-new", "o1", normal(), 100.0, False, self.config)
        self.assertEqual(decision.verdict, Verdict.SUSPECT_OPENED)
        self.assertEqual(decision.view.state, State.SUSPECTED)
        self.assertTrue(decision.persisted)
        self.assertFalse(decision.linkage_ready)

    def test_spaced_reports_confirm(self) -> None:
        view = suspected(100.0, 100.0, 1)
        [decision] = evaluate_report("d2", "p1", "inc-new", "o2", view, 115.0, False, self.config)
        self.assertEqual(decision.verdict, Verdict.FIRE_CONFIRMED)
        self.assertTrue(decision.linkage_ready)
        self.assertEqual(decision.view.state, State.FIRE)

    def test_burst_is_de_duplicated(self) -> None:
        view = suspected(100.0, 100.0, 1)
        [decision] = evaluate_report("d2", "p1", "inc-new", "o2", view, 101.0, False, self.config)
        self.assertEqual(decision.verdict, Verdict.IGNORED)
        self.assertEqual(decision.view.state, State.SUSPECTED)

    def test_second_report_too_close_stays_suspected(self) -> None:
        view = suspected(100.0, 100.0, 1)
        [decision] = evaluate_report("d2", "p1", "inc-new", "o2", view, 105.0, False, self.config)
        self.assertEqual(decision.verdict, Verdict.SUSPECT_KEPT)

    def test_restore_inside_window_clears(self) -> None:
        view = suspected(100.0, 100.0, 1)
        [decision] = evaluate_report("d2", "p1", "inc-new", "o2", view, 120.0, True, self.config)
        self.assertEqual(decision.verdict, Verdict.SUSPECT_CLEARED)
        self.assertTrue(decision.terminal)
        self.assertEqual(decision.view.state, State.NORMAL)

    def test_window_expiry_withdraws_automatically(self) -> None:
        view = suspected(100.0, 100.0, 1)
        decision = evaluate_expiry("dx", "p1", view, 160.0, self.config)
        assert decision is not None
        self.assertEqual(decision.verdict, Verdict.SUSPECT_EXPIRED)
        self.assertEqual(decision.view.state, State.NORMAL)
        self.assertIsNone(evaluate_expiry("dx", "p1", normal(), 160.0, self.config))

    def test_restore_after_fire_releases_linkage(self) -> None:
        view = PointView(State.FIRE, 100.0, 115.0, 2, "inc-1")
        [decision] = evaluate_report("d3", "p1", "inc-new", "o3", view, 200.0, True, self.config)
        self.assertEqual(decision.verdict, Verdict.FIRE_RESTORED)
        self.assertTrue(decision.linkage_releases)

    def test_report_after_expiry_closes_then_reopens(self) -> None:
        view = suspected(100.0, 100.0, 1)
        decisions = evaluate_report("d4", "p1", "inc-new", "o4", view, 161.0, False, self.config)
        self.assertEqual([item.verdict for item in decisions], [Verdict.SUSPECT_EXPIRED, Verdict.SUSPECT_OPENED])

    def test_invalid_config_rejected(self) -> None:
        with self.assertRaises(ValueError):
            PolicyConfig(window_seconds=0).validate()
        with self.assertRaises(ValueError):
            PolicyConfig(window_seconds=10, min_gap_seconds=10).validate()
        with self.assertRaises(ValueError):
            PolicyConfig(reports_to_confirm=0).validate()


class RecordingGateway:
    def __init__(self, fail_at: str = "") -> None:
        self.fail_at = fail_at
        self.dampers: list[tuple[str, bool]] = []
        self.ventilation = "running"
        self.suppression: list[tuple[str, bool]] = []
        self.panel: set[str] = set()

    def close_damper(self, zone: str) -> None:
        self.dampers.append((zone, True))

    def open_damper(self, zone: str) -> None:
        self.dampers.append((zone, False))

    def stop_ventilation(self) -> None:
        self.ventilation = "stopped"

    def start_ventilation(self) -> None:
        self.ventilation = "running"

    def activate_suppression(self, zone: str) -> None:
        if self.fail_at == zone:
            raise RuntimeError(f"{zone} bus down")
        self.suppression.append((zone, True))

    def deactivate_suppression(self, zone: str) -> None:
        self.suppression.append((zone, False))

    def raise_panel_alarm(self, incident_id: str) -> None:
        if self.fail_at == "panel":
            raise RuntimeError("panel down")
        self.panel.add(incident_id)

    def clear_panel_alarm(self, incident_id: str) -> None:
        self.panel.discard(incident_id)


def build_service(gateway: RecordingGateway | None = None, config: PolicyConfig | None = None, clock=None):
    store = Store.open(tempfile.mkdtemp())
    vent = VentService()
    suppression = SuppressionLog()
    audit = AuditRegistry()
    service = FireService(
        store,
        vent,
        suppression,
        MarkSet(),
        ("zone-1", "zone-2", "zone-3"),
        store=store,
        audit=audit,
        config=config or PolicyConfig(),
        gateway=gateway,
        clock=clock,
    )
    service.add_detector(Detector(id="detector-1", zone="zone-1"))
    return service, store, vent, audit


class ServiceCase(unittest.TestCase):
    def test_cooking_steam_single_report_then_restore_never_links(self) -> None:
        clock = FakeClock(0.0)
        service, store, vent, audit = build_service(clock=clock)
        first = service.report_smoke("detector-1", "evt-1")
        self.assertEqual(first.state, "suspected")
        self.assertEqual(service.suspected_points(), ["detector-1"])
        self.assertTrue(vent.running())
        self.assertEqual(store.load("damper", "zone-1"), None)

        clock.advance(5)
        restored = service.report_restore("detector-1", "evt-2")
        self.assertEqual(restored.as_dict()["verdicts"], ["suspect_cleared"])
        self.assertEqual(service.suspected_points(), [])
        self.assertTrue(vent.running())
        self.assertEqual(service.linkage_records(), [])
        incident = [i for i in service.incidents() if i.close_reason == "suspect_cleared"][0]
        self.assertEqual(incident.state, "closed")
        # Suspected and cleared states were both persisted.
        self.assertTrue(store.exists(fire_records.INCIDENT_KIND, incident.id))
        decision_events = [r.event for r in audit.records() if r.event.startswith("fire_")]
        self.assertIn("fire_suspect_opened", decision_events)
        self.assertIn("fire_suspect_cleared", decision_events)

    def test_real_fire_confirms_and_links_in_order(self) -> None:
        gateway = RecordingGateway()
        clock = FakeClock(0.0)
        service, store, vent, audit = build_service(gateway=gateway, clock=clock)
        service.report_smoke("detector-1", "evt-1")
        self.assertFalse(gateway.panel)  # crews not paged while only suspected

        clock.advance(15)
        outcome = service.report_smoke("detector-1", "evt-2")
        self.assertEqual(outcome.state, "fire")
        self.assertIsNotNone(outcome.linkage)
        self.assertEqual(outcome.linkage.status, "engaged")
        # damper -> ventilation -> suppression source first -> panel last
        keys = [(r.step_key, r.target) for r in service.linkage_records() if r.status == "engaged"]
        self.assertEqual(
            keys,
            [
                ("damper", "zone-1"),
                ("ventilation", "bank"),
                ("suppression", "zone-1"),
                ("suppression", "zone-2"),
                ("suppression", "zone-3"),
                ("panel", outcome.incident_id),
            ],
        )
        self.assertEqual(gateway.ventilation, "stopped")
        self.assertTrue(gateway.panel)

        clock.advance(100)
        released = service.report_restore("detector-1", "evt-3")
        self.assertEqual(released.linkage.status, "released")
        self.assertEqual(gateway.ventilation, "running")
        self.assertEqual(gateway.panel, set())
        deactivations = [zone for zone, active in gateway.suppression if not active]
        self.assertEqual(deactivations, ["zone-3", "zone-2", "zone-1"])

    def test_duplicate_event_id_is_idempotent(self) -> None:
        clock = FakeClock(0.0)
        service, store, vent, audit = build_service(clock=clock)
        service.report_smoke("detector-1", "same")
        before = store.file_count()
        clock.advance(30)
        duplicate = service.report_smoke("detector-1", "same")
        self.assertTrue(duplicate.duplicate)
        self.assertEqual(store.file_count(), before)
        self.assertEqual(service.suspected_points(), ["detector-1"])

    def test_retransmission_burst_does_not_count_twice(self) -> None:
        gateway = RecordingGateway()
        clock = FakeClock(0.0)
        service, _, _, _ = build_service(gateway=gateway, clock=clock)
        service.report_smoke("detector-1", "a")
        clock.advance(1)
        service.report_smoke("detector-1", "b")  # inside dedupe interval
        self.assertEqual(service.suspected_points(), ["detector-1"])
        self.assertEqual(gateway.panel, set())

    def test_window_expiry_auto_withdraws(self) -> None:
        clock = FakeClock(0.0)
        service, store, vent, audit = build_service(clock=clock)
        service.report_smoke("detector-1", "a")
        clock.advance(61)
        decisions = service.sweep_expired()
        self.assertEqual(len(decisions), 1)
        self.assertEqual(decisions[0].verdict, Verdict.SUSPECT_EXPIRED)
        self.assertEqual(service.suspected_points(), [])
        self.assertTrue(vent.running())

    def test_chattering_detector_gets_escalated_for_manual_review(self) -> None:
        clock = FakeClock(0.0)
        config = PolicyConfig(escalate_after=3)
        service, _, _, _ = build_service(config=config, clock=clock)
        for index in range(3):
            service.report_smoke("detector-1", f"e{index}-a")
            clock.advance(61)
            service.sweep_expired()
            clock.advance(1)
            service.report_smoke("detector-1", f"e{index}-b")
        self.assertTrue(any(i.escalated for i in service.incidents()))

    def test_linkage_failure_rolls_back_in_reverse_order(self) -> None:
        gateway = RecordingGateway(fail_at="zone-2")
        clock = FakeClock(0.0)
        service, store, vent, audit = build_service(gateway=gateway, clock=clock)
        service.report_smoke("detector-1", "a")
        clock.advance(15)
        outcome = service.report_smoke("detector-1", "b")
        self.assertEqual(outcome.linkage.status, "rolled_back")
        self.assertEqual(outcome.linkage.failed_step, "suppression")
        # damper reopened, ventilation restarted, zone-1 suppression undone;
        # zone-2 never activated and zone-3 was never reached.
        self.assertEqual(gateway.dampers[-1], ("zone-1", False))
        self.assertEqual(gateway.ventilation, "running")
        self.assertEqual(gateway.suppression, [("zone-1", True), ("zone-1", False)])
        self.assertEqual(gateway.panel, set())
        incident = next(i for i in service.incidents() if i.id == outcome.incident_id)
        self.assertEqual(incident.state, "linkage_failed")

    def test_rollback_records_are_immutable_and_retry_replays(self) -> None:
        gateway = RecordingGateway(fail_at="panel")
        clock = FakeClock(0.0)
        service, store, vent, audit = build_service(gateway=gateway, clock=clock)
        service.report_smoke("detector-1", "a")
        clock.advance(15)
        outcome = service.report_smoke("detector-1", "b")
        self.assertEqual(outcome.linkage.status, "rolled_back")
        engaged_ids = [r.id for r in service.linkage_records() if r.status == "engaged"]
        # The same effective record id cannot be overwritten with new content.
        record = store.load(fire_records.LINK_KIND, engaged_ids[0])
        tampered = LinkRecord.from_dict(record)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            fire_records.save_link_record(
                store, LinkRecord(**{**tampered.as_dict(), "detail": "rewritten"})
            )

        # Recovered bus: retry the same plan replays compensated effects once.
        gateway.fail_at = ""
        retry = service._executor.engage(
            outcome.incident_id, "zone-1", ("zone-1", "zone-2", "zone-3")
        )
        self.assertEqual(retry.status, "engaged")
        self.assertEqual(gateway.ventilation, "stopped")
        self.assertTrue(gateway.panel)

    def test_audit_references_the_same_decision_as_runtime(self) -> None:
        clock = FakeClock(0.0)
        service, store, vent, audit = build_service(clock=clock)
        outcome = service.report_smoke("detector-1", "a")
        decision_id = outcome.decisions[0].decision_id
        # The audit entry points at the exact persisted decision document.
        refs = [r.event.split(":", 1)[1] for r in audit.records() if r.event.startswith("fire_decision_ref:")]
        self.assertIn(decision_id, refs)
        persisted = store.load(fire_records.DECISION_KIND, decision_id)
        self.assertEqual(persisted["verdict"], "suspect_opened")  # type: ignore[index]
        # Re-running the pure policy on the stored view reproduces the verdict.
        stored_view = PointView(
            State(persisted["view"]["state"]),  # type: ignore[index]
            persisted["view"]["window_started_at"],  # type: ignore[index]
            persisted["view"]["last_report_at"],  # type: ignore[index]
            persisted["view"]["distinct_reports"],  # type: ignore[index]
            persisted["view"]["incident_id"],  # type: ignore[index]
        )
        [again] = evaluate_report(
            "other", "p", "i", "o", stored_view, 5.0, False, service.policy_config()
        )
        # Within 10s spacing the same decision stays "suspect kept": audit and
        # runtime cannot disagree because both call this one pure function.
        self.assertEqual(again.verdict, Verdict.SUSPECT_KEPT)


class FakeClock:
    def __init__(self, start: float) -> None:
        self.value = start

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


if __name__ == "__main__":
    unittest.main()
