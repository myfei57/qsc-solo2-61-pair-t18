"""One full tunnel control cycle walked in chain order."""

from __future__ import annotations

from tunnelnet.ns import Stage, control_chain

from .audit_log import record_event
from .http import Request, Response, json_response
from .runtime import Runtime


def detector_for_zone(rt: Runtime, zone: str) -> str:
    """Pick the detector registered for a zone, falling back to the zone id."""

    for detector in rt.fire.detectors():
        if detector.zone == zone:
            return detector.id
    return zone


def run_cycle(rt: Runtime, request: Request) -> Response:
    """Walk the whole chain once, in production order."""

    cabin_id = request.str_field("cabin_id")
    requester = request.str_field("requester", "operator")
    zone = request.str_field("zone")
    sensor_id = request.str_field("sensor_id", "sensor-1")
    samples = request.float_list("samples")
    fallback = request.float_field("value")
    at = request.str_field("at")
    watts = request.float_field("watts")

    reading = sum(samples) / len(samples) if samples else fallback

    approval = rt.access.approve(cabin_id, requester)
    record_event(rt, "access_approved", approval.id)

    alarmed = rt.env.sample(sensor_id, reading, at)

    # Two reports from the same detector within the confirmation window are
    # what confirms a fire; the cycle drives both and linkage follows on
    # confirmation (rolled back automatically if it partially fails).
    detector_id = detector_for_zone(rt, zone)
    rt.fire.report_smoke(detector_id, at=at, event_key=f"{zone}:{at}:1")
    second = rt.fire.report_smoke(detector_id, at=at, event_key=f"{zone}:{at}:2")
    raised = second.escalated()
    zones = rt.fire.zones() if raised else []

    rt.patrol.check_in(cabin_id, at)

    usage = rt.quota.add_usage(cabin_id, watts)

    rt.drain.start_drain(cabin_id)
    rt.drain.record_cycle(cabin_id, at)

    record_event(rt, "cycle", cabin_id)
    line = control_chain()

    return json_response(
        {
            "approval": approval.id,
            "alarmed": alarmed,
            "reading": reading,
            "zones": zones,
            "alarm_raised": raised,
            "patrol_route": rt.patrol.route_len(),
            "usage": usage,
            "drain_runs": rt.drain.run_count(),
            "audit_count": rt.audit.count(),
            "last_stage": Stage.AUDIT.value if line.contains(Stage.AUDIT) else "",
        }
    )
