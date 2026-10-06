"""Durable fire records kept in the shared file store.

Record kinds (one JSON document each, atomic writes):

* ``fire_event``  - seen upstream event ids, making repeated reports idempotent;
* ``fire_observation`` - every report that passed de-duplication, append only;
* ``fire_incident`` - the mutable current/lifecycle document of one point;
* ``fire_decision`` - every policy decision, append only;
* ``fire_link``    - immutable record of one physical linkage effect;
* ``fire_plan``    - mutable progress document of one linkage plan.
"""

from __future__ import annotations

import re

from tunnelnet.store import Store

from .model import Incident, LinkRecord, Observation
from .policy import Decision

EVENT_KIND = "fire_event"
OBSERVATION_KIND = "fire_observation"
INCIDENT_KIND = "fire_incident"
DECISION_KIND = "fire_decision"
LINK_KIND = "fire_link"
PLAN_KIND = "fire_plan"

_SAFE_ID = re.compile(r"[^A-Za-z0-9_.-]+")


def safe_id(value: str) -> str:
    """Map an arbitrary upstream id onto a safe store record identifier."""

    cleaned = _SAFE_ID.sub("_", value.strip())
    return cleaned or "_"


# --------------------------------------------------------------------------- de-duplication


def event_seen(store: Store, event_id: str) -> bool:
    return store.exists(EVENT_KIND, safe_id(event_id))


def mark_event(store: Store, event_id: str, at: float, observation_id: str) -> None:
    store.save(
        EVENT_KIND,
        safe_id(event_id),
        {"event_id": event_id, "seen_at": at, "observation_id": observation_id},
    )


# --------------------------------------------------------------------------- observations


def save_observation(store: Store, observation: Observation) -> None:
    store.save(OBSERVATION_KIND, observation.id, observation.as_dict())


def load_observation(store: Store, observation_id: str) -> Observation | None:
    payload = store.load(OBSERVATION_KIND, observation_id)
    return None if payload is None else Observation.from_dict(payload)


def list_observations(store: Store) -> list[Observation]:
    items = [item for item in (load_observation(store, rid) for rid in store.list(OBSERVATION_KIND)) if item]
    return sorted(items, key=lambda item: (item.at, item.id))


# --------------------------------------------------------------------------- incidents


def save_incident(store: Store, incident: Incident) -> None:
    store.save(INCIDENT_KIND, incident.id, incident.as_dict())


def load_incident(store: Store, incident_id: str) -> Incident | None:
    payload = store.load(INCIDENT_KIND, incident_id)
    return None if payload is None else Incident.from_dict(payload)


def list_incidents(store: Store) -> list[Incident]:
    items = [item for item in (load_incident(store, rid) for rid in store.list(INCIDENT_KIND)) if item]
    return sorted(items, key=lambda item: (item.opened_at, item.id))


def active_incidents(store: Store) -> list[Incident]:
    return [item for item in list_incidents(store) if item.state in {"suspected", "fire"}]


# --------------------------------------------------------------------------- decisions


def save_decision(store: Store, decision: Decision) -> None:
    store.save(DECISION_KIND, decision.decision_id, decision.as_dict())


def list_decisions(store: Store) -> list[dict[str, object]]:
    rows = [payload for payload in (store.load(DECISION_KIND, rid) for rid in store.list(DECISION_KIND)) if payload]
    return sorted(rows, key=lambda row: (float(row.get("at", 0.0)), str(row.get("decision_id", ""))))


def load_decision(store: Store, decision_id: str) -> dict[str, object] | None:
    return store.load(DECISION_KIND, safe_id(decision_id))


# --------------------------------------------------------------------------- linkage


def save_link_record(store: Store, record: LinkRecord) -> None:
    """Write one linkage record; an effective record cannot be rewritten.

    A byte-identical re-write is tolerated so crash recovery can replay the
    same append; any other change to an existing id is rejected.
    """

    existing = store.load(LINK_KIND, record.id)
    if existing is not None and existing != record.as_dict():
        raise ValueError(f"effective linkage record {record.id} is immutable")
    store.save(LINK_KIND, record.id, record.as_dict())


def load_link_record(store: Store, record_id: str) -> LinkRecord | None:
    payload = store.load(LINK_KIND, record_id)
    return None if payload is None else LinkRecord.from_dict(payload)


def list_link_records(store: Store) -> list[LinkRecord]:
    items = [item for item in (load_link_record(store, rid) for rid in store.list(LINK_KIND)) if item]
    return sorted(items, key=lambda item: (item.plan_id, item.order, item.seq, item.id))


def link_records_for_plan(store: Store, plan_id: str) -> list[LinkRecord]:
    return [item for item in list_link_records(store) if item.plan_id == plan_id]


def next_link_order(store: Store, plan_id: str) -> int:
    """Monotonic append position for one plan's next linkage record."""

    orders = [item.order for item in link_records_for_plan(store, plan_id)]
    return (max(orders) + 1) if orders else 0


def live_link_targets(store: Store, plan_id: str | None = None) -> set[tuple[str, str]]:
    """(step_key, target) pairs currently effective, for idempotent re-drive.

    A target counts as live only when its latest effect for the plan was
    ``engaged``; compensated or failed effects are absent, so a retried
    engagement replays them.
    """

    live: set[tuple[str, str]] = set()
    for item in list_link_records(store):
        if plan_id is not None and item.plan_id != plan_id:
            continue
        key = (item.step_key, item.target)
        if item.status == "engaged":
            live.add(key)
        elif item.status in {"compensated", "disengaged", "failed"}:
            live.discard(key)
    return live


def save_plan(store: Store, plan_id: str, payload: dict[str, object]) -> None:
    store.save(PLAN_KIND, safe_id(plan_id), payload)


def load_plan(store: Store, plan_id: str) -> dict[str, object] | None:
    return store.load(PLAN_KIND, safe_id(plan_id))


def list_plans(store: Store) -> list[dict[str, object]]:
    rows = [payload for payload in (store.load(PLAN_KIND, rid) for rid in store.list(PLAN_KIND)) if payload]
    return sorted(rows, key=lambda row: (float(row.get("opened_at", 0.0)), str(row.get("plan_id", ""))))
