"""Smoke confirmation window, fire linkage and audit de-duplication."""

from .adjudication import (
    Case,
    Decision,
    Policy,
    State,
    Trigger,
    adjudicate,
    case_id_for,
    expire,
)
from .linkage import (
    DamperStore,
    Linkage,
    LinkageError,
    LinkageStep,
    Suppressor,
    VentStopper,
    escalation_steps,
)
from .model import DamperState, Detector
from .persistence import (
    LinkageRecord,
    delete_case,
    linkage_exists,
    live_cases,
    load_case,
    load_decisions,
    load_linkages,
    save_case,
    save_decision,
    save_linkage,
)
from .report import FireReport
from .service import AuditSink, FireService, utc_now
from .zone import activation_order, adjacent_zones

__all__ = [
    "AuditSink",
    "Case",
    "DamperState",
    "DamperStore",
    "Decision",
    "Detector",
    "FireReport",
    "FireService",
    "Linkage",
    "LinkageError",
    "LinkageRecord",
    "LinkageStep",
    "Policy",
    "State",
    "Suppressor",
    "Trigger",
    "VentStopper",
    "activation_order",
    "adjacent_zones",
    "adjudicate",
    "case_id_for",
    "delete_case",
    "escalation_steps",
    "expire",
    "linkage_exists",
    "live_cases",
    "load_case",
    "load_decisions",
    "load_linkages",
    "save_case",
    "save_decision",
    "save_linkage",
    "utc_now",
]
