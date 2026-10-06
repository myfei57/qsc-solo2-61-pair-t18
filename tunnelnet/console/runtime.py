"""Wiring of every control component behind the console."""

from __future__ import annotations

from tunnelnet.access import AccessService
from tunnelnet.audit import AuditRegistry, MarkSet
from tunnelnet.cabin import PartitionTable, PowerBook, Registry as CabinRegistry, SuppressionLog
from tunnelnet.cable import CableRegistry, MovingAverage
from tunnelnet.drain import DrainService, PumpUnit
from tunnelnet.env import Environment
from tunnelnet.fire import FireService, Policy
from tunnelnet.ns import Registry as NamespaceRegistry
from tunnelnet.patrol import PatrolService
from tunnelnet.quota import QuotaService
from tunnelnet.store import Store
from tunnelnet.vent import VentService

DEFAULT_ZONES = ("zone-1", "zone-2", "zone-3")
DEFAULT_THRESHOLD = 75.0
DEFAULT_WINDOW_SECONDS = 30.0
DEFAULT_REQUIRED_REPORTS = 2


class Runtime:
    """Owns one instance of each control component for a single store."""

    def __init__(self, store: Store) -> None:
        self.store = store
        self.namespaces = NamespaceRegistry()
        self.cabins = CabinRegistry()
        self.partitions = PartitionTable()
        self.filter = MovingAverage(3)
        self.cables = CableRegistry()
        self.env = Environment(self.filter, self.partitions, DEFAULT_THRESHOLD)
        self.access = AccessService(store, self.cabins)
        self.pump = PumpUnit()
        self.drain = DrainService(self.cabins, self.pump, store)
        self.ventilation = VentService()
        self.suppression = SuppressionLog()
        self.dedupe = MarkSet()
        self.audit = AuditRegistry()
        self.fire = FireService.with_outputs(
            store,
            store,
            self.ventilation,
            self.suppression,
            DEFAULT_ZONES,
            audit=self.audit,
            policy=Policy(DEFAULT_WINDOW_SECONDS, DEFAULT_REQUIRED_REPORTS),
            deduper=self.dedupe,
        )
        self.patrol = PatrolService(self.cabins)
        self.power_book = PowerBook()
        self.quota = QuotaService(self.cabins, self.power_book)
