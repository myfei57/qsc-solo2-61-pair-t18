"""Zone suppression log raised when a fire zone is activated."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Suppression:
    """One suppression action taken against a zone."""

    zone: str
    active: bool

    def as_dict(self) -> dict[str, object]:
        return {"zone": self.zone, "active": self.active}


class SuppressionLog:
    """Append only record of the zones that were suppressed and released."""

    def __init__(self) -> None:
        self._entries: list[Suppression] = []
        self._panel: set[str] = set()

    def activate(self, zone: str) -> Suppression:
        entry = Suppression(zone=zone, active=True)
        self._entries.append(entry)
        return entry

    def deactivate(self, zone: str) -> Suppression:
        """Reverse action used when a confirmed linkage is rolled back."""

        entry = Suppression(zone=zone, active=False)
        self._entries.append(entry)
        return entry

    def raise_panel_alarm(self, incident_id: str) -> None:
        self._panel.add(incident_id)
        self._entries.append(Suppression(zone=incident_id, active=True))

    def clear_panel_alarm(self, incident_id: str) -> None:
        self._panel.discard(incident_id)
        self._entries.append(Suppression(zone=incident_id, active=False))

    def panel_alarms(self) -> list[str]:
        return sorted(self._panel)

    def zones(self) -> list[str]:
        return [entry.zone for entry in self._entries]

    def active_zones(self) -> list[str]:
        """Zones currently suppressed, accounting for later deactivation."""

        active: list[str] = []
        for entry in self._entries:
            if entry.active and entry.zone not in active:
                active.append(entry.zone)
            elif not entry.active and entry.zone in active:
                active.remove(entry.zone)
        return active

    def entries(self) -> list[Suppression]:
        return list(self._entries)

    def distinct_zones(self) -> list[str]:
        seen: list[str] = []
        for zone in self.zones():
            if zone not in seen:
                seen.append(zone)
        return seen

    def count(self) -> int:
        return len(self._entries)

    def clear(self) -> None:
        self._entries = []
        self._panel = set()

    def describe(self) -> str:
        return f"suppressions={self.count()} zones={len(self.distinct_zones())}"
