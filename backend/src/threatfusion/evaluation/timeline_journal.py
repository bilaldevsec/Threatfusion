"""Read-only grouping of consecutive timeline rows by actor.

The returned groups point at the original records. Hashes on those records
are not rewritten.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any


def timeline_actor(event: Mapping[str, Any] | None) -> str:
    if not isinstance(event, Mapping):
        return "stored-flow"
    for key in ("actor_id", "actor", "operator_id", "src_entity_id"):
        value = event.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return "stored-flow"


def group_consecutive_timeline_by_actor(
    events: Sequence[Mapping[str, Any]] | None,
) -> list[dict[str, Any]]:
    """Group only consecutive rows that share an actor."""
    groups: list[dict[str, Any]] = []
    for event in events or ():
        actor = timeline_actor(event if isinstance(event, Mapping) else None)
        if groups and groups[-1]["actor"] == actor:
            groups[-1]["events"].append(event)
            continue
        groups.append({"actor": actor, "events": [event]})
    return groups
