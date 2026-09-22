"""Bounded per-alert analyst workflow and process-local authorization contract."""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID, uuid4

from threatfusion.schemas.alert_candidate import AlertCandidate

ANALYST_STATE_SCHEMA_VERSION = "analyst_state_v1"
ANALYST_TRANSITION_SCHEMA_VERSION = "analyst_transition_v1"
ANALYST_ROLES = frozenset({"viewer", "analyst"})
ANALYST_STATES = frozenset({"new", "in_review", "closed", "escalated"})
MAX_ANALYST_ACTOR_ID_BYTES = 64
MAX_ANALYST_RATIONALE_BYTES = 512

_ACTOR_ID = re.compile(r"[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?\Z")
_ALERT_ID = re.compile(r"alert_candidate_v1:[0-9a-f]{64}\Z")
_TRANSITIONS = {
    ("new", "in_review"),
    ("in_review", "closed"),
    ("in_review", "escalated"),
}


class AnalystStateError(RuntimeError):
    """Sanitized workflow, authorization, or persistence error."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def is_alert_candidate_id(value: object) -> bool:
    return type(value) is str and _ALERT_ID.fullmatch(value) is not None


def canonical_uuid4(value: object) -> bool:
    if type(value) is not str:
        return False
    try:
        parsed = UUID(value)
        return parsed.version == 4 and str(parsed) == value
    except (AttributeError, ValueError):
        return False


def valid_actor_id(value: object) -> bool:
    return (
        type(value) is str
        and _ACTOR_ID.fullmatch(value) is not None
        and len(value.encode("utf-8")) <= MAX_ANALYST_ACTOR_ID_BYTES
    )


def valid_rationale(value: object) -> bool:
    if type(value) is not str or value != value.strip() or not value.isprintable():
        return False
    try:
        return 0 < len(value.encode("utf-8")) <= MAX_ANALYST_RATIONALE_BYTES
    except UnicodeEncodeError:
        return False


def is_utc(value: object) -> bool:
    return (
        type(value) is datetime
        and value.tzinfo is not None
        and value.utcoffset() is not None
        and value.utcoffset().total_seconds() == 0
    )


@dataclass(frozen=True, slots=True)
class AnalystRegistryEntry:
    """One configured local authorization record."""

    actor_id: str
    role: str
    enabled: bool = True

    def __post_init__(self) -> None:
        if (
            not valid_actor_id(self.actor_id)
            or type(self.role) is not str
            or self.role not in ANALYST_ROLES
            or type(self.enabled) is not bool
        ):
            raise AnalystStateError("analyst_registry_entry_invalid")


@dataclass(frozen=True, slots=True, repr=False)
class AnalystCapability:
    """Process-local capability issued for a trusted upstream identity."""

    actor_id: str
    role: str
    _registry_id: str
    _token: bytes

    def __repr__(self) -> str:
        return "<AnalystCapability>"


class AnalystAuthorizationRegistry:
    """Fixed allowlist; upstream authentication must supply the asserted actor identity."""

    def __init__(self, entries: tuple[AnalystRegistryEntry, ...]) -> None:
        if (
            type(entries) is not tuple
            or not entries
            or any(type(entry) is not AnalystRegistryEntry for entry in entries)
        ):
            raise AnalystStateError("analyst_registry_invalid")
        by_actor = {entry.actor_id: entry for entry in entries}
        if len(by_actor) != len(entries):
            raise AnalystStateError("analyst_registry_invalid")
        self._entries = by_actor
        self._registry_id = str(uuid4())
        self._secret = secrets.token_bytes(32)

    def _signature(self, actor_id: str, role: str) -> bytes:
        message = f"{self._registry_id}\0{actor_id}\0{role}".encode("utf-8")
        return hmac.new(self._secret, message, hashlib.sha256).digest()

    def issue_for_trusted_actor(self, actor_id: str) -> AnalystCapability:
        """Issue only after an external trusted boundary has authenticated this actor ID."""
        if not valid_actor_id(actor_id):
            raise AnalystStateError("analyst_not_authorized")
        entry = self._entries.get(actor_id)
        if entry is None or not entry.enabled:
            raise AnalystStateError("analyst_not_authorized")
        return AnalystCapability(
            actor_id=entry.actor_id,
            role=entry.role,
            _registry_id=self._registry_id,
            _token=self._signature(entry.actor_id, entry.role),
        )

    def require_read(self, capability: AnalystCapability) -> str:
        return self._require(capability, transition=False)

    def require_transition(self, capability: AnalystCapability) -> str:
        return self._require(capability, transition=True)

    def _require(self, capability: AnalystCapability, *, transition: bool) -> str:
        if (
            type(capability) is not AnalystCapability
            or not valid_actor_id(capability.actor_id)
            or type(capability.role) is not str
            or capability.role not in ANALYST_ROLES
            or type(capability._registry_id) is not str
            or type(capability._token) is not bytes
        ):
            raise AnalystStateError("analyst_not_authorized")
        entry = self._entries.get(capability.actor_id)
        expected = self._signature(capability.actor_id, capability.role)
        if (
            capability._registry_id != self._registry_id
            or entry is None
            or not entry.enabled
            or entry.role != capability.role
            or not hmac.compare_digest(capability._token, expected)
            or (transition and capability.role != "analyst")
        ):
            raise AnalystStateError("analyst_not_authorized")
        return capability.actor_id


@dataclass(frozen=True, slots=True)
class AnalystStateSnapshot:
    alert_candidate_id: str
    state: str
    version: int
    updated_at: datetime | None
    updated_by: str | None
    last_transition_id: str | None

    def __post_init__(self) -> None:
        if (
            not is_alert_candidate_id(self.alert_candidate_id)
            or type(self.state) is not str
            or self.state not in ANALYST_STATES
            or type(self.version) is not int
        ):
            raise AnalystStateError("analyst_state_record_invalid")
        if self.state == "new":
            valid = (
                self.version == 0
                and self.updated_at is None
                and self.updated_by is None
                and self.last_transition_id is None
            )
        else:
            expected_version = 1 if self.state == "in_review" else 2
            valid = (
                self.version == expected_version
                and is_utc(self.updated_at)
                and valid_actor_id(self.updated_by)
                and canonical_uuid4(self.last_transition_id)
            )
        if not valid:
            raise AnalystStateError("analyst_state_record_invalid")


@dataclass(frozen=True, slots=True)
class AnalystTransitionEvent:
    schema_version: str
    transition_id: str
    alert_candidate_id: str
    sequence: int
    expected_version: int
    from_state: str
    to_state: str
    actor_id: str
    rationale: str
    transitioned_at: datetime

    def __post_init__(self) -> None:
        if (
            self.schema_version != ANALYST_TRANSITION_SCHEMA_VERSION
            or not canonical_uuid4(self.transition_id)
            or not is_alert_candidate_id(self.alert_candidate_id)
            or type(self.sequence) is not int
            or type(self.expected_version) is not int
            or self.sequence != self.expected_version + 1
            or type(self.from_state) is not str
            or type(self.to_state) is not str
            or (self.from_state, self.to_state) not in _TRANSITIONS
            or self.expected_version != (0 if self.from_state == "new" else 1)
            or not valid_actor_id(self.actor_id)
            or not valid_rationale(self.rationale)
            or not is_utc(self.transitioned_at)
        ):
            raise AnalystStateError("analyst_transition_record_invalid")


@dataclass(frozen=True, slots=True)
class AnalystAlertListItem:
    candidate: AlertCandidate
    analyst_state: AnalystStateSnapshot

    def __post_init__(self) -> None:
        if (
            type(self.candidate) is not AlertCandidate
            or type(self.analyst_state) is not AnalystStateSnapshot
            or self.candidate.alert_candidate_id != self.analyst_state.alert_candidate_id
        ):
            raise AnalystStateError("analyst_alert_view_invalid")


@dataclass(frozen=True, slots=True)
class AnalystAlertDetail:
    candidate: AlertCandidate
    analyst_state: AnalystStateSnapshot
    transitions: tuple[AnalystTransitionEvent, ...]

    def __post_init__(self) -> None:
        if (
            type(self.candidate) is not AlertCandidate
            or type(self.analyst_state) is not AnalystStateSnapshot
            or type(self.transitions) is not tuple
            or any(type(event) is not AnalystTransitionEvent for event in self.transitions)
            or self.candidate.alert_candidate_id != self.analyst_state.alert_candidate_id
            or any(
                event.alert_candidate_id != self.candidate.alert_candidate_id
                for event in self.transitions
            )
        ):
            raise AnalystStateError("analyst_alert_view_invalid")


@dataclass(frozen=True, slots=True)
class AnalystTransitionResult:
    disposition: str
    reason: str
    analyst_state: AnalystStateSnapshot
    transition: AnalystTransitionEvent

    def __post_init__(self) -> None:
        expected_reasons = {
            "created": "analyst_transition_created",
            "existing": "analyst_transition_already_exists",
        }
        if (
            type(self.disposition) is not str
            or self.disposition not in expected_reasons
            or self.reason != expected_reasons[self.disposition]
            or type(self.analyst_state) is not AnalystStateSnapshot
            or type(self.transition) is not AnalystTransitionEvent
            or self.analyst_state.alert_candidate_id != self.transition.alert_candidate_id
            or self.analyst_state.version < self.transition.sequence
        ):
            raise AnalystStateError("analyst_transition_result_invalid")
