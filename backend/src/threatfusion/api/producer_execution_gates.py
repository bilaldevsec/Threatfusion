"""Process-local rate and concurrency gates for an already admitted producer.

These are internal correctness controls, not an authentication boundary. The future TLS
adapter must supply an exact ``AdmittedProducer`` after certificate admission.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from threading import Lock
from typing import Callable, Iterator

from threatfusion.api.producer_admission import (
    REGISTERED_UNSW_PRODUCER_ID,
    REGISTERED_UNSW_SOURCE_CONTRACT,
    AdmittedProducer,
)

PRODUCER_GATE_SCHEMA_VERSION = "producer_execution_gates_v1"
RATE_ATTEMPTS_PER_MINUTE = 6
RATE_REFILL_INTERVAL_NS = 10_000_000_000
RATE_BURST_CAPACITY = 2
GLOBAL_CONCURRENCY_LIMIT = 1
PRODUCER_CONCURRENCY_LIMIT = 1
QUEUE_CAPACITY = 0
MAX_MONOTONIC_NS = 9_223_372_036_854_775_807

GATE_ACCEPTED = "accepted"
GATE_RATE_LIMITED = "rate_limited"
GATE_SERVER_BUSY = "server_busy"


class ProducerExecutionGateError(RuntimeError):
    """Sanitized internal gate error without submitted values or implementation details."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)

    def __repr__(self) -> str:
        return "<ProducerExecutionGateError>"


@dataclass(frozen=True, slots=True, repr=False)
class ProducerGateConfiguration:
    """Exact immutable v1 limits; arbitrary producer configuration is not supported."""

    schema_version: str = PRODUCER_GATE_SCHEMA_VERSION
    producer_ids: tuple[str, ...] = (REGISTERED_UNSW_PRODUCER_ID,)
    allowed_source_contracts: tuple[str, ...] = (REGISTERED_UNSW_SOURCE_CONTRACT,)
    rate_attempts_per_minute: int = RATE_ATTEMPTS_PER_MINUTE
    refill_interval_ns: int = RATE_REFILL_INTERVAL_NS
    burst_capacity: int = RATE_BURST_CAPACITY
    global_concurrency_limit: int = GLOBAL_CONCURRENCY_LIMIT
    producer_concurrency_limit: int = PRODUCER_CONCURRENCY_LIMIT
    queue_capacity: int = QUEUE_CAPACITY

    def __post_init__(self) -> None:
        if (
            self.schema_version != PRODUCER_GATE_SCHEMA_VERSION
            or self.producer_ids != (REGISTERED_UNSW_PRODUCER_ID,)
            or self.allowed_source_contracts != (REGISTERED_UNSW_SOURCE_CONTRACT,)
            or type(self.rate_attempts_per_minute) is not int
            or self.rate_attempts_per_minute != RATE_ATTEMPTS_PER_MINUTE
            or type(self.refill_interval_ns) is not int
            or self.refill_interval_ns != RATE_REFILL_INTERVAL_NS
            or type(self.burst_capacity) is not int
            or self.burst_capacity != RATE_BURST_CAPACITY
            or type(self.global_concurrency_limit) is not int
            or self.global_concurrency_limit != GLOBAL_CONCURRENCY_LIMIT
            or type(self.producer_concurrency_limit) is not int
            or self.producer_concurrency_limit != PRODUCER_CONCURRENCY_LIMIT
            or type(self.queue_capacity) is not int
            or self.queue_capacity != QUEUE_CAPACITY
        ):
            raise ProducerExecutionGateError("gate_configuration_invalid")

    def __repr__(self) -> str:
        return "<ProducerGateConfiguration>"


V1_PRODUCER_GATE_CONFIGURATION = ProducerGateConfiguration()


@dataclass(frozen=True, slots=True, repr=False)
class ProducerExecutionLease:
    """Opaque capability proving ownership of the sole active execution slot."""

    producer_id: str
    gate_instance_id: str
    ownership_token: str

    def __repr__(self) -> str:
        return "<ProducerExecutionLease>"


@dataclass(frozen=True, slots=True, repr=False)
class ProducerGateDecision:
    """Sanitized decision; only an accepted attempt receives an execution lease."""

    disposition: str
    lease: ProducerExecutionLease | None

    def __post_init__(self) -> None:
        if (
            type(self.disposition) is not str
            or self.disposition not in {GATE_ACCEPTED, GATE_RATE_LIMITED, GATE_SERVER_BUSY}
            or (self.disposition == GATE_ACCEPTED) != (type(self.lease) is ProducerExecutionLease)
        ):
            raise ProducerExecutionGateError("gate_decision_invalid")

    def __repr__(self) -> str:
        return "<ProducerGateDecision>"


@dataclass(frozen=True, slots=True, repr=False)
class ProducerGateSnapshot:
    """Count-only process-local state and metrics with no producer or credential data."""

    available_token_count: int
    rate_credit_nanoseconds: int
    global_active_count: int
    producer_active_count: int
    accepted_count: int
    rate_limited_count: int
    server_busy_count: int
    released_count: int
    clock_rejected_count: int

    def __repr__(self) -> str:
        return "<ProducerGateSnapshot>"


def _is_uuid4(value: object) -> bool:
    if type(value) is not str or len(value) != 36:
        return False
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError):
        return False
    return parsed.version == 4 and str(parsed) == value


def _is_ownership_token(value: object) -> bool:
    if type(value) is not str or len(value) != 43:
        return False
    try:
        decoded = base64.b64decode(value + "=", altchars=b"-_", validate=True)
    except (ValueError, UnicodeError):
        return False
    return (
        len(decoded) == 32
        and base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") == value
    )


class ProducerExecutionGates:
    """One-owner, process-local v1 rate bucket and nonqueueing concurrency gate."""

    def __init__(
        self,
        *,
        monotonic_ns: Callable[[], int] = time.monotonic_ns,
        configuration: ProducerGateConfiguration = V1_PRODUCER_GATE_CONFIGURATION,
    ) -> None:
        if (
            not callable(monotonic_ns)
            or type(configuration) is not ProducerGateConfiguration
            or configuration != V1_PRODUCER_GATE_CONFIGURATION
        ):
            raise ProducerExecutionGateError("gate_configuration_invalid")
        self._monotonic_ns = monotonic_ns
        self._configuration = configuration
        self._gate_instance_id = str(uuid.uuid4())
        self._lock = Lock()
        self._rate_credit_ns = RATE_BURST_CAPACITY * RATE_REFILL_INTERVAL_NS
        self._last_monotonic_ns: int | None = None
        self._active_token_sha256: str | None = None
        self._global_active_count = 0
        self._producer_active_count = 0
        self._accepted_count = 0
        self._rate_limited_count = 0
        self._server_busy_count = 0
        self._released_count = 0
        self._clock_rejected_count = 0

    def __repr__(self) -> str:
        return "<ProducerExecutionGates>"

    @staticmethod
    def _validate_producer(producer: object) -> None:
        if (
            type(producer) is not AdmittedProducer
            or producer.producer_id != REGISTERED_UNSW_PRODUCER_ID
            or producer.allowed_source_contracts != (REGISTERED_UNSW_SOURCE_CONTRACT,)
        ):
            raise ProducerExecutionGateError("producer_not_admitted")

    def _read_clock(self) -> int:
        try:
            value = self._monotonic_ns()
        except Exception:
            with self._lock:
                self._clock_rejected_count += 1
            raise ProducerExecutionGateError("monotonic_clock_invalid") from None
        if type(value) is not int or not 0 <= value <= MAX_MONOTONIC_NS:
            with self._lock:
                self._clock_rejected_count += 1
            raise ProducerExecutionGateError("monotonic_clock_invalid")
        return value

    def _require_active_lease(self, lease: ProducerExecutionLease) -> str:
        if (
            type(lease) is not ProducerExecutionLease
            or lease.producer_id != REGISTERED_UNSW_PRODUCER_ID
            or not _is_uuid4(lease.gate_instance_id)
            or not _is_ownership_token(lease.ownership_token)
        ):
            raise ProducerExecutionGateError("lease_not_active")
        token_sha256 = hashlib.sha256(lease.ownership_token.encode("ascii")).hexdigest()
        if (
            lease.gate_instance_id != self._gate_instance_id
            or self._active_token_sha256 is None
            or not hmac.compare_digest(self._active_token_sha256, token_sha256)
            or self._global_active_count != 1
            or self._producer_active_count != 1
        ):
            raise ProducerExecutionGateError("lease_not_active")
        return token_sha256

    def acquire(self, producer: AdmittedProducer) -> ProducerGateDecision:
        """Consume one rate token, then immediately acquire the sole execution slot."""
        self._validate_producer(producer)
        now_ns = self._read_clock()
        with self._lock:
            if self._last_monotonic_ns is None:
                self._last_monotonic_ns = now_ns
            elif now_ns < self._last_monotonic_ns:
                self._clock_rejected_count += 1
                raise ProducerExecutionGateError("monotonic_clock_invalid")
            else:
                elapsed_ns = now_ns - self._last_monotonic_ns
                maximum_credit = RATE_BURST_CAPACITY * RATE_REFILL_INTERVAL_NS
                self._rate_credit_ns = min(maximum_credit, self._rate_credit_ns + elapsed_ns)
                self._last_monotonic_ns = now_ns

            if self._rate_credit_ns < RATE_REFILL_INTERVAL_NS:
                self._rate_limited_count += 1
                return ProducerGateDecision(GATE_RATE_LIMITED, None)

            # The documented order intentionally charges authenticated busy attempts.
            self._rate_credit_ns -= RATE_REFILL_INTERVAL_NS
            if self._global_active_count or self._producer_active_count:
                self._server_busy_count += 1
                return ProducerGateDecision(GATE_SERVER_BUSY, None)

            ownership_token = secrets.token_urlsafe(32)
            self._active_token_sha256 = hashlib.sha256(ownership_token.encode("ascii")).hexdigest()
            self._global_active_count = 1
            self._producer_active_count = 1
            self._accepted_count += 1
            return ProducerGateDecision(
                GATE_ACCEPTED,
                ProducerExecutionLease(
                    REGISTERED_UNSW_PRODUCER_ID,
                    self._gate_instance_id,
                    ownership_token,
                ),
            )

    def release(self, lease: ProducerExecutionLease) -> None:
        """Release exactly once using the exact active capability from this gate instance."""
        with self._lock:
            self._require_active_lease(lease)
            self._active_token_sha256 = None
            self._global_active_count = 0
            self._producer_active_count = 0
            self._released_count += 1

    @contextmanager
    def lease_context(self, lease: ProducerExecutionLease) -> Iterator[ProducerExecutionLease]:
        """Release an active lease through a finally path on return or exception."""
        with self._lock:
            self._require_active_lease(lease)
        try:
            yield lease
        finally:
            self.release(lease)

    def snapshot(self) -> ProducerGateSnapshot:
        """Return immutable counts without reading the clock or exposing identity state."""
        with self._lock:
            return ProducerGateSnapshot(
                available_token_count=self._rate_credit_ns // RATE_REFILL_INTERVAL_NS,
                rate_credit_nanoseconds=self._rate_credit_ns,
                global_active_count=self._global_active_count,
                producer_active_count=self._producer_active_count,
                accepted_count=self._accepted_count,
                rate_limited_count=self._rate_limited_count,
                server_busy_count=self._server_busy_count,
                released_count=self._released_count,
                clock_rejected_count=self._clock_rejected_count,
            )
