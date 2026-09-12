"""Deterministic process-local producer rate and concurrency gate tests."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, fields, replace
from datetime import UTC, datetime
import math
from threading import Barrier

import pytest

import threatfusion.models.network_inference as inference
from threatfusion.api.producer_admission import (
    REGISTERED_UNSW_PRODUCER_ID,
    REGISTERED_UNSW_PRODUCER_TYPE,
    REGISTERED_UNSW_SOURCE_CONTRACT,
    REGISTERED_UNSW_URI_SAN,
    TLS_VERSION,
    AdmittedProducer,
    CertificateRegistry,
    CertificateRegistryRecord,
    PeerCertificateEvidence,
    ProducerAdmissionError,
)
from threatfusion.api.producer_execution_gates import (
    GATE_ACCEPTED,
    GATE_RATE_LIMITED,
    GATE_SERVER_BUSY,
    PRODUCER_GATE_SCHEMA_VERSION,
    RATE_REFILL_INTERVAL_NS,
    ProducerExecutionGateError,
    ProducerExecutionGates,
    ProducerExecutionLease,
    ProducerGateConfiguration,
)
from threatfusion.db.alert_repository import AlertCandidateRepository
from threatfusion.db.producer_replay_journal import ProducerReplayJournal

FINGERPRINT = "a" * 64


class FakeMonotonicClock:
    def __init__(self, value: object = 0) -> None:
        self.value = value

    def __call__(self):
        if isinstance(self.value, BaseException):
            raise self.value
        return self.value

    def advance(self, nanoseconds: int) -> None:
        assert type(self.value) is int
        self.value += nanoseconds


@pytest.fixture(autouse=True)
def downstream_spies(monkeypatch):
    """Gate decisions must not themselves invoke replay, prediction, or persistence."""
    calls: list[str] = []

    def forbidden(name):
        def call(*args, **kwargs):
            calls.append(name)
            pytest.fail(f"producer execution gate invoked {name}")

        return call

    monkeypatch.setattr(ProducerReplayJournal, "claim", forbidden("replay"))
    monkeypatch.setattr(inference._FrozenNetworkPredictor, "infer", forbidden("predictor"))
    monkeypatch.setattr(AlertCandidateRepository, "insert", forbidden("repository"))
    yield
    assert calls == []


def admitted_producer(producer_id: str = REGISTERED_UNSW_PRODUCER_ID) -> AdmittedProducer:
    return AdmittedProducer(
        producer_id,
        FINGERPRINT,
        (REGISTERED_UNSW_SOURCE_CONTRACT,),
    )


def gate(
    clock: FakeMonotonicClock | None = None,
) -> tuple[ProducerExecutionGates, FakeMonotonicClock]:
    selected_clock = clock or FakeMonotonicClock()
    return ProducerExecutionGates(monotonic_ns=selected_clock), selected_clock


def acquire_and_release(instance: ProducerExecutionGates):
    decision = instance.acquire(admitted_producer())
    if decision.lease is not None:
        instance.release(decision.lease)
    return decision


def test_initial_burst_is_exactly_two_attempts():
    instance, _ = gate()

    assert acquire_and_release(instance).disposition == GATE_ACCEPTED
    assert acquire_and_release(instance).disposition == GATE_ACCEPTED
    assert instance.acquire(admitted_producer()).disposition == GATE_RATE_LIMITED

    snapshot = instance.snapshot()
    assert (snapshot.accepted_count, snapshot.rate_limited_count) == (2, 1)
    assert (snapshot.available_token_count, snapshot.rate_credit_nanoseconds) == (0, 0)


def test_exact_refill_boundary_at_ten_seconds():
    instance, clock = gate()
    acquire_and_release(instance)
    acquire_and_release(instance)

    clock.advance(RATE_REFILL_INTERVAL_NS - 1)
    assert instance.acquire(admitted_producer()).disposition == GATE_RATE_LIMITED
    clock.advance(1)
    assert acquire_and_release(instance).disposition == GATE_ACCEPTED


def test_partial_intervals_accumulate_without_creating_complete_token():
    instance, clock = gate()
    acquire_and_release(instance)
    acquire_and_release(instance)

    clock.advance(4_000_000_000)
    assert instance.acquire(admitted_producer()).disposition == GATE_RATE_LIMITED
    assert instance.snapshot().available_token_count == 0
    clock.advance(5_999_999_999)
    assert instance.acquire(admitted_producer()).disposition == GATE_RATE_LIMITED
    clock.advance(1)
    assert acquire_and_release(instance).disposition == GATE_ACCEPTED


def test_long_interval_never_refills_above_capacity_two():
    instance, clock = gate()
    acquire_and_release(instance)
    acquire_and_release(instance)
    clock.advance(10_000 * RATE_REFILL_INTERVAL_NS)

    assert instance.snapshot().available_token_count == 0
    assert acquire_and_release(instance).disposition == GATE_ACCEPTED
    assert acquire_and_release(instance).disposition == GATE_ACCEPTED
    assert instance.acquire(admitted_producer()).disposition == GATE_RATE_LIMITED


def test_sustained_rate_is_exactly_six_refills_per_minute():
    instance, clock = gate()
    acquire_and_release(instance)
    acquire_and_release(instance)

    decisions = []
    for _ in range(6):
        clock.advance(10_000_000_000)
        decisions.append(acquire_and_release(instance).disposition)

    assert decisions == [GATE_ACCEPTED] * 6
    assert instance.acquire(admitted_producer()).disposition == GATE_RATE_LIMITED


@pytest.mark.parametrize(
    "invalid",
    [
        -1,
        9_223_372_036_854_775_808,
        1.5,
        math.nan,
        math.inf,
        -math.inf,
        True,
        None,
        RuntimeError("clock failed"),
    ],
)
def test_invalid_negative_noninteger_or_failing_clock_fails_closed(invalid):
    instance, _ = gate(FakeMonotonicClock(invalid))
    before = instance.snapshot()

    with pytest.raises(ProducerExecutionGateError, match="^monotonic_clock_invalid$"):
        instance.acquire(admitted_producer())

    after = instance.snapshot()
    assert after.available_token_count == before.available_token_count
    assert after.rate_credit_nanoseconds == before.rate_credit_nanoseconds
    assert (after.global_active_count, after.producer_active_count) == (0, 0)
    assert after.clock_rejected_count == before.clock_rejected_count + 1


def test_backward_clock_fails_closed_without_adding_capacity():
    instance, clock = gate(FakeMonotonicClock(100))
    first = instance.acquire(admitted_producer())
    instance.release(first.lease)
    before = instance.snapshot()
    clock.value = 99

    with pytest.raises(ProducerExecutionGateError, match="^monotonic_clock_invalid$"):
        instance.acquire(admitted_producer())

    after = instance.snapshot()
    assert after.rate_credit_nanoseconds == before.rate_credit_nanoseconds
    assert after.clock_rejected_count == before.clock_rejected_count + 1


def test_unknown_producer_does_not_read_clock_or_create_state():
    clock = FakeMonotonicClock(RuntimeError("must not be read"))
    instance, _ = gate(clock)
    before = instance.snapshot()

    with pytest.raises(ProducerExecutionGateError, match="^producer_not_admitted$"):
        instance.acquire(admitted_producer("attacker-controlled-producer"))

    assert instance.snapshot() == before


def test_authentication_or_admission_failure_allocates_no_gate_state():
    instance, _ = gate()
    before = instance.snapshot()

    for invalid in (object(), AdmittedProducer("wrong", FINGERPRINT, ())):
        with pytest.raises(ProducerExecutionGateError, match="^producer_not_admitted$"):
            instance.acquire(invalid)

    assert instance.snapshot() == before


def test_certificate_authentication_failure_never_reaches_or_changes_gate_state():
    instance, _ = gate()
    before = instance.snapshot()
    registry = CertificateRegistry(
        (
            CertificateRegistryRecord(
                producer_id=REGISTERED_UNSW_PRODUCER_ID,
                producer_type=REGISTERED_UNSW_PRODUCER_TYPE,
                uri_san=REGISTERED_UNSW_URI_SAN,
                certificate_sha256=FINGERPRINT,
                enabled=True,
                revoked=False,
                not_before=datetime(2026, 9, 11, tzinfo=UTC),
                not_after=datetime(2026, 9, 13, tzinfo=UTC),
                allowed_source_contracts=(REGISTERED_UNSW_SOURCE_CONTRACT,),
            ),
        )
    )
    peer = PeerCertificateEvidence(
        TLS_VERSION,
        True,
        True,
        "f" * 64,
        (REGISTERED_UNSW_URI_SAN,),
    )

    with pytest.raises(ProducerAdmissionError, match="^request_unauthorized$"):
        registry.authenticate(
            peer,
            trusted_now=datetime(2026, 9, 12, tzinfo=UTC),
        )

    assert instance.snapshot() == before


def test_one_global_and_per_producer_request_is_active_with_no_queue():
    instance, _ = gate()
    first = instance.acquire(admitted_producer())
    second = instance.acquire(admitted_producer())

    assert first.disposition == GATE_ACCEPTED
    assert second == replace(second, disposition=GATE_SERVER_BUSY)
    assert second.lease is None
    snapshot = instance.snapshot()
    assert (snapshot.global_active_count, snapshot.producer_active_count) == (1, 1)
    instance.release(first.lease)


def test_threaded_barrier_has_exactly_one_concurrency_winner_without_sleep():
    instance, _ = gate()
    barrier = Barrier(2)

    def compete():
        barrier.wait()
        return instance.acquire(admitted_producer())

    with ThreadPoolExecutor(max_workers=2) as executor:
        decisions = list(executor.map(lambda _: compete(), range(2)))

    assert [item.disposition for item in decisions].count(GATE_ACCEPTED) == 1
    assert [item.disposition for item in decisions].count(GATE_SERVER_BUSY) == 1
    winner = next(item for item in decisions if item.lease is not None)
    instance.release(winner.lease)


def test_separate_gate_instances_have_independent_process_local_state():
    first, _ = gate()
    second, _ = gate()

    first_decision = first.acquire(admitted_producer())
    second_decision = second.acquire(admitted_producer())

    assert first_decision.disposition == second_decision.disposition == GATE_ACCEPTED
    assert first_decision.lease.gate_instance_id != second_decision.lease.gate_instance_id
    first.release(first_decision.lease)
    second.release(second_decision.lease)


def test_release_permits_later_request_after_rate_refill():
    instance, clock = gate()
    first = instance.acquire(admitted_producer())
    instance.release(first.lease)
    second = instance.acquire(admitted_producer())
    instance.release(second.lease)
    clock.advance(RATE_REFILL_INTERVAL_NS)

    later = instance.acquire(admitted_producer())

    assert later.disposition == GATE_ACCEPTED
    instance.release(later.lease)


def test_context_manager_releases_on_normal_return():
    instance, _ = gate()
    lease = instance.acquire(admitted_producer()).lease

    with instance.lease_context(lease) as active:
        assert active is lease
        assert instance.snapshot().global_active_count == 1

    assert instance.snapshot().global_active_count == 0


def test_context_manager_releases_on_exception():
    instance, _ = gate()
    lease = instance.acquire(admitted_producer()).lease

    with pytest.raises(ValueError, match="expected"):
        with instance.lease_context(lease):
            raise ValueError("expected")

    assert instance.snapshot().global_active_count == 0


def test_context_manager_rejects_foreign_lease_before_yielding():
    owner, _ = gate()
    foreign, _ = gate()
    lease = owner.acquire(admitted_producer()).lease
    entered = False

    with pytest.raises(ProducerExecutionGateError, match="^lease_not_active$"):
        with foreign.lease_context(lease):
            entered = True

    assert entered is False
    owner.release(lease)


def test_double_release_is_rejected():
    instance, _ = gate()
    lease = instance.acquire(admitted_producer()).lease
    instance.release(lease)

    with pytest.raises(ProducerExecutionGateError, match="^lease_not_active$"):
        instance.release(lease)


def test_stale_release_cannot_release_a_later_lease():
    instance, _ = gate()
    stale = instance.acquire(admitted_producer()).lease
    instance.release(stale)
    current = instance.acquire(admitted_producer()).lease

    with pytest.raises(ProducerExecutionGateError, match="^lease_not_active$"):
        instance.release(stale)

    assert instance.snapshot().global_active_count == 1
    instance.release(current)


def test_foreign_gate_rejects_another_instances_lease():
    owner, _ = gate()
    foreign, _ = gate()
    lease = owner.acquire(admitted_producer()).lease

    with pytest.raises(ProducerExecutionGateError, match="^lease_not_active$"):
        foreign.release(lease)

    owner.release(lease)


@pytest.mark.parametrize(
    "lease",
    [
        object(),
        ProducerExecutionLease(REGISTERED_UNSW_PRODUCER_ID, "not-a-uuid", "A" * 43),
        ProducerExecutionLease(
            REGISTERED_UNSW_PRODUCER_ID,
            "11111111-1111-4111-8111-111111111111",
            "é" * 43,
        ),
    ],
)
def test_forged_leases_fail_closed(lease):
    instance, _ = gate()
    with pytest.raises(ProducerExecutionGateError, match="^lease_not_active$"):
        instance.release(lease)


def test_authenticated_concurrency_rejection_consumes_rate_token():
    instance, clock = gate()
    active = instance.acquire(admitted_producer())

    assert instance.acquire(admitted_producer()).disposition == GATE_SERVER_BUSY
    instance.release(active.lease)
    assert instance.acquire(admitted_producer()).disposition == GATE_RATE_LIMITED
    clock.advance(RATE_REFILL_INTERVAL_NS)
    later = instance.acquire(admitted_producer())
    assert later.disposition == GATE_ACCEPTED
    instance.release(later.lease)


def test_arbitrary_producer_ids_cannot_grow_internal_state():
    instance, _ = gate()
    before = instance.snapshot()

    for index in range(1_000):
        with pytest.raises(ProducerExecutionGateError, match="^producer_not_admitted$"):
            instance.acquire(admitted_producer(f"arbitrary-{index}"))

    assert instance.snapshot() == before
    assert not hasattr(instance, "_producer_buckets")


def test_failures_and_reprs_are_sanitized():
    submitted = "/private/certificates/producer.pem"
    instance, _ = gate()

    with pytest.raises(ProducerExecutionGateError) as raised:
        instance.acquire(admitted_producer(submitted))

    rendered = f"{raised.value!s} {raised.value!r} {raised.value.__dict__} {instance!r}"
    assert submitted not in rendered
    assert "/private" not in rendered
    assert FINGERPRINT not in rendered


def test_successful_acquisition_only_returns_an_internal_lease():
    instance, _ = gate()
    decision = instance.acquire(admitted_producer())

    assert decision.disposition == GATE_ACCEPTED
    assert type(decision.lease) is ProducerExecutionLease
    assert FINGERPRINT not in repr(decision)
    instance.release(decision.lease)


def test_configuration_decisions_leases_and_snapshots_are_immutable_and_isolated():
    configuration = ProducerGateConfiguration()
    instance = ProducerExecutionGates(
        monotonic_ns=FakeMonotonicClock(), configuration=configuration
    )
    decision = instance.acquire(admitted_producer())
    snapshot = instance.snapshot()

    assert configuration.schema_version == PRODUCER_GATE_SCHEMA_VERSION
    assert {item.name for item in fields(snapshot)} == {
        "available_token_count",
        "rate_credit_nanoseconds",
        "global_active_count",
        "producer_active_count",
        "accepted_count",
        "rate_limited_count",
        "server_busy_count",
        "released_count",
        "clock_rejected_count",
    }
    for value, attribute in (
        (configuration, "burst_capacity"),
        (decision, "disposition"),
        (decision.lease, "ownership_token"),
        (snapshot, "accepted_count"),
    ):
        with pytest.raises(FrozenInstanceError):
            setattr(value, attribute, None)
    instance.release(decision.lease)


def test_nonexact_configuration_is_rejected():
    with pytest.raises(ProducerExecutionGateError, match="^gate_configuration_invalid$"):
        ProducerGateConfiguration(burst_capacity=3)
