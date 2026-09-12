"""Transport-independent producer admission tests with no datasets or model artifacts."""

from __future__ import annotations

import hashlib
import io
import json
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

import threatfusion.models.network_inference as inference
from threatfusion.api.producer_admission import (
    INGEST_METHOD,
    INGEST_TARGET,
    JSON_CONTENT_TYPE,
    MAX_REQUEST_BODY_BYTES,
    MAX_RESPONSE_BYTES,
    PRODUCER_INGEST_REQUEST_SCHEMA_VERSION,
    PRODUCER_INGEST_RESPONSE_SCHEMA_VERSION,
    REGISTERED_UNSW_PRODUCER_ID,
    REGISTERED_UNSW_PRODUCER_TYPE,
    REGISTERED_UNSW_SOURCE_CONTRACT,
    REGISTERED_UNSW_URI_SAN,
    TLS_VERSION,
    CertificateRegistry,
    CertificateRegistryRecord,
    PeerCertificateEvidence,
    ProducerAdmissionError,
    ProducerRecordDisposition,
    ProducerResponse,
    ValidatedAdmissionRecord,
    admit_producer_request,
    decode_producer_envelope,
    read_bounded_body,
    serialize_producer_response,
)
from threatfusion.db.alert_repository import AlertCandidateRepository

NOW = datetime(2026, 9, 12, 12, 0, 0, tzinfo=UTC)
FINGERPRINT = "a" * 64
REQUEST_ID = "123e4567-e89b-42d3-a456-426614174000"
NONCE = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
MEMBER_DIGEST = "b" * 64


@pytest.fixture(autouse=True)
def downstream_spies(monkeypatch):
    """Every case in this module must remain before inference and persistence."""
    calls: list[str] = []

    def predictor_forbidden(*args, **kwargs):
        calls.append("predictor")
        pytest.fail("producer admission invoked the predictor")

    def repository_forbidden(*args, **kwargs):
        calls.append("repository")
        pytest.fail("producer admission invoked persistence")

    monkeypatch.setattr(inference._FrozenNetworkPredictor, "infer", predictor_forbidden)
    monkeypatch.setattr(AlertCandidateRepository, "insert", repository_forbidden)
    yield
    assert calls == []


def registry_record(**updates) -> CertificateRegistryRecord:
    values = {
        "producer_id": REGISTERED_UNSW_PRODUCER_ID,
        "producer_type": REGISTERED_UNSW_PRODUCER_TYPE,
        "uri_san": REGISTERED_UNSW_URI_SAN,
        "certificate_sha256": FINGERPRINT,
        "enabled": True,
        "revoked": False,
        "not_before": NOW - timedelta(days=1),
        "not_after": NOW + timedelta(days=1),
        "allowed_source_contracts": (REGISTERED_UNSW_SOURCE_CONTRACT,),
    }
    values.update(updates)
    return CertificateRegistryRecord(**values)


def peer(**updates) -> PeerCertificateEvidence:
    values = {
        "tls_version": TLS_VERSION,
        "chain_authenticated": True,
        "client_auth_eku": True,
        "certificate_sha256": FINGERPRINT,
        "uri_sans": (REGISTERED_UNSW_URI_SAN,),
    }
    values.update(updates)
    return PeerCertificateEvidence(**values)


def payload(**updates) -> dict[str, object]:
    value: dict[str, object] = {
        "schema_version": PRODUCER_INGEST_REQUEST_SCHEMA_VERSION,
        "producer_id": REGISTERED_UNSW_PRODUCER_ID,
        "request_id": REQUEST_ID,
        "produced_at": "2026-09-12T12:00:00Z",
        "nonce": NONCE,
        "source_contract": REGISTERED_UNSW_SOURCE_CONTRACT,
        "records": [{"source_member_sha256": MEMBER_DIGEST, "row_number": 1}],
    }
    value.update(updates)
    return value


def body_for(value: object | None = None) -> bytes:
    return json.dumps(payload() if value is None else value, separators=(",", ":")).encode()


def admit(
    body: bytes | None = None,
    *,
    registry: CertificateRegistry | None = None,
    peer_evidence: PeerCertificateEvidence | None = None,
    content_length: int | None = None,
    trusted_now: datetime = NOW,
    method: str = INGEST_METHOD,
    target: str = INGEST_TARGET,
    content_type: str = JSON_CONTENT_TYPE,
) -> ValidatedAdmissionRecord:
    accepted_body = body_for() if body is None else body
    return admit_producer_request(
        registry=registry or CertificateRegistry((registry_record(),)),
        peer=peer_evidence or peer(),
        method=method,
        target=target,
        content_type=content_type,
        content_length=len(accepted_body) if content_length is None else content_length,
        body_stream=io.BytesIO(accepted_body),
        trusted_now=trusted_now,
    )


def test_valid_envelope_produces_exact_immutable_admission_record():
    body = body_for()
    admitted = admit(body)

    assert admitted.producer_id == REGISTERED_UNSW_PRODUCER_ID
    assert admitted.credential_id == FINGERPRINT
    assert admitted.request_id == REQUEST_ID
    assert admitted.nonce_sha256 == hashlib.sha256(NONCE.encode("ascii")).hexdigest()
    assert admitted.body_sha256 == hashlib.sha256(body).hexdigest()
    assert admitted.records[0].source_member_sha256 == MEMBER_DIGEST
    assert UUID(admitted.correlation_id).version == 4
    assert admitted.correlation_id != admitted.request_id
    with pytest.raises(FrozenInstanceError):
        admitted.request_id = "changed"


def test_invalid_utf8_is_rejected():
    with pytest.raises(ProducerAdmissionError, match="invalid_utf8"):
        admit(b'\xff{"not":"utf8"}')


class RecordingStream(io.BytesIO):
    def __init__(self, value: bytes):
        super().__init__(value)
        self.requested: list[int] = []

    def read(self, size=-1):
        self.requested.append(size)
        return super().read(size)


def test_bounded_reader_rejects_truncated_body_and_never_uses_unbounded_read():
    stream = RecordingStream(b"short")
    with pytest.raises(ProducerAdmissionError, match="body_truncated"):
        read_bounded_body(stream, content_length=6)
    assert stream.requested == [6, 1]
    assert all(size > 0 for size in stream.requested)


def test_bounded_reader_rejects_declared_oversize_without_reading():
    stream = RecordingStream(b"")
    with pytest.raises(ProducerAdmissionError) as raised:
        read_bounded_body(stream, content_length=MAX_REQUEST_BODY_BYTES + 1)
    assert (raised.value.code, raised.value.status_code) == ("request_too_large", 413)
    assert stream.requested == []


def test_bounded_reader_rejects_content_length_shorter_than_observed_body():
    with pytest.raises(ProducerAdmissionError, match="content_length_mismatch"):
        read_bounded_body(io.BytesIO(b"abcd"), content_length=3)


def test_bounded_reader_rejects_empty_body():
    with pytest.raises(ProducerAdmissionError, match="empty_body"):
        read_bounded_body(io.BytesIO(b""), content_length=0)


@pytest.mark.parametrize(
    "document",
    [
        b'{"schema_version":"producer_ingest_request_v1","schema_version":"again"}',
        (
            b'{"schema_version":"producer_ingest_request_v1","producer_id":"x",'
            b'"request_id":"123e4567-e89b-42d3-a456-426614174000",'
            b'"produced_at":"2026-09-12T12:00:00Z",'
            b'"nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",'
            b'"source_contract":"unsw_registered_event_ref_v1",'
            b'"records":[{"source_member_sha256":"'
            + MEMBER_DIGEST.encode()
            + b'","row_number":1,"row_number":2}]}'
        ),
    ],
    ids=("top_level", "nested"),
)
def test_duplicate_json_keys_at_every_object_level_are_rejected(document):
    with pytest.raises(ProducerAdmissionError, match="invalid_json"):
        decode_producer_envelope(document)


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_non_finite_json_numbers_are_rejected(constant):
    document = body_for(payload(records=[{"source_member_sha256": MEMBER_DIGEST, "row_number": 1}]))
    document = document[:-1] + f',"extra":{constant}}}'.encode()
    with pytest.raises(ProducerAdmissionError, match="invalid_json"):
        decode_producer_envelope(document)


def test_excessive_json_depth_is_rejected_before_schema_validation():
    with pytest.raises(ProducerAdmissionError, match="json_depth_exceeded"):
        decode_producer_envelope(b"[[[[[]]]]]")


@pytest.mark.parametrize(
    "value",
    [
        lambda item: {key: value for key, value in item.items() if key != "nonce"},
        lambda item: item | {"unknown": "field"},
        lambda item: item | {"records": "wrong"},
        lambda item: item | {"records": [{"source_member_sha256": MEMBER_DIGEST}]},
        lambda item: item
        | {"records": [{"source_member_sha256": MEMBER_DIGEST, "row_number": 1, "unknown": 1}]},
    ],
    ids=("missing", "unknown", "wrong_type", "record_missing", "record_unknown"),
)
def test_missing_unknown_and_wrongly_typed_fields_are_rejected(value):
    with pytest.raises(ProducerAdmissionError):
        decode_producer_envelope(body_for(value(payload())))


def test_boolean_cannot_masquerade_as_row_integer():
    with pytest.raises(ProducerAdmissionError, match="record_invalid"):
        decode_producer_envelope(
            body_for(payload(records=[{"source_member_sha256": MEMBER_DIGEST, "row_number": True}]))
        )


@pytest.mark.parametrize(
    ("update", "code"),
    [
        ({"schema_version": "producer_ingest_request_v2"}, "schema_version_unsupported"),
        ({"source_contract": "a" * 65}, "source_contract_invalid"),
    ],
)
def test_unsupported_schema_and_oversized_source_versions_are_rejected(update, code):
    with pytest.raises(ProducerAdmissionError, match=code):
        decode_producer_envelope(body_for(payload(**update)))


@pytest.mark.parametrize(
    ("update", "code"),
    [
        ({"produced_at": "2026-09-12T12:00:00+00:00"}, "request_time_invalid"),
        ({"nonce": "short"}, "nonce_invalid"),
        ({"request_id": "123e4567-e89b-12d3-a456-426614174000"}, "request_id_invalid"),
        ({"producer_id": "INVALID PRODUCER"}, "producer_id_invalid"),
        ({"producer_id": "\ud800"}, "producer_id_invalid"),
        ({"producer_id": "a" * 129}, "producer_id_invalid"),
        (
            {"records": [{"source_member_sha256": "A" * 64, "row_number": 1}]},
            "record_invalid",
        ),
        (
            {"records": [{"source_member_sha256": MEMBER_DIGEST, "row_number": 0}]},
            "record_invalid",
        ),
    ],
)
def test_invalid_timestamp_nonce_request_producer_and_event_identifiers(update, code):
    with pytest.raises(ProducerAdmissionError, match=code):
        decode_producer_envelope(body_for(payload(**update)))


@pytest.mark.parametrize("produced_at", ["2026-09-12T11:54:59Z", "2026-09-12T12:01:01Z"])
def test_stale_and_excessively_future_timestamps_are_rejected(produced_at):
    with pytest.raises(ProducerAdmissionError, match="request_time_invalid"):
        admit(body_for(payload(produced_at=produced_at)))


@pytest.mark.parametrize(
    ("record_updates", "peer_updates", "security_event"),
    [
        ({}, {"certificate_sha256": "f" * 64}, "authentication_failed"),
        ({"enabled": False}, {}, "credential_disabled"),
        ({"revoked": True}, {}, "credential_revoked"),
        (
            {"not_before": NOW - timedelta(days=2), "not_after": NOW},
            {},
            "credential_expired",
        ),
        (
            {"not_before": NOW + timedelta(seconds=1), "not_after": NOW + timedelta(days=1)},
            {},
            "credential_not_yet_valid",
        ),
    ],
    ids=("unknown", "disabled", "revoked", "expired", "not_yet_valid"),
)
def test_certificate_state_failures_are_uniform_to_client(
    record_updates, peer_updates, security_event
):
    selected_registry = CertificateRegistry((registry_record(**record_updates),))
    with pytest.raises(ProducerAdmissionError) as raised:
        admit(registry=selected_registry, peer_evidence=peer(**peer_updates))
    assert (raised.value.code, raised.value.status_code) == ("request_unauthorized", 401)
    assert raised.value.security_event == security_event


def test_uri_san_mismatch_fails_closed():
    with pytest.raises(ProducerAdmissionError) as raised:
        admit(peer_evidence=peer(uri_sans=("urn:threatfusion:producer:wrong",)))
    assert raised.value.code == "request_unauthorized"


def test_fingerprint_mismatch_fails_closed():
    with pytest.raises(ProducerAdmissionError) as raised:
        admit(peer_evidence=peer(certificate_sha256="c" * 64))
    assert raised.value.code == "request_unauthorized"


def test_unauthorized_source_contract_fails_closed():
    wrong = body_for(payload(source_contract="cic_registered_event_ref_v1"))
    with pytest.raises(ProducerAdmissionError) as raised:
        admit(wrong)
    assert (raised.value.code, raised.value.status_code, raised.value.security_event) == (
        "admission_rejected",
        403,
        "source_contract_denied",
    )


def test_body_producer_mismatch_is_uniformly_unauthorized():
    with pytest.raises(ProducerAdmissionError) as raised:
        admit(body_for(payload(producer_id="tf-demo-unsw-replay-02")))
    assert (raised.value.code, raised.value.security_event) == (
        "request_unauthorized",
        "producer_mismatch",
    )


def test_valid_certificate_rotation_overlap_maps_both_fingerprints():
    old = registry_record(not_after=NOW + timedelta(hours=12))
    new = registry_record(
        certificate_sha256="c" * 64,
        not_before=NOW,
        not_after=NOW + timedelta(days=2),
    )
    selected_registry = CertificateRegistry((old, new))
    assert selected_registry.authenticate(peer(), trusted_now=NOW).producer_id == (
        REGISTERED_UNSW_PRODUCER_ID
    )
    assert (
        selected_registry.authenticate(
            peer(certificate_sha256="c" * 64), trusted_now=NOW
        ).producer_id
        == REGISTERED_UNSW_PRODUCER_ID
    )


def test_certificate_rotation_overlap_above_24_hours_is_rejected():
    old = registry_record(not_after=NOW + timedelta(days=2))
    new = registry_record(
        certificate_sha256="c" * 64,
        not_before=NOW,
        not_after=NOW + timedelta(days=3),
    )
    with pytest.raises(ProducerAdmissionError, match="certificate_rotation_invalid"):
        CertificateRegistry((old, new))


def test_exact_body_digest_is_repeatable_and_changes_with_meaningful_content():
    original = body_for()
    same = bytes(bytearray(original))
    changed = body_for(payload(request_id="123e4567-e89b-42d3-a456-426614174001"))
    first = admit(original)
    retry = admit(same)
    different = admit(changed)
    assert first.body_sha256 == retry.body_sha256
    assert first.body_sha256 != different.body_sha256
    assert first.records == retry.records


def test_failures_are_sanitized_and_do_not_expose_submitted_values_or_paths():
    submitted = "/private/secret/certificate.pem"
    malformed = body_for(payload(producer_id=submitted))
    with pytest.raises(ProducerAdmissionError) as raised:
        admit(malformed)
    rendered = f"{raised.value!s} {raised.value!r} {raised.value.__dict__}"
    assert submitted not in rendered
    assert "/private" not in rendered
    assert FINGERPRINT not in rendered
    assert NONCE not in rendered
    assert raised.value.correlation_id is not None


def record_payloads(count: int) -> list[dict[str, object]]:
    return [
        {"source_member_sha256": hashlib.sha256(str(index).encode()).hexdigest(), "row_number": 1}
        for index in range(count)
    ]


def test_maximum_256_record_request_is_accepted_and_snapshotted():
    source = record_payloads(256)
    admitted = admit(body_for(payload(records=source)))
    source[0]["row_number"] = 99
    assert len(admitted.records) == 256
    assert admitted.records[0].row_number == 1


def test_257_record_request_is_rejected():
    with pytest.raises(ProducerAdmissionError, match="batch_size_invalid"):
        admit(body_for(payload(records=record_payloads(257))))


def test_duplicate_record_reference_is_rejected():
    duplicate = {"source_member_sha256": MEMBER_DIGEST, "row_number": 1}
    with pytest.raises(ProducerAdmissionError, match="duplicate_record"):
        admit(body_for(payload(records=[duplicate, duplicate.copy()])))


def test_measured_worst_case_response_size_matches_policy_and_stays_bounded():
    response = ProducerResponse(
        schema_version=PRODUCER_INGEST_RESPONSE_SCHEMA_VERSION,
        correlation_id="ffffffff-ffff-4fff-bfff-ffffffffffff",
        reason="alert_candidate_identity_conflict",
        records=tuple(
            ProducerRecordDisposition(
                record_index=index,
                disposition="outcome_unknown",
                reason="alert_candidate_identity_conflict",
            )
            for index in range(1, 257)
        ),
    )
    encoded = serialize_producer_response(response)
    assert len(encoded) == 25_142
    assert len(encoded) <= MAX_RESPONSE_BYTES
    assert encoded.endswith(b"\n")
    assert b"source_member" not in encoded
    assert b"path" not in encoded
    assert b"endpoint" not in encoded
    assert b"feature" not in encoded


def test_registry_envelope_records_and_response_are_immutable_and_sanitized():
    record = registry_record()
    selected_registry = CertificateRegistry((record,))
    envelope = decode_producer_envelope(body_for())
    response_record = ProducerRecordDisposition(1, "rejected", "request_rejected")
    response = ProducerResponse(
        PRODUCER_INGEST_RESPONSE_SCHEMA_VERSION,
        "ffffffff-ffff-4fff-bfff-ffffffffffff",
        "request_rejected",
        (response_record,),
    )
    for value in (
        record,
        selected_registry,
        envelope,
        envelope.records[0],
        response_record,
        response,
    ):
        assert "private" not in repr(value)
    with pytest.raises(FrozenInstanceError):
        record.enabled = False
    with pytest.raises(FrozenInstanceError):
        selected_registry._records = ()
    with pytest.raises(FrozenInstanceError):
        envelope.records = ()
    with pytest.raises(FrozenInstanceError):
        response.reason = "changed"


@pytest.mark.parametrize(
    "updates",
    [
        {"tls_version": "TLSv1.2"},
        {"chain_authenticated": False},
        {"client_auth_eku": False},
        {"uri_sans": ()},
        {"uri_sans": (REGISTERED_UNSW_URI_SAN, REGISTERED_UNSW_URI_SAN)},
    ],
)
def test_tls_peer_evidence_fails_closed_until_adapter_supplies_exact_v1_facts(updates):
    with pytest.raises(ProducerAdmissionError) as raised:
        admit(peer_evidence=peer(**updates))
    assert raised.value.code == "request_unauthorized"


@pytest.mark.parametrize(
    ("updates", "code"),
    [
        ({"method": "GET"}, "invalid_request_route"),
        ({"target": "/other"}, "invalid_request_route"),
        ({"content_type": "application/json; charset=utf-8"}, "content_type_invalid"),
    ],
)
def test_exact_request_representation_is_required(updates, code):
    with pytest.raises(ProducerAdmissionError, match=code):
        admit(**updates)


def test_registry_rejects_non_tuple_mutable_configuration():
    with pytest.raises(ProducerAdmissionError, match="certificate_registry_invalid"):
        CertificateRegistry([registry_record()])


def test_certificate_validity_over_90_days_is_rejected():
    with pytest.raises(ProducerAdmissionError, match="certificate_registry_invalid"):
        registry_record(not_before=NOW, not_after=NOW + timedelta(days=91))


def test_untrusted_or_non_utc_clock_fails_closed():
    with pytest.raises(ProducerAdmissionError) as raised:
        admit(trusted_now=datetime(2026, 9, 12, 12, 0, 0))
    assert raised.value.code == "request_unauthorized"


def test_content_length_boolean_is_rejected_as_wrong_type():
    with pytest.raises(ProducerAdmissionError, match="content_length_invalid"):
        admit(content_length=True)


def test_response_rejects_nonsequential_record_indexes_without_truncation():
    with pytest.raises(ProducerAdmissionError, match="response_invalid"):
        ProducerResponse(
            PRODUCER_INGEST_RESPONSE_SCHEMA_VERSION,
            "ffffffff-ffff-4fff-bfff-ffffffffffff",
            "request_rejected",
            (ProducerRecordDisposition(2, "rejected", "request_rejected"),),
        )


def test_dataclass_replace_cannot_bypass_validated_event_reference():
    reference = decode_producer_envelope(body_for()).records[0]
    with pytest.raises(ProducerAdmissionError, match="record_invalid"):
        replace(reference, row_number=True)


def test_dataclass_replace_cannot_bypass_envelope_or_admission_record_validation():
    envelope = decode_producer_envelope(body_for())
    admitted = admit()
    with pytest.raises(ProducerAdmissionError, match="envelope_schema_invalid"):
        replace(envelope, records=())
    with pytest.raises(ProducerAdmissionError, match="admission_record_invalid"):
        replace(admitted, request_id=admitted.correlation_id)
