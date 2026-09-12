"""Transport-independent producer admission for registered UNSW references.

Peer evidence is supplied by the future directly terminating TLS adapter. Constructing
``PeerCertificateEvidence`` is not authentication and Python object privacy is not a trust anchor.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import BinaryIO

PRODUCER_INGEST_REQUEST_SCHEMA_VERSION = "producer_ingest_request_v1"
PRODUCER_INGEST_RESPONSE_SCHEMA_VERSION = "producer_ingest_response_v1"
REGISTERED_UNSW_PRODUCER_ID = "tf-demo-unsw-replay-01"
REGISTERED_UNSW_PRODUCER_TYPE = "registered_unsw_replay_v1"
REGISTERED_UNSW_SOURCE_CONTRACT = "unsw_registered_event_ref_v1"
REGISTERED_UNSW_URI_SAN = f"urn:threatfusion:producer:{REGISTERED_UNSW_PRODUCER_ID}"
INGEST_METHOD = "POST"
INGEST_TARGET = "/v1/ingest/unsw-registered"
JSON_CONTENT_TYPE = "application/json"
TLS_VERSION = "TLSv1.3"

MAX_REQUEST_BODY_BYTES = 131_072
MAX_JSON_DEPTH = 4
MAX_RECORDS = 256
MAX_ROW_NUMBER = 9_223_372_036_854_775_807
MAX_CERTIFICATE_VALIDITY = timedelta(days=90)
MAX_CERTIFICATE_ROTATION_OVERLAP = timedelta(hours=24)
MAX_RESPONSE_BYTES = 65_536
BODY_READ_CHUNK_BYTES = 8_192

_PRODUCER_ID = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,126}[a-z0-9])?\Z")
_IDENTIFIER = re.compile(r"[a-z0-9](?:[a-z0-9_-]{0,62}[a-z0-9])?\Z")
_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_NONCE = re.compile(r"[A-Za-z0-9_-]{43}\Z")
_UTC_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
_ENVELOPE_KEYS = frozenset(
    {
        "schema_version",
        "producer_id",
        "request_id",
        "produced_at",
        "nonce",
        "source_contract",
        "records",
    }
)
_RECORD_KEYS = frozenset({"source_member_sha256", "row_number"})

RESPONSE_DISPOSITIONS = frozenset(
    {"created", "existing", "not_actionable", "rejected", "duplicate", "outcome_unknown"}
)
RESPONSE_REASONS = frozenset(
    {
        "request_completed",
        "request_rejected",
        "request_in_progress",
        "request_replay_rejected",
        "outcome_unknown",
        "alert_candidate_created",
        "alert_candidate_already_exists",
        "alert_candidate_identity_conflict",
        "inference_not_actionable",
        "registered_event_invalid",
        "registered_event_unavailable",
        "registered_event_rejected",
    }
)


class ProducerAdmissionError(RuntimeError):
    """Sanitized error with separate client and allowlisted security dispositions."""

    def __init__(
        self,
        code: str,
        *,
        status_code: int = 400,
        security_event: str = "invalid_request",
        correlation_id: str | None = None,
    ) -> None:
        self.code = code
        self.status_code = status_code
        self.security_event = security_event
        self.correlation_id = correlation_id
        super().__init__(code)

    def __repr__(self) -> str:
        return "<ProducerAdmissionError>"

    def for_attempt(self, correlation_id: str) -> ProducerAdmissionError:
        return ProducerAdmissionError(
            self.code,
            status_code=self.status_code,
            security_event=self.security_event,
            correlation_id=correlation_id,
        )


def _fail(
    code: str,
    *,
    status_code: int = 400,
    security_event: str = "invalid_request",
) -> ProducerAdmissionError:
    return ProducerAdmissionError(code, status_code=status_code, security_event=security_event)


def _is_plain_utc(value: object) -> bool:
    return type(value) is datetime and value.tzinfo is UTC


def _is_sha256(value: object) -> bool:
    return type(value) is str and _LOWER_SHA256.fullmatch(value) is not None


def _is_uuid4(value: object) -> bool:
    if type(value) is not str or len(value) != 36:
        return False
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError):
        return False
    return parsed.version == 4 and str(parsed) == value


def _is_nonce(value: object) -> bool:
    if type(value) is not str or _NONCE.fullmatch(value) is None:
        return False
    try:
        decoded = base64.b64decode(value + "=", altchars=b"-_", validate=True)
    except (ValueError, TypeError):
        return False
    return len(decoded) == 32 and base64.urlsafe_b64encode(decoded).rstrip(b"=").decode() == value


def _parse_timestamp(value: object) -> datetime:
    if type(value) is not str or _UTC_TIMESTAMP.fullmatch(value) is None:
        raise _fail("request_time_invalid")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError:
        raise _fail("request_time_invalid") from None


@dataclass(frozen=True, slots=True, repr=False)
class CertificateRegistryRecord:
    """One deployment-approved certificate mapping; it contains no certificate bytes."""

    producer_id: str
    producer_type: str
    uri_san: str
    certificate_sha256: str
    enabled: bool
    revoked: bool
    not_before: datetime
    not_after: datetime
    allowed_source_contracts: tuple[str, ...]

    def __post_init__(self) -> None:
        if (
            self.producer_id != REGISTERED_UNSW_PRODUCER_ID
            or self.producer_type != REGISTERED_UNSW_PRODUCER_TYPE
            or self.uri_san != REGISTERED_UNSW_URI_SAN
            or not _is_sha256(self.certificate_sha256)
            or type(self.enabled) is not bool
            or type(self.revoked) is not bool
            or not _is_plain_utc(self.not_before)
            or not _is_plain_utc(self.not_after)
            or self.not_before >= self.not_after
            or self.not_after - self.not_before > MAX_CERTIFICATE_VALIDITY
            or type(self.allowed_source_contracts) is not tuple
            or self.allowed_source_contracts != (REGISTERED_UNSW_SOURCE_CONTRACT,)
        ):
            raise _fail("certificate_registry_invalid", security_event="registry_invalid")

    def __repr__(self) -> str:
        return "<CertificateRegistryRecord>"


@dataclass(frozen=True, slots=True, repr=False)
class PeerCertificateEvidence:
    """Facts asserted by the future TLS adapter, not independently authenticated here."""

    tls_version: str
    chain_authenticated: bool
    client_auth_eku: bool
    certificate_sha256: str
    uri_sans: tuple[str, ...]

    def __repr__(self) -> str:
        return "<PeerCertificateEvidence>"


@dataclass(frozen=True, slots=True, repr=False)
class AdmittedProducer:
    """Current registry decision for one TLS-authenticated certificate."""

    producer_id: str
    credential_id: str
    allowed_source_contracts: tuple[str, ...]

    def __repr__(self) -> str:
        return "<AdmittedProducer>"


@dataclass(frozen=True, slots=True, repr=False, init=False)
class CertificateRegistry:
    """Immutable, exact v1 certificate allowlist with bounded rotation overlap."""

    _records: tuple[CertificateRegistryRecord, ...]

    def __init__(self, records: tuple[CertificateRegistryRecord, ...]) -> None:
        if (
            type(records) is not tuple
            or not records
            or any(type(record) is not CertificateRegistryRecord for record in records)
        ):
            raise _fail("certificate_registry_invalid", security_event="registry_invalid")
        fingerprints = {record.certificate_sha256 for record in records}
        if len(fingerprints) != len(records):
            raise _fail("certificate_registry_invalid", security_event="registry_invalid")
        active = tuple(record for record in records if record.enabled and not record.revoked)
        if len(active) > 2:
            raise _fail("certificate_rotation_invalid", security_event="registry_invalid")
        if len(active) == 2:
            overlap = min(record.not_after for record in active) - max(
                record.not_before for record in active
            )
            if overlap > MAX_CERTIFICATE_ROTATION_OVERLAP:
                raise _fail("certificate_rotation_invalid", security_event="registry_invalid")
        object.__setattr__(self, "_records", tuple(records))

    def __repr__(self) -> str:
        return "<CertificateRegistry>"

    def authenticate(
        self, peer: PeerCertificateEvidence, *, trusted_now: datetime
    ) -> AdmittedProducer:
        if not _is_plain_utc(trusted_now):
            raise _fail(
                "request_unauthorized", status_code=401, security_event="authentication_failed"
            )
        if (
            type(peer) is not PeerCertificateEvidence
            or peer.tls_version != TLS_VERSION
            or peer.chain_authenticated is not True
            or peer.client_auth_eku is not True
            or not _is_sha256(peer.certificate_sha256)
            or type(peer.uri_sans) is not tuple
            or len(peer.uri_sans) != 1
            or type(peer.uri_sans[0]) is not str
        ):
            raise _fail(
                "request_unauthorized", status_code=401, security_event="authentication_failed"
            )
        matched = None
        for record in self._records:
            if hmac.compare_digest(record.certificate_sha256, peer.certificate_sha256):
                matched = record
        if matched is None:
            raise _fail(
                "request_unauthorized", status_code=401, security_event="authentication_failed"
            )
        if not matched.enabled:
            raise _fail(
                "request_unauthorized", status_code=401, security_event="credential_disabled"
            )
        if matched.revoked:
            raise _fail(
                "request_unauthorized", status_code=401, security_event="credential_revoked"
            )
        if trusted_now < matched.not_before:
            raise _fail(
                "request_unauthorized", status_code=401, security_event="credential_not_yet_valid"
            )
        if trusted_now >= matched.not_after:
            raise _fail(
                "request_unauthorized", status_code=401, security_event="credential_expired"
            )
        if peer.uri_sans != (matched.uri_san,):
            raise _fail(
                "request_unauthorized", status_code=401, security_event="authentication_failed"
            )
        return AdmittedProducer(
            matched.producer_id,
            matched.certificate_sha256,
            matched.allowed_source_contracts,
        )


@dataclass(frozen=True, slots=True, repr=False)
class ProducerEventReference:
    """Validated registered-member reference, not yet a manifest-proven event identity."""

    source_member_sha256: str
    row_number: int

    def __post_init__(self) -> None:
        if (
            not _is_sha256(self.source_member_sha256)
            or type(self.row_number) is not int
            or not 1 <= self.row_number <= MAX_ROW_NUMBER
        ):
            raise _fail("record_invalid")

    def __repr__(self) -> str:
        return "<ProducerEventReference>"


@dataclass(frozen=True, slots=True, repr=False)
class ProducerEnvelope:
    """Immutable exact v1 envelope created only after strict JSON decoding."""

    schema_version: str
    producer_id: str
    request_id: str
    produced_at: datetime
    nonce: str
    source_contract: str
    records: tuple[ProducerEventReference, ...]

    def __post_init__(self) -> None:
        if (
            self.schema_version != PRODUCER_INGEST_REQUEST_SCHEMA_VERSION
            or type(self.producer_id) is not str
            or _PRODUCER_ID.fullmatch(self.producer_id) is None
            or len(self.producer_id) > 128
            or not _is_uuid4(self.request_id)
            or not _is_plain_utc(self.produced_at)
            or not _is_nonce(self.nonce)
            or type(self.source_contract) is not str
            or _IDENTIFIER.fullmatch(self.source_contract) is None
            or len(self.source_contract) > 64
            or type(self.records) is not tuple
            or not 1 <= len(self.records) <= MAX_RECORDS
            or any(type(record) is not ProducerEventReference for record in self.records)
            or len({(record.source_member_sha256, record.row_number) for record in self.records})
            != len(self.records)
        ):
            raise _fail("envelope_schema_invalid")

    def __repr__(self) -> str:
        return "<ProducerEnvelope>"


@dataclass(frozen=True, slots=True, repr=False)
class ValidatedAdmissionRecord:
    """Exact replay-journal input; raw body and nonce are deliberately absent."""

    correlation_id: str
    producer_id: str
    credential_id: str
    request_id: str
    produced_at: datetime
    received_at: datetime
    nonce_sha256: str
    body_sha256: str
    method: str
    target: str
    content_type: str
    content_length: int
    source_contract: str
    records: tuple[ProducerEventReference, ...]

    def __post_init__(self) -> None:
        if (
            not _is_uuid4(self.correlation_id)
            or self.producer_id != REGISTERED_UNSW_PRODUCER_ID
            or not _is_sha256(self.credential_id)
            or not _is_uuid4(self.request_id)
            or self.correlation_id == self.request_id
            or not _is_plain_utc(self.produced_at)
            or not _is_plain_utc(self.received_at)
            or not _is_sha256(self.nonce_sha256)
            or not _is_sha256(self.body_sha256)
            or self.method != INGEST_METHOD
            or self.target != INGEST_TARGET
            or self.content_type != JSON_CONTENT_TYPE
            or type(self.content_length) is not int
            or not 1 <= self.content_length <= MAX_REQUEST_BODY_BYTES
            or self.source_contract != REGISTERED_UNSW_SOURCE_CONTRACT
            or type(self.records) is not tuple
            or not 1 <= len(self.records) <= MAX_RECORDS
            or any(type(record) is not ProducerEventReference for record in self.records)
            or len({(record.source_member_sha256, record.row_number) for record in self.records})
            != len(self.records)
        ):
            raise _fail(
                "admission_record_invalid", status_code=500, security_event="internal_error"
            )

    def __repr__(self) -> str:
        return "<ValidatedAdmissionRecord>"


def read_bounded_body(stream: BinaryIO, *, content_length: int) -> bytes:
    """Read an exact bounded body without claiming to time out an arbitrary stream."""
    if type(content_length) is not int or content_length < 0:
        raise _fail("content_length_invalid")
    if content_length > MAX_REQUEST_BODY_BYTES:
        raise _fail("request_too_large", status_code=413, security_event="request_too_large")
    if content_length == 0:
        raise _fail("empty_body")
    read = getattr(stream, "read", None)
    if not callable(read):
        raise _fail("body_read_failed")
    chunks: list[bytes] = []
    observed = 0
    remaining = content_length
    try:
        while remaining:
            requested = min(BODY_READ_CHUNK_BYTES, remaining)
            chunk = read(requested)
            if type(chunk) is not bytes or not chunk:
                raise _fail("body_truncated", security_event="body_incomplete")
            observed += len(chunk)
            if len(chunk) > requested or observed > MAX_REQUEST_BODY_BYTES:
                raise _fail(
                    "request_too_large", status_code=413, security_event="request_too_large"
                )
            chunks.append(chunk)
            remaining -= len(chunk)
        trailing = read(1)
        if type(trailing) is not bytes:
            raise _fail("body_read_failed")
        if trailing:
            raise _fail("content_length_mismatch", security_event="body_incomplete")
    except ProducerAdmissionError:
        raise
    except Exception:
        raise _fail("body_read_failed", security_event="body_incomplete") from None
    return b"".join(chunks)


class _DuplicateKey(ValueError):
    pass


def _object_without_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise _DuplicateKey
        value[key] = item
    return value


def _finite_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError
    return parsed


def _reject_constant(value: str) -> None:
    raise ValueError


def _enforce_json_depth(text: str) -> None:
    depth = 0
    in_string = False
    escaped = False
    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
        elif character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > MAX_JSON_DEPTH:
                raise _fail("json_depth_exceeded")
        elif character in "]}":
            depth -= 1
            if depth < 0:
                raise _fail("invalid_json")


def decode_producer_envelope(body: bytes) -> ProducerEnvelope:
    """Decode strict UTF-8/JSON and validate the complete exact v1 schema."""
    if type(body) is not bytes or not body or len(body) > MAX_REQUEST_BODY_BYTES:
        raise _fail("invalid_body")
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        raise _fail("invalid_utf8") from None
    _enforce_json_depth(text)
    try:
        payload = json.loads(
            text,
            object_pairs_hook=_object_without_duplicates,
            parse_constant=_reject_constant,
            parse_float=_finite_float,
        )
    except (json.JSONDecodeError, UnicodeError, ValueError, RecursionError):
        raise _fail("invalid_json") from None
    if type(payload) is not dict or frozenset(payload) != _ENVELOPE_KEYS:
        raise _fail("envelope_schema_invalid")
    schema_version = payload["schema_version"]
    producer_id = payload["producer_id"]
    request_id = payload["request_id"]
    nonce = payload["nonce"]
    source_contract = payload["source_contract"]
    records_value = payload["records"]
    if schema_version != PRODUCER_INGEST_REQUEST_SCHEMA_VERSION:
        raise _fail("schema_version_unsupported")
    if (
        type(producer_id) is not str
        or _PRODUCER_ID.fullmatch(producer_id) is None
        or len(producer_id) > 128
    ):
        raise _fail("producer_id_invalid")
    if not _is_uuid4(request_id):
        raise _fail("request_id_invalid")
    if not _is_nonce(nonce):
        raise _fail("nonce_invalid")
    if (
        type(source_contract) is not str
        or _IDENTIFIER.fullmatch(source_contract) is None
        or len(source_contract) > 64
    ):
        raise _fail("source_contract_invalid")
    produced_at = _parse_timestamp(payload["produced_at"])
    if type(records_value) is not list or not 1 <= len(records_value) <= MAX_RECORDS:
        raise _fail("batch_size_invalid")
    records: list[ProducerEventReference] = []
    seen: set[tuple[str, int]] = set()
    for value in records_value:
        if type(value) is not dict or frozenset(value) != _RECORD_KEYS:
            raise _fail("record_invalid")
        reference = ProducerEventReference(
            source_member_sha256=value["source_member_sha256"],
            row_number=value["row_number"],
        )
        identity = (reference.source_member_sha256, reference.row_number)
        if identity in seen:
            raise _fail("duplicate_record")
        seen.add(identity)
        records.append(reference)
    return ProducerEnvelope(
        schema_version,
        producer_id,
        request_id,
        produced_at,
        nonce,
        source_contract,
        tuple(records),
    )


def _validate_request_time(produced_at: datetime, trusted_now: datetime) -> None:
    if not _is_plain_utc(trusted_now):
        raise _fail("trusted_time_unavailable", status_code=503, security_event="clock_unavailable")
    difference = produced_at - trusted_now
    if difference > timedelta(seconds=60) or difference < -timedelta(seconds=300):
        raise _fail("request_time_invalid")


def admit_producer_request(
    *,
    registry: CertificateRegistry,
    peer: PeerCertificateEvidence,
    method: str,
    target: str,
    content_type: str,
    content_length: int,
    body_stream: BinaryIO,
    trusted_now: datetime,
) -> ValidatedAdmissionRecord:
    """Authenticate and validate one request without inference, persistence, or replay claims."""
    correlation_id = str(uuid.uuid4())
    try:
        if type(registry) is not CertificateRegistry:
            raise _fail(
                "request_unauthorized", status_code=401, security_event="authentication_failed"
            )
        producer = registry.authenticate(peer, trusted_now=trusted_now)
        if method != INGEST_METHOD or target != INGEST_TARGET:
            raise _fail("invalid_request_route")
        if content_type != JSON_CONTENT_TYPE:
            raise _fail("content_type_invalid")
        body = read_bounded_body(body_stream, content_length=content_length)
        envelope = decode_producer_envelope(body)
        if envelope.producer_id != producer.producer_id:
            raise _fail("request_unauthorized", status_code=401, security_event="producer_mismatch")
        if envelope.source_contract not in producer.allowed_source_contracts:
            raise _fail(
                "admission_rejected", status_code=403, security_event="source_contract_denied"
            )
        _validate_request_time(envelope.produced_at, trusted_now)
        return ValidatedAdmissionRecord(
            correlation_id=correlation_id,
            producer_id=producer.producer_id,
            credential_id=producer.credential_id,
            request_id=envelope.request_id,
            produced_at=envelope.produced_at,
            received_at=trusted_now,
            nonce_sha256=hashlib.sha256(envelope.nonce.encode("ascii")).hexdigest(),
            body_sha256=hashlib.sha256(body).hexdigest(),
            method=INGEST_METHOD,
            target=INGEST_TARGET,
            content_type=JSON_CONTENT_TYPE,
            content_length=content_length,
            source_contract=envelope.source_contract,
            records=envelope.records,
        )
    except ProducerAdmissionError as exc:
        raise exc.for_attempt(correlation_id) from None


@dataclass(frozen=True, slots=True, repr=False)
class ProducerRecordDisposition:
    """One bounded response item identified only by its request-local position."""

    record_index: int
    disposition: str
    reason: str

    def __post_init__(self) -> None:
        if (
            type(self.record_index) is not int
            or not 1 <= self.record_index <= MAX_RECORDS
            or self.disposition not in RESPONSE_DISPOSITIONS
            or self.reason not in RESPONSE_REASONS
        ):
            raise _fail("response_invalid", status_code=500, security_event="internal_error")

    def __repr__(self) -> str:
        return "<ProducerRecordDisposition>"


@dataclass(frozen=True, slots=True, repr=False)
class ProducerResponse:
    """Privacy-minimized response contract with a separate handling correlation ID."""

    schema_version: str
    correlation_id: str
    reason: str
    records: tuple[ProducerRecordDisposition, ...]

    def __post_init__(self) -> None:
        if (
            self.schema_version != PRODUCER_INGEST_RESPONSE_SCHEMA_VERSION
            or not _is_uuid4(self.correlation_id)
            or self.reason not in RESPONSE_REASONS
            or type(self.records) is not tuple
            or len(self.records) > MAX_RECORDS
            or any(type(record) is not ProducerRecordDisposition for record in self.records)
            or tuple(record.record_index for record in self.records)
            != tuple(range(1, len(self.records) + 1))
        ):
            raise _fail("response_invalid", status_code=500, security_event="internal_error")

    def __repr__(self) -> str:
        return "<ProducerResponse>"


def serialize_producer_response(response: ProducerResponse) -> bytes:
    """Serialize the exact response contract and reject rather than truncate overflow."""
    if type(response) is not ProducerResponse:
        raise _fail("response_invalid", status_code=500, security_event="internal_error")
    payload = {
        "schema_version": response.schema_version,
        "correlation_id": response.correlation_id,
        "reason": response.reason,
        "records": [
            {
                "record_index": record.record_index,
                "disposition": record.disposition,
                "reason": record.reason,
            }
            for record in response.records
        ],
    }
    encoded = (
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
            "ascii"
        )
        + b"\n"
    )
    if len(encoded) > MAX_RESPONSE_BYTES:
        raise _fail("internal_error", status_code=500, security_event="internal_error")
    return encoded
