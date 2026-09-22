"""Synchronous parent orchestration with terminating registered-inference workers."""

from __future__ import annotations

import hashlib
import io
import math
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Callable

from threatfusion.alerts.network_alerts import build_alert_candidate
from threatfusion.api.producer_admission import (
    INGEST_METHOD,
    INGEST_TARGET,
    PRODUCER_ORCHESTRATOR_RESPONSE_SCHEMA_VERSION,
    REGISTERED_UNSW_SOURCE_CONTRACT,
    CertificateRegistry,
    ProducerAdmissionError,
    ProducerRecordDisposition,
    ProducerResponse,
    ValidatedAdmissionRecord,
    admit_producer_request,
    serialize_producer_response,
)
from threatfusion.api.producer_execution_gates import (
    GATE_ACCEPTED,
    GATE_RATE_LIMITED,
    ProducerExecutionGateError,
    ProducerExecutionGates,
)
from threatfusion.api.producer_inference_worker import (
    PROCESSING_RECORD_SECONDS,
    PROCESSING_REQUEST_SECONDS,
    ProducerInferenceWorkerError,
    ProducerInferenceWorkerLimits,
    TerminatingProducerInferenceWorker,
)
from threatfusion.api.producer_tls_transport import (
    AuthenticatedTlsSession,
    ProducerTlsListener,
    ProducerTlsTransportError,
)
from threatfusion.db.alert_repository import (
    AlertCandidateRepository,
    AlertInsertResult,
    AlertPersistenceError,
)
from threatfusion.db.producer_replay_journal import (
    STATE_COMPLETED,
    STATE_IN_PROGRESS,
    STATE_OUTCOME_UNKNOWN,
    ProducerReplayJournal,
    ProducerReplayJournalError,
    ReplayClaim,
)
from threatfusion.db.producer_security_audit import (
    ProducerSecurityAuditError,
    ProducerSecurityAuditRepository,
    create_producer_security_audit_event,
)
from threatfusion.models.network_inference import (
    MAX_INFERENCE_BATCH_SIZE,
    NetworkInferenceError,
    NetworkModelChoice,
    RegisteredUnswInferenceResult,
    UnswNetworkInferenceBoundary,
)
from threatfusion.schemas.alert_candidate import AlertCandidateError

ORCHESTRATOR_SCHEMA_VERSION = "producer_orchestrator_v1"


class ProducerOrchestratorError(RuntimeError):
    """Sanitized orchestration failure without client or dependency details."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)

    def __repr__(self) -> str:
        return "<ProducerOrchestratorError>"


@dataclass(frozen=True, slots=True, repr=False)
class ProducerOrchestratorResult:
    """Minimal result for one closed connection attempt."""

    reason: str
    response_bytes: bytes | None
    fatal: bool

    def __repr__(self) -> str:
        return "<ProducerOrchestratorResult>"


_AUDIT = {
    "authentication_failed": (
        "authentication_rejected",
        "authentication",
        "rejected",
        "authentication_failed",
    ),
    "credential_disabled": (
        "authentication_rejected",
        "authentication",
        "rejected",
        "credential_disabled",
    ),
    "credential_revoked": (
        "authentication_rejected",
        "authentication",
        "rejected",
        "credential_revoked",
    ),
    "credential_not_yet_valid": (
        "authentication_rejected",
        "authentication",
        "rejected",
        "credential_not_yet_valid",
    ),
    "credential_expired": (
        "authentication_rejected",
        "authentication",
        "rejected",
        "credential_expired",
    ),
    "producer_mismatch": (
        "producer_admission_rejected",
        "admission",
        "rejected",
        "producer_mismatch",
    ),
    "source_contract_denied": (
        "producer_admission_rejected",
        "admission",
        "rejected",
        "source_contract_denied",
    ),
    "invalid_request": (
        "producer_admission_rejected",
        "admission",
        "rejected",
        "invalid_request",
    ),
    "request_time_invalid": (
        "producer_admission_rejected",
        "admission",
        "rejected",
        "request_time_invalid",
    ),
    "request_too_large": (
        "producer_admission_rejected",
        "admission",
        "rejected",
        "request_too_large",
    ),
    "body_incomplete": (
        "producer_admission_rejected",
        "admission",
        "rejected",
        "body_incomplete",
    ),
    "rate_limited": ("rate_limited", "rate_control", "rejected", "rate_limited"),
    "server_busy": ("server_busy", "concurrency_control", "rejected", "server_busy"),
    "request_admitted": ("request_admitted", "admission", "admitted", "request_admitted"),
    "request_in_progress": (
        "replay_in_progress",
        "replay",
        "deferred",
        "request_in_progress",
    ),
    "request_replay_rejected": (
        "replay_conflict",
        "replay",
        "rejected",
        "request_replay_rejected",
    ),
    "outcome_unknown": (
        "replay_outcome_unknown",
        "replay",
        "unknown",
        "outcome_unknown",
    ),
    "request_completed": (
        "request_completed",
        "completion",
        "completed",
        "request_completed",
    ),
    "internal_error": ("internal_failure", "internal", "failed", "internal_error"),
    "clock_unavailable": ("internal_failure", "internal", "failed", "clock_unavailable"),
    "request_timeout": (
        "internal_failure",
        "processing",
        "failed",
        "request_timeout",
    ),
    "processing_timeout": (
        "internal_failure",
        "processing",
        "failed",
        "processing_timeout",
    ),
    "audit_unavailable": (
        "internal_failure",
        "audit",
        "failed",
        "audit_unavailable",
    ),
    "recovery_completed": (
        "startup_recovery",
        "recovery",
        "completed",
        "recovery_completed",
    ),
}


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("ascii")).hexdigest()


class ProducerOrchestrator:
    """One fixed v1 owner joining the existing producer component boundaries.

    Construction performs no recovery and opens no listener. Correct operation assumes one
    externally coordinated service owner, one shared gate, and one service generation.
    """

    def __init__(
        self,
        *,
        transport: ProducerTlsListener,
        certificate_registry: CertificateRegistry,
        execution_gates: ProducerExecutionGates,
        replay_journal: ProducerReplayJournal,
        security_audit: ProducerSecurityAuditRepository,
        inference_boundary: UnswNetworkInferenceBoundary,
        alert_repository: AlertCandidateRepository,
        trusted_now: Callable[[], datetime] = lambda: datetime.now(UTC),
        monotonic: Callable[[], float] = time.monotonic,
        worker_limits: ProducerInferenceWorkerLimits | None = None,
        _test_inference_mode: str | None = None,
    ) -> None:
        if (
            type(transport) is not ProducerTlsListener
            or type(certificate_registry) is not CertificateRegistry
            or type(execution_gates) is not ProducerExecutionGates
            or type(replay_journal) is not ProducerReplayJournal
            or type(security_audit) is not ProducerSecurityAuditRepository
            or type(inference_boundary) is not UnswNetworkInferenceBoundary
            or type(alert_repository) is not AlertCandidateRepository
            or not callable(trusted_now)
            or not callable(monotonic)
            or (
                _test_inference_mode is not None
                and (
                    type(_test_inference_mode) is not str
                    or _test_inference_mode != "inline_registered_inference"
                )
            )
        ):
            raise ProducerOrchestratorError("orchestrator_configuration_invalid")
        provenance = inference_boundary.audit_provenance
        if (
            type(provenance) is not dict
            or provenance.get("primary_model") != NetworkModelChoice.RANDOM_FOREST.value
            or provenance.get("automatic_fallback") is not False
            or provenance.get("source_representation")
            != "unsw_nb15.argus.raw_49.transaction_bytes.v1"
            or provenance.get("feature_contract") != "network_behavior_v1"
            or provenance.get("maximum_batch_size") != MAX_INFERENCE_BATCH_SIZE
            or replay_journal.service_generation_id == ""
        ):
            raise ProducerOrchestratorError("orchestrator_configuration_invalid")
        self._transport = transport
        self._registry = certificate_registry
        self._gates = execution_gates
        self._replay = replay_journal
        self._audit = security_audit
        self._inference = inference_boundary
        self._alerts = alert_repository
        self._trusted_now = trusted_now
        self._monotonic = monotonic
        self._worker = None
        if _test_inference_mode is None:
            project_root = getattr(inference_boundary, "_project_root", None)
            registered_source = getattr(inference_boundary, "_registered_source", None)
            manifest_sha256 = getattr(registered_source, "manifest_sha256", None)
            if not isinstance(project_root, Path) or type(manifest_sha256) is not str:
                raise ProducerOrchestratorError("orchestrator_configuration_invalid")
            try:
                self._worker = TerminatingProducerInferenceWorker(
                    project_root=project_root,
                    manifest_sha256=manifest_sha256,
                    limits=worker_limits,
                )
            except ProducerInferenceWorkerError:
                raise ProducerOrchestratorError("orchestrator_configuration_invalid") from None
            self._inline_inference_for_tests = False
        else:
            if worker_limits is not None:
                raise ProducerOrchestratorError("orchestrator_configuration_invalid")
            self._inline_inference_for_tests = True
        self._fatal = False

    def __repr__(self) -> str:
        return "<ProducerOrchestrator>"

    @property
    def fatal(self) -> bool:
        return self._fatal

    @property
    def worker_completed_record_count(self) -> int:
        """Count validated records returned by fully cleaned production workers."""
        return 0 if self._worker is None else self._worker.completed_record_count

    def open(self) -> None:
        """Open the already validated injected transport; no recovery is implicit."""
        if self._fatal:
            raise ProducerOrchestratorError("service_fatal")
        self._transport.open()

    def close(self) -> None:
        self._transport.close()

    def _now(self) -> datetime:
        try:
            value = self._trusted_now()
        except Exception:
            raise ProducerOrchestratorError("trusted_time_unavailable") from None
        if type(value) is not datetime or value.tzinfo is not UTC:
            raise ProducerOrchestratorError("trusted_time_unavailable")
        return value

    def _monotonic_now(self) -> float:
        try:
            value = self._monotonic()
        except Exception:
            raise ProducerOrchestratorError("monotonic_clock_invalid") from None
        if type(value) not in {int, float} or not math.isfinite(value) or value < 0:
            raise ProducerOrchestratorError("monotonic_clock_invalid")
        return float(value)

    def _append_audit(
        self,
        reason: str,
        *,
        session: AuthenticatedTlsSession | None = None,
        record: ValidatedAdmissionRecord | None = None,
        correlation_id: str | None = None,
    ) -> None:
        taxonomy = _AUDIT.get(reason)
        if taxonomy is None:
            raise ProducerOrchestratorError("audit_mapping_invalid")
        producer_id = source_contract = credential = request_digest = body_digest = None
        if session is not None:
            producer_id = session.admitted_producer.producer_id
            credential = session.admitted_producer.credential_id
            source_contract = REGISTERED_UNSW_SOURCE_CONTRACT
        if record is not None:
            producer_id = record.producer_id
            credential = record.credential_id
            source_contract = record.source_contract
            request_digest = _sha256_text(record.request_id)
            body_digest = record.body_sha256
            correlation_id = record.correlation_id
        try:
            event = create_producer_security_audit_event(
                event_type=taxonomy[0],
                processing_stage=taxonomy[1],
                outcome=taxonomy[2],
                reason_code=taxonomy[3],
                correlation_id=correlation_id,
                producer_id=producer_id,
                source_contract_id=source_contract,
                credential_sha256=credential,
                request_id_sha256=request_digest,
                body_sha256=body_digest,
                trusted_now=self._now,
            )
            self._audit.append(event)
        except (ProducerSecurityAuditError, ProducerOrchestratorError):
            raise ProducerOrchestratorError("audit_unavailable") from None

    @staticmethod
    def _response(
        correlation_id: str,
        reason: str,
        records: tuple[ProducerRecordDisposition, ...] = (),
    ) -> bytes:
        try:
            return serialize_producer_response(
                ProducerResponse(
                    PRODUCER_ORCHESTRATOR_RESPONSE_SCHEMA_VERSION,
                    correlation_id,
                    reason,
                    records,
                )
            )
        except ProducerAdmissionError:
            raise ProducerOrchestratorError("response_invalid") from None

    @staticmethod
    def _admission_reason(error: ProducerAdmissionError) -> str:
        return (
            error.security_event
            if error.security_event
            in {
                "producer_mismatch",
                "source_contract_denied",
                "request_time_invalid",
                "request_too_large",
                "body_incomplete",
            }
            else "invalid_request"
        )

    @staticmethod
    def _transport_reason(error: ProducerTlsTransportError, *, authenticated: bool) -> str:
        if not authenticated:
            return (
                error.reason
                if error.reason
                in {
                    "credential_disabled",
                    "credential_revoked",
                    "credential_not_yet_valid",
                    "credential_expired",
                }
                else "authentication_failed"
            )
        if error.code == "request_too_large":
            return "request_too_large"
        if error.code in {"body_incomplete", "request_read_failed", "unexpected_trailing_data"}:
            return "body_incomplete"
        if error.reason == "request_timeout":
            return "request_timeout"
        return "invalid_request"

    def _write(
        self, session: AuthenticatedTlsSession, capability: object, response: bytes
    ) -> ProducerOrchestratorResult:
        try:
            session.connection.write_response(capability, response)
        except ProducerTlsTransportError:
            return ProducerOrchestratorResult("response_write_failed", response, self._fatal)
        return ProducerOrchestratorResult(serialize_reason(response), response, self._fatal)

    def _audit_or_unavailable(
        self,
        reason: str,
        *,
        session: AuthenticatedTlsSession,
        capability: object,
        record: ValidatedAdmissionRecord | None = None,
        correlation_id: str | None = None,
        poison: bool = False,
    ) -> ProducerOrchestratorResult | None:
        try:
            self._append_audit(
                reason,
                session=session,
                record=record,
                correlation_id=correlation_id,
            )
            return None
        except ProducerOrchestratorError:
            if poison:
                self._fatal = True
            selected = record.correlation_id if record is not None else correlation_id
            if selected is None:
                raise ProducerOrchestratorError("audit_unavailable") from None
            return self._write(
                session,
                capability,
                self._response(selected, "audit_unavailable"),
            )

    def _check_processing(self, started: float, record_started: float | None = None) -> None:
        now = self._monotonic_now()
        if now < started or now - started > PROCESSING_REQUEST_SECONDS:
            raise ProducerOrchestratorError("processing_timeout")
        if record_started is not None and (
            now < record_started or now - record_started > PROCESSING_RECORD_SECONDS
        ):
            raise ProducerOrchestratorError("processing_timeout")

    def _raise_ambiguous(
        self,
        code: str,
        *,
        session: AuthenticatedTlsSession,
        record: ValidatedAdmissionRecord,
        audit_reason: str = "internal_error",
    ) -> None:
        """Poison the generation and best-effort audit an unresolved request outcome."""
        self._fatal = True
        try:
            self._append_audit(audit_reason, session=session, record=record)
        except ProducerOrchestratorError:
            pass
        raise ProducerOrchestratorError(code) from None

    def _complete_and_write(
        self,
        *,
        session: AuthenticatedTlsSession,
        capability: object,
        record: ValidatedAdmissionRecord,
        claim: ReplayClaim,
        response: bytes,
        processing_started: float,
        enforce_budget: bool = True,
    ) -> ProducerOrchestratorResult:
        audit_failure = self._audit_or_unavailable(
            "request_completed",
            session=session,
            capability=capability,
            record=record,
            poison=True,
        )
        if audit_failure is not None:
            return audit_failure
        if enforce_budget:
            try:
                self._check_processing(processing_started)
            except ProducerOrchestratorError as error:
                self._raise_ambiguous(
                    error.code,
                    session=session,
                    record=record,
                    audit_reason=(
                        "processing_timeout"
                        if error.code == "processing_timeout"
                        else "internal_error"
                    ),
                )
        try:
            cached = self._replay.complete(claim, response, completed_at=self._now())
            if cached != response:
                raise ProducerReplayJournalError("cached_response_invalid")
        except (ProducerReplayJournalError, ProducerOrchestratorError):
            self._raise_ambiguous("replay_completion_ambiguous", session=session, record=record)
        return self._write(session, capability, response)

    def _complete_failure_and_write(
        self,
        *,
        failure_reason: str,
        session: AuthenticatedTlsSession,
        capability: object,
        record: ValidatedAdmissionRecord,
        claim: ReplayClaim,
        response: bytes,
        processing_started: float,
        enforce_budget: bool = True,
    ) -> ProducerOrchestratorResult:
        audit_failure = self._audit_or_unavailable(
            failure_reason,
            session=session,
            capability=capability,
            record=record,
            poison=True,
        )
        if audit_failure is not None:
            return audit_failure
        return self._complete_and_write(
            session=session,
            capability=capability,
            record=record,
            claim=claim,
            response=response,
            processing_started=processing_started,
            enforce_budget=enforce_budget,
        )

    def _process_claimed(
        self,
        *,
        session: AuthenticatedTlsSession,
        capability: object,
        record: ValidatedAdmissionRecord,
        claim: ReplayClaim,
    ) -> ProducerOrchestratorResult:
        audit_failure = self._audit_or_unavailable(
            "request_admitted",
            session=session,
            capability=capability,
            record=record,
            poison=True,
        )
        if audit_failure is not None:
            return audit_failure
        processing_started = self._monotonic_now()
        references = tuple(
            (reference.source_member_sha256, reference.row_number) for reference in record.records
        )
        record_started: float | None = None
        try:
            if not self._inline_inference_for_tests:
                if self._worker is None:
                    raise ProducerOrchestratorError("orchestrator_configuration_invalid")
                inferred = self._worker.execute(references)
            else:
                prepared = self._inference._prepare_registered_batch(references=references)
                inline_results = []
                for item in prepared:
                    record_started = self._monotonic_now()
                    inline_results.append(
                        self._inference._infer_prepared_registered(
                            item, model=NetworkModelChoice.RANDOM_FOREST
                        )
                    )
                    self._check_processing(processing_started, record_started)
                inferred = tuple(inline_results)
            if (
                type(inferred) is not tuple
                or len(inferred) != len(record.records)
                or any(type(item) is not RegisteredUnswInferenceResult for item in inferred)
            ):
                raise ProducerOrchestratorError("inference_result_invalid")
            self._check_processing(processing_started)
        except NetworkInferenceError:
            if self._worker is None:
                try:
                    self._check_processing(processing_started, record_started)
                except ProducerOrchestratorError:
                    response = self._response(record.correlation_id, "processing_timeout")
                    return self._complete_failure_and_write(
                        failure_reason="processing_timeout",
                        session=session,
                        capability=capability,
                        record=record,
                        claim=claim,
                        response=response,
                        processing_started=processing_started,
                        enforce_budget=False,
                    )
            # Registered-reference rejection proves there was no AlertCandidate persistence.
            response = self._response(
                record.correlation_id,
                "request_completed",
                tuple(
                    ProducerRecordDisposition(index, "rejected", "inference_rejected")
                    for index in range(1, len(record.records) + 1)
                ),
            )
            return self._complete_and_write(
                session=session,
                capability=capability,
                record=record,
                claim=claim,
                response=response,
                processing_started=processing_started,
            )
        except ProducerInferenceWorkerError as error:
            timed_out = error.code in {"worker_record_timeout", "worker_request_timeout"}
            reason = "processing_timeout" if timed_out else "internal_error"
            response = self._response(record.correlation_id, reason)
            return self._complete_failure_and_write(
                failure_reason=reason,
                session=session,
                capability=capability,
                record=record,
                claim=claim,
                response=response,
                processing_started=processing_started,
                enforce_budget=not timed_out,
            )
        except ProducerOrchestratorError as error:
            if error.code == "processing_timeout":
                response = self._response(record.correlation_id, "processing_timeout")
                return self._complete_failure_and_write(
                    failure_reason="processing_timeout",
                    session=session,
                    capability=capability,
                    record=record,
                    claim=claim,
                    response=response,
                    processing_started=processing_started,
                    enforce_budget=False,
                )
            self._fatal = True
            raise
        except Exception:
            self._raise_ambiguous("inference_outcome_ambiguous", session=session, record=record)

        try:
            candidates = tuple(
                (
                    build_alert_candidate(result, created_at=self._now())
                    if result.inference.status == "completed"
                    and result.inference.predicted_class == "Attack"
                    else None
                )
                for result in inferred
            )
        except (AlertCandidateError, ProducerOrchestratorError):
            response = self._response(record.correlation_id, "internal_error")
            return self._complete_failure_and_write(
                failure_reason="internal_error",
                session=session,
                capability=capability,
                record=record,
                claim=claim,
                response=response,
                processing_started=processing_started,
            )
        except Exception:
            self._raise_ambiguous(
                "candidate_construction_ambiguous", session=session, record=record
            )

        persisted: list[AlertInsertResult | None] = []
        durable_alert_results = 0
        for candidate in candidates:
            if candidate is None:
                persisted.append(None)
                continue
            try:
                self._check_processing(processing_started)
                result = self._alerts.insert(candidate)
                self._check_processing(processing_started)
                if type(result) is not AlertInsertResult:
                    raise ProducerOrchestratorError("alert_result_invalid")
                persisted.append(result)
                durable_alert_results += 1
            except AlertPersistenceError as error:
                if (
                    error.code
                    in {
                        "database_unavailable",
                        "database_busy",
                        "alert_candidate_type_invalid",
                        "database_record_invalid",
                        "alert_candidate_identity_conflict",
                    }
                    and durable_alert_results == 0
                ):
                    response = self._response(record.correlation_id, "internal_error")
                    return self._complete_failure_and_write(
                        failure_reason="internal_error",
                        session=session,
                        capability=capability,
                        record=record,
                        claim=claim,
                        response=response,
                        processing_started=processing_started,
                    )
                self._raise_ambiguous("alert_persistence_ambiguous", session=session, record=record)
            except ProducerOrchestratorError:
                self._raise_ambiguous("alert_persistence_ambiguous", session=session, record=record)
            except Exception:
                self._raise_ambiguous("alert_persistence_ambiguous", session=session, record=record)

        try:
            dispositions = []
            for index, (registered, persistence) in enumerate(
                zip(inferred, persisted, strict=True), start=1
            ):
                inference = registered.inference
                if inference.status != "completed" or inference.predicted_class is None:
                    dispositions.append(
                        ProducerRecordDisposition(index, "rejected", "inference_rejected")
                    )
                elif inference.predicted_class == "Normal":
                    dispositions.append(
                        ProducerRecordDisposition(
                            index,
                            "not_actionable",
                            "inference_not_actionable",
                            "Normal",
                            float(inference.attack_probability),
                        )
                    )
                else:
                    if persistence is None:
                        raise ProducerOrchestratorError("alert_result_invalid")
                    dispositions.append(
                        ProducerRecordDisposition(
                            index,
                            persistence.disposition,
                            persistence.reason,
                            "Attack",
                            float(inference.attack_probability),
                            persistence.candidate.alert_candidate_id,
                        )
                    )
            response = self._response(
                record.correlation_id, "request_completed", tuple(dispositions)
            )
        except Exception:
            self._raise_ambiguous("response_finalization_ambiguous", session=session, record=record)
        return self._complete_and_write(
            session=session,
            capability=capability,
            record=record,
            claim=claim,
            response=response,
            processing_started=processing_started,
        )

    def _process_session(self, session: AuthenticatedTlsSession) -> ProducerOrchestratorResult:
        capability: object = session.capability
        lease = None
        try:
            try:
                head, capability = session.connection.read_request_head(capability)
            except ProducerTlsTransportError as error:
                reason = self._transport_reason(error, authenticated=True)
                try:
                    self._append_audit(reason, session=session)
                except ProducerOrchestratorError:
                    raise ProducerOrchestratorError("audit_unavailable") from None
                raise ProducerOrchestratorError(reason) from None

            try:
                body, capability = session.connection.read_body(capability)
                record = admit_producer_request(
                    registry=self._registry,
                    peer=session.peer_evidence,
                    method=INGEST_METHOD,
                    target=INGEST_TARGET,
                    content_type=head.content_type,
                    content_length=head.content_length,
                    body_stream=io.BytesIO(body),
                    trusted_now=self._now(),
                )
                if (
                    record.producer_id != session.admitted_producer.producer_id
                    or record.credential_id != session.admitted_producer.credential_id
                    or record.source_contract
                    not in session.admitted_producer.allowed_source_contracts
                    or record.content_length != len(body)
                ):
                    raise ProducerAdmissionError(
                        "request_unauthorized", security_event="producer_mismatch"
                    )
            except ProducerTlsTransportError as error:
                reason = self._transport_reason(error, authenticated=True)
                try:
                    self._append_audit(reason, session=session)
                except ProducerOrchestratorError:
                    self._fatal = True
                    raise ProducerOrchestratorError("audit_unavailable") from None
                raise ProducerOrchestratorError(reason) from None
            except ProducerAdmissionError as error:
                reason = self._admission_reason(error)
                failed = self._audit_or_unavailable(
                    reason,
                    session=session,
                    capability=capability,
                    correlation_id=error.correlation_id,
                )
                if failed is not None:
                    return failed
                return self._write(
                    session,
                    capability,
                    self._response(error.correlation_id, "request_rejected"),
                )

            try:
                if session.admitted_producer.allowed_source_contracts != (
                    REGISTERED_UNSW_SOURCE_CONTRACT,
                ):
                    raise ProducerExecutionGateError("producer_not_admitted")
                decision = self._gates.acquire(session.admitted_producer)
            except ProducerExecutionGateError as error:
                audit_reason = (
                    "clock_unavailable"
                    if error.code == "monotonic_clock_invalid"
                    else "source_contract_denied"
                )
                failed = self._audit_or_unavailable(
                    audit_reason,
                    session=session,
                    capability=capability,
                    record=record,
                )
                if failed is not None:
                    return failed
                raise ProducerOrchestratorError(audit_reason) from None

            if decision.disposition != GATE_ACCEPTED:
                reason = (
                    "rate_limited" if decision.disposition == GATE_RATE_LIMITED else "server_busy"
                )
                failed = self._audit_or_unavailable(
                    reason,
                    session=session,
                    capability=capability,
                    record=record,
                )
                if failed is not None:
                    return failed
                return self._write(
                    session,
                    capability,
                    self._response(record.correlation_id, reason),
                )
            lease = decision.lease
            if lease is None:
                raise ProducerOrchestratorError("gate_decision_invalid")

            try:
                replay = self._replay.claim(record, claimed_at=self._now())
            except ProducerReplayJournalError as error:
                if error.code == "request_replay_rejected":
                    failed = self._audit_or_unavailable(
                        "request_replay_rejected",
                        session=session,
                        capability=capability,
                        record=record,
                    )
                    if failed is not None:
                        return failed
                    return self._write(
                        session,
                        capability,
                        self._response(record.correlation_id, "request_replay_rejected"),
                    )
                self._raise_ambiguous("replay_claim_ambiguous", session=session, record=record)

            if replay.disposition == STATE_COMPLETED:
                failed = self._audit_or_unavailable(
                    "request_completed",
                    session=session,
                    capability=capability,
                    record=record,
                )
                if failed is not None:
                    return failed
                if replay.cached_response is None:
                    self._fatal = True
                    raise ProducerOrchestratorError("cached_response_invalid")
                return self._write(session, capability, replay.cached_response)
            if (
                replay.disposition in {STATE_IN_PROGRESS, STATE_OUTCOME_UNKNOWN}
                and replay.claim is None
            ):
                reason = (
                    "request_in_progress"
                    if replay.disposition == STATE_IN_PROGRESS
                    else "outcome_unknown"
                )
                failed = self._audit_or_unavailable(
                    reason,
                    session=session,
                    capability=capability,
                    record=record,
                )
                if failed is not None:
                    return failed
                return self._write(
                    session,
                    capability,
                    self._response(record.correlation_id, reason),
                )
            if replay.claim is None or replay.reason != "request_claimed":
                self._fatal = True
                raise ProducerOrchestratorError("replay_claim_invalid")
            return self._process_claimed(
                session=session,
                capability=capability,
                record=record,
                claim=replay.claim,
            )
        finally:
            release_failure = False
            try:
                if lease is not None:
                    try:
                        self._gates.release(lease)
                    except ProducerExecutionGateError:
                        self._fatal = True
                        release_failure = True
            finally:
                if not session.connection.closed:
                    try:
                        session.connection.close(capability)
                    except ProducerTlsTransportError:
                        pass
            if release_failure:
                raise ProducerOrchestratorError("lease_release_failed") from None

    def process_one(self) -> ProducerOrchestratorResult:
        """Accept one connection and synchronously join any spawned inference worker."""
        if self._fatal:
            raise ProducerOrchestratorError("service_fatal")
        try:
            session = self._transport.accept_authenticated(
                self._registry,
                trusted_now=self._now(),
            )
        except ProducerTlsTransportError as error:
            reason = self._transport_reason(error, authenticated=False)
            try:
                self._append_audit(reason)
            except ProducerOrchestratorError:
                raise ProducerOrchestratorError("audit_unavailable") from None
            raise ProducerOrchestratorError("authentication_rejected") from None
        if type(session) is not AuthenticatedTlsSession:
            self._fatal = True
            raise ProducerOrchestratorError("transport_session_invalid")
        return self._process_session(session)

    def recover_abandoned_generation(self, abandoned_generation_id: str) -> int:
        """Explicitly recover one externally proven-stopped service generation."""
        if self._fatal:
            raise ProducerOrchestratorError("service_fatal")
        try:
            changed = self._replay.recover_abandoned_generation(
                abandoned_generation_id=abandoned_generation_id,
                recovered_at=self._now(),
            )
            self._append_audit("recovery_completed")
            return changed
        except ProducerReplayJournalError:
            try:
                self._append_audit("internal_error")
            except ProducerOrchestratorError:
                self._fatal = True
                raise ProducerOrchestratorError("audit_unavailable") from None
            raise ProducerOrchestratorError("recovery_failed") from None
        except ProducerOrchestratorError:
            self._fatal = True
            raise


def serialize_reason(response: bytes) -> str:
    """Return only the already validated response reason for internal result reporting."""
    from threatfusion.api.producer_admission import decode_producer_response

    try:
        return decode_producer_response(response).reason
    except ProducerAdmissionError:
        return "internal_error"
