"""Terminating process boundary for registered producer inference."""

from __future__ import annotations

import json
import math
import multiprocessing
import os
import signal
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from multiprocessing.connection import Connection
from pathlib import Path
from uuid import UUID, uuid4

from threatfusion.models.network_inference import (
    APPROVED_MODEL_HASHES,
    MAX_INFERENCE_BATCH_SIZE,
    NetworkInferenceError,
    NetworkInferenceResult,
    NetworkModelChoice,
    RegisteredUnswInferenceResult,
    UnswNetworkInferenceBoundary,
)
from threatfusion.schemas.alert_candidate import derive_source_event_id

PROCESSING_RECORD_SECONDS = 30.0
PROCESSING_REQUEST_SECONDS = 300.0
WORKER_CLEANUP_SECONDS = 2.0
MAX_WORKER_MESSAGE_BYTES = 262_144
WORKER_PROTOCOL_VERSION = "producer_inference_worker_v1"
_TEST_WORKER_MODES = frozenset(
    {
        "success_normal",
        "crash",
        "silent_exit",
        "malformed_wire",
        "malformed_result",
        "child_failure",
        "request_hang",
        "record_hang",
        "cleanup_hang",
        "malformed_after_attack",
    }
)


class ProducerInferenceWorkerError(RuntimeError):
    """Allowlisted worker failure without child-process details."""

    _CODES = frozenset(
        {
            "worker_start_failed",
            "worker_crashed",
            "worker_response_missing",
            "worker_response_invalid",
            "worker_failed",
            "worker_record_timeout",
            "worker_request_timeout",
            "worker_cleanup_failed",
        }
    )

    def __init__(self, code: str) -> None:
        self.code = code if code in self._CODES else "worker_failed"
        super().__init__(self.code)

    def __repr__(self) -> str:
        return "<ProducerInferenceWorkerError>"


@dataclass(frozen=True, slots=True)
class ProducerInferenceWorkerLimits:
    """Production ceilings; tests may inject only shorter positive limits."""

    record_seconds: float = PROCESSING_RECORD_SECONDS
    request_seconds: float = PROCESSING_REQUEST_SECONDS
    cleanup_seconds: float = WORKER_CLEANUP_SECONDS

    def __post_init__(self) -> None:
        values = (self.record_seconds, self.request_seconds, self.cleanup_seconds)
        if any(type(value) not in {int, float} or not math.isfinite(value) for value in values):
            raise ProducerInferenceWorkerError("worker_start_failed")
        if (
            not 0 < self.record_seconds <= PROCESSING_RECORD_SECONDS
            or not 0 < self.request_seconds <= PROCESSING_REQUEST_SECONDS
            or not 0 < self.cleanup_seconds <= WORKER_CLEANUP_SECONDS
        ):
            raise ProducerInferenceWorkerError("worker_start_failed")


def _encode_message(kind: str, **payload: object) -> bytes:
    return json.dumps(
        {"protocol": WORKER_PROTOCOL_VERSION, "kind": kind, **payload},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _registered_payload(result: RegisteredUnswInferenceResult) -> dict[str, object]:
    return {
        "source_event_id": result.source_event_id,
        "observed_at": result.observed_at.isoformat(),
        "model_artifact_sha256": result.model_artifact_sha256,
        "inference": result.inference.to_dict(),
    }


def _send(connection: Connection, kind: str, **payload: object) -> None:
    encoded = _encode_message(kind, **payload)
    if len(encoded) > MAX_WORKER_MESSAGE_BYTES:
        raise RuntimeError("worker_message_too_large")
    connection.send_bytes(encoded)


def _default_worker_target(
    connection: Connection,
    project_root: str,
    references: tuple[tuple[str, int], ...],
) -> None:
    """Load and execute the existing frozen boundary wholly inside the child."""
    try:
        boundary = UnswNetworkInferenceBoundary(project_root=Path(project_root))
        prepared = boundary._prepare_registered_batch(references=references)
        if type(prepared) is not tuple or len(prepared) != len(references):
            raise RuntimeError("prepared_result_invalid")
        _send(connection, "prepared", count=len(prepared))
        for index, item in enumerate(prepared, start=1):
            _send(connection, "record_started", index=index)
            result = boundary._infer_prepared_registered(
                item, model=NetworkModelChoice.RANDOM_FOREST
            )
            _send(
                connection,
                "record_result",
                index=index,
                result=_registered_payload(result),
            )
        _send(connection, "complete", count=len(prepared))
    except NetworkInferenceError:
        _send(connection, "inference_rejected")
    except BaseException:
        try:
            _send(connection, "worker_failed")
        except BaseException:
            pass


def _test_result_payload(
    *,
    manifest_sha256: str,
    reference: tuple[str, int],
    predicted_class: str,
) -> dict[str, object]:
    probability = 0.8 if predicted_class == "Attack" else 0.2
    return {
        "source_event_id": derive_source_event_id(
            source_representation="unsw_nb15.argus.raw_49.transaction_bytes.v1",
            manifest_sha256=manifest_sha256,
            source_member_sha256=reference[0],
            row_number=reference[1],
        ),
        "observed_at": datetime(2015, 1, 22, tzinfo=UTC).isoformat(),
        "model_artifact_sha256": APPROVED_MODEL_HASHES["random_forest"]["model"],
        "inference": {
            "correlation_id": str(uuid4()),
            "model_identity": "random_forest",
            "model_version": "network_random_forest_baseline_v1",
            "contract_identity": "network_behavior_v1",
            "source_representation_identity": ("unsw_nb15.argus.raw_49.transaction_bytes.v1"),
            "attack_probability": probability,
            "decision_threshold": 0.5,
            "predicted_class": predicted_class,
            "status": "completed",
            "reason": "inference_succeeded",
            "processed_at": datetime(2026, 9, 22, tzinfo=UTC).isoformat(),
            "latency_ms": 0.0,
        },
    }


def _send_test_success(
    connection: Connection,
    manifest_sha256: str,
    references: tuple[tuple[str, int], ...],
    *,
    predicted_class: str = "Normal",
) -> None:
    _send(connection, "prepared", count=len(references))
    for index, reference in enumerate(references, start=1):
        _send(connection, "record_started", index=index)
        _send(
            connection,
            "record_result",
            index=index,
            result=_test_result_payload(
                manifest_sha256=manifest_sha256,
                reference=reference,
                predicted_class=predicted_class,
            ),
        )
    _send(connection, "complete", count=len(references))


def _run_test_mode(
    connection: Connection,
    manifest_sha256: str,
    references: tuple[tuple[str, int], ...],
    mode: str,
) -> None:
    """Dispatch an exact code-owned test behavior from a primitive allowlist."""
    if mode == "success_normal":
        _send_test_success(connection, manifest_sha256, references)
    elif mode == "crash":
        os._exit(23)
    elif mode == "silent_exit":
        return
    elif mode == "malformed_wire":
        _send_test_success(connection, manifest_sha256, references)
        connection.send_bytes(b'{"not":"the worker protocol"}')
    elif mode == "malformed_result":
        _send(connection, "prepared", count=len(references))
        _send(connection, "record_started", index=1)
        payload = _test_result_payload(
            manifest_sha256=manifest_sha256,
            reference=references[0],
            predicted_class="Normal",
        )
        inference = payload["inference"]
        if type(inference) is not dict:
            raise RuntimeError("test_payload_invalid")
        inference["attack_probability"] = "/private/model.joblib"
        _send(connection, "record_result", index=1, result=payload)
    elif mode == "child_failure":
        raise RuntimeError("/private/model.joblib secret exception")
    elif mode == "request_hang":
        while True:
            signal.pause()
    elif mode == "record_hang":
        _send(connection, "prepared", count=len(references))
        _send(connection, "record_started", index=1)
        while True:
            signal.pause()
    elif mode == "cleanup_hang":
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        _send_test_success(connection, manifest_sha256, references)
        while True:
            signal.pause()
    elif mode == "malformed_after_attack":
        _send(connection, "prepared", count=len(references))
        _send(connection, "record_started", index=1)
        _send(
            connection,
            "record_result",
            index=1,
            result=_test_result_payload(
                manifest_sha256=manifest_sha256,
                reference=references[0],
                predicted_class="Attack",
            ),
        )
        _send(connection, "record_started", index=2)
        connection.send_bytes(b'{"path":"/private/model.joblib","secret":"credential"}')
    else:
        raise RuntimeError("test_mode_invalid")


def _worker_bootstrap(
    connection: Connection,
    project_root: str,
    manifest_sha256: str,
    references: tuple[tuple[str, int], ...],
    test_mode: str | None,
) -> None:
    try:
        os.setsid()
        _send(connection, "booted", pid=os.getpid())
        if test_mode is None:
            _default_worker_target(connection, project_root, references)
        else:
            _run_test_mode(connection, manifest_sha256, references, test_mode)
    except BaseException:
        try:
            _send(connection, "worker_failed")
        except BaseException:
            pass
    finally:
        connection.close()


def _strict_object(raw: bytes) -> dict[str, object]:
    if type(raw) is not bytes or not raw or len(raw) > MAX_WORKER_MESSAGE_BYTES:
        raise ProducerInferenceWorkerError("worker_response_invalid")

    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate")
            result[key] = value
        return result

    try:
        decoded = json.loads(raw.decode("ascii"), object_pairs_hook=pairs)
    except (UnicodeError, ValueError, TypeError):
        raise ProducerInferenceWorkerError("worker_response_invalid") from None
    if type(decoded) is not dict or decoded.get("protocol") != WORKER_PROTOCOL_VERSION:
        raise ProducerInferenceWorkerError("worker_response_invalid")
    return decoded


def _utc_datetime(value: object) -> datetime:
    if type(value) is not str or len(value) > 64:
        raise ProducerInferenceWorkerError("worker_response_invalid")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        raise ProducerInferenceWorkerError("worker_response_invalid") from None
    if parsed.tzinfo is not UTC:
        raise ProducerInferenceWorkerError("worker_response_invalid")
    return parsed


def _canonical_uuid4(value: object) -> str:
    if type(value) is not str or len(value) != 36:
        raise ProducerInferenceWorkerError("worker_response_invalid")
    try:
        parsed = UUID(value)
    except ValueError:
        raise ProducerInferenceWorkerError("worker_response_invalid") from None
    if parsed.version != 4 or str(parsed) != value:
        raise ProducerInferenceWorkerError("worker_response_invalid")
    return value


def _finite_number(value: object, *, minimum: float = 0.0) -> float:
    if type(value) not in {int, float}:
        raise ProducerInferenceWorkerError("worker_response_invalid")
    result = float(value)
    if not math.isfinite(result) or result < minimum:
        raise ProducerInferenceWorkerError("worker_response_invalid")
    return result


def _decode_registered_result(value: object) -> RegisteredUnswInferenceResult:
    if type(value) is not dict or set(value) != {
        "source_event_id",
        "observed_at",
        "model_artifact_sha256",
        "inference",
    }:
        raise ProducerInferenceWorkerError("worker_response_invalid")
    source_event_id = value["source_event_id"]
    artifact_hash = value["model_artifact_sha256"]
    if (
        type(source_event_id) is not str
        or not source_event_id.startswith("unsw_registered_source_event_v1:")
        or len(source_event_id) != len("unsw_registered_source_event_v1:") + 64
        or any(character not in "0123456789abcdef" for character in source_event_id[-64:])
        or artifact_hash != APPROVED_MODEL_HASHES["random_forest"]["model"]
    ):
        raise ProducerInferenceWorkerError("worker_response_invalid")
    inference = value["inference"]
    expected = {
        "correlation_id",
        "model_identity",
        "model_version",
        "contract_identity",
        "source_representation_identity",
        "attack_probability",
        "decision_threshold",
        "predicted_class",
        "status",
        "reason",
        "processed_at",
        "latency_ms",
    }
    if type(inference) is not dict or set(inference) != expected:
        raise ProducerInferenceWorkerError("worker_response_invalid")
    status = inference["status"]
    predicted = inference["predicted_class"]
    probability = inference["attack_probability"]
    reason = inference["reason"]
    if (
        inference["model_identity"] != "random_forest"
        or inference["model_version"] != "network_random_forest_baseline_v1"
        or inference["contract_identity"] != "network_behavior_v1"
        or inference["source_representation_identity"]
        != "unsw_nb15.argus.raw_49.transaction_bytes.v1"
        or inference["decision_threshold"] != 0.5
        or type(reason) is not str
        or not 1 <= len(reason) <= 64
        or any(character not in "abcdefghijklmnopqrstuvwxyz_" for character in reason)
    ):
        raise ProducerInferenceWorkerError("worker_response_invalid")
    if status == "completed":
        if predicted not in {"Normal", "Attack"} or reason != "inference_succeeded":
            raise ProducerInferenceWorkerError("worker_response_invalid")
        probability = _finite_number(probability)
        if probability > 1.0:
            raise ProducerInferenceWorkerError("worker_response_invalid")
        expected_prediction = "Attack" if probability >= 0.5 else "Normal"
        if predicted != expected_prediction:
            raise ProducerInferenceWorkerError("worker_response_invalid")
    elif status == "rejected":
        if predicted is not None or probability is not None:
            raise ProducerInferenceWorkerError("worker_response_invalid")
    else:
        raise ProducerInferenceWorkerError("worker_response_invalid")
    result = NetworkInferenceResult(
        correlation_id=_canonical_uuid4(inference["correlation_id"]),
        model_identity="random_forest",
        model_version="network_random_forest_baseline_v1",
        contract_identity="network_behavior_v1",
        source_representation_identity="unsw_nb15.argus.raw_49.transaction_bytes.v1",
        attack_probability=probability,
        decision_threshold=0.5,
        predicted_class=predicted,
        status=status,
        reason=reason,
        processed_at=_utc_datetime(inference["processed_at"]).isoformat(),
        latency_ms=_finite_number(inference["latency_ms"]),
    )
    return RegisteredUnswInferenceResult(
        source_event_id=source_event_id,
        observed_at=_utc_datetime(value["observed_at"]),
        model_artifact_sha256=artifact_hash,
        inference=result,
    )


class TerminatingProducerInferenceWorker:
    """Spawn one isolated worker and return only a complete validated batch."""

    def __init__(
        self,
        *,
        project_root: Path,
        manifest_sha256: str,
        limits: ProducerInferenceWorkerLimits | None = None,
        _test_mode: str | None = None,
    ) -> None:
        if (
            not isinstance(project_root, Path)
            or not project_root.is_absolute()
            or type(manifest_sha256) is not str
            or len(manifest_sha256) != 64
            or any(character not in "0123456789abcdef" for character in manifest_sha256)
            or (
                _test_mode is not None
                and (type(_test_mode) is not str or _test_mode not in _TEST_WORKER_MODES)
            )
        ):
            raise ProducerInferenceWorkerError("worker_start_failed")
        self._project_root = project_root
        self._manifest_sha256 = manifest_sha256
        self._limits = limits or ProducerInferenceWorkerLimits()
        if type(self._limits) is not ProducerInferenceWorkerLimits:
            raise ProducerInferenceWorkerError("worker_start_failed")
        self._test_mode = _test_mode
        self._context = multiprocessing.get_context("spawn")
        self._last_worker_pid: int | None = None
        self._completed_record_count = 0
        self._last_worker_process_group_id: int | None = None

    @property
    def limits(self) -> ProducerInferenceWorkerLimits:
        return self._limits

    @property
    def last_worker_pid(self) -> int | None:
        return self._last_worker_pid

    @property
    def completed_record_count(self) -> int:
        return self._completed_record_count

    @property
    def last_worker_process_group_id(self) -> int | None:
        return self._last_worker_process_group_id

    def _remaining(self, request_deadline: float, record_deadline: float | None) -> float:
        now = time.monotonic()
        remaining = request_deadline - now
        if record_deadline is not None:
            remaining = min(remaining, record_deadline - now)
        return max(0.0, remaining)

    @staticmethod
    def _signal_worker(
        process: multiprocessing.Process, signal_number: signal.Signals, *, group_ready: bool
    ) -> None:
        if process.pid is None:
            return
        try:
            if group_ready:
                os.killpg(process.pid, signal_number)
            elif process.is_alive() and signal_number is signal.SIGTERM:
                process.terminate()
            elif process.is_alive():
                process.kill()
        except (OSError, ProcessLookupError):
            pass

    @staticmethod
    def _group_exists(process: multiprocessing.Process, *, group_ready: bool) -> bool:
        if process.pid is None or not group_ready:
            return False
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        return True

    def _stop(self, process: multiprocessing.Process, *, group_ready: bool) -> bool:
        self._signal_worker(process, signal.SIGTERM, group_ready=group_ready)
        process.join(self._limits.cleanup_seconds)
        if process.is_alive() or self._group_exists(process, group_ready=group_ready):
            self._signal_worker(process, signal.SIGKILL, group_ready=group_ready)
            process.join(self._limits.cleanup_seconds)
        return not process.is_alive() and not self._group_exists(process, group_ready=group_ready)

    def execute(
        self, references: tuple[tuple[str, int], ...]
    ) -> tuple[RegisteredUnswInferenceResult, ...]:
        if (
            type(references) is not tuple
            or not 1 <= len(references) <= MAX_INFERENCE_BATCH_SIZE
            or any(
                type(item) is not tuple
                or len(item) != 2
                or type(item[0]) is not str
                or len(item[0]) != 64
                or any(character not in "0123456789abcdef" for character in item[0])
                or type(item[1]) is not int
                or item[1] <= 0
                for item in references
            )
        ):
            raise ProducerInferenceWorkerError("worker_start_failed")
        receive, send = self._context.Pipe(duplex=False)
        process = self._context.Process(
            target=_worker_bootstrap,
            args=(
                send,
                str(self._project_root),
                self._manifest_sha256,
                references,
                self._test_mode,
            ),
            name="threatfusion-producer-inference",
        )
        started = time.monotonic()
        request_deadline = started + self._limits.request_seconds
        record_deadline: float | None = None
        results: list[RegisteredUnswInferenceResult] = []
        complete = False
        group_ready = False
        failure: ProducerInferenceWorkerError | NetworkInferenceError | None = None
        try:
            try:
                process.start()
                self._last_worker_pid = process.pid
            except BaseException:
                raise ProducerInferenceWorkerError("worker_start_failed") from None
            finally:
                send.close()
            expected_kind = "booted"
            while not complete:
                remaining = self._remaining(request_deadline, record_deadline)
                if remaining <= 0 or not receive.poll(remaining):
                    code = (
                        "worker_record_timeout"
                        if record_deadline is not None
                        else "worker_request_timeout"
                    )
                    raise ProducerInferenceWorkerError(code)
                try:
                    message = _strict_object(receive.recv_bytes(MAX_WORKER_MESSAGE_BYTES))
                except EOFError:
                    process.join(self._limits.cleanup_seconds)
                    code = (
                        "worker_crashed"
                        if process.exitcode not in {None, 0}
                        else "worker_response_missing"
                    )
                    raise ProducerInferenceWorkerError(code) from None
                except OSError:
                    raise ProducerInferenceWorkerError("worker_response_invalid") from None
                kind = message.get("kind")
                if expected_kind == "booted":
                    if set(message) != {"protocol", "kind", "pid"} or kind != "booted":
                        raise ProducerInferenceWorkerError("worker_response_invalid")
                    if type(message["pid"]) is not int or message["pid"] != process.pid:
                        raise ProducerInferenceWorkerError("worker_response_invalid")
                    group_ready = True
                    self._last_worker_process_group_id = process.pid
                    expected_kind = "prepared"
                    continue
                if kind == "inference_rejected" and set(message) == {"protocol", "kind"}:
                    raise NetworkInferenceError("registered_event_rejected")
                if kind == "worker_failed" and set(message) == {"protocol", "kind"}:
                    raise ProducerInferenceWorkerError("worker_failed")
                if expected_kind == "prepared":
                    if (
                        kind != "prepared"
                        or set(message) != {"protocol", "kind", "count"}
                        or message["count"] != len(references)
                    ):
                        raise ProducerInferenceWorkerError("worker_response_invalid")
                    expected_kind = "record_started"
                elif expected_kind == "record_started":
                    index = len(results) + 1
                    if (
                        kind != "record_started"
                        or set(message) != {"protocol", "kind", "index"}
                        or message["index"] != index
                    ):
                        raise ProducerInferenceWorkerError("worker_response_invalid")
                    record_deadline = time.monotonic() + self._limits.record_seconds
                    expected_kind = "record_result"
                elif expected_kind == "record_result":
                    index = len(results) + 1
                    if (
                        kind != "record_result"
                        or set(message) != {"protocol", "kind", "index", "result"}
                        or message["index"] != index
                    ):
                        raise ProducerInferenceWorkerError("worker_response_invalid")
                    result = _decode_registered_result(message["result"])
                    expected_source_event_id = derive_source_event_id(
                        source_representation=("unsw_nb15.argus.raw_49.transaction_bytes.v1"),
                        manifest_sha256=self._manifest_sha256,
                        source_member_sha256=references[index - 1][0],
                        row_number=references[index - 1][1],
                    )
                    if result.source_event_id != expected_source_event_id:
                        raise ProducerInferenceWorkerError("worker_response_invalid")
                    results.append(result)
                    record_deadline = None
                    expected_kind = (
                        "complete" if len(results) == len(references) else "record_started"
                    )
                elif expected_kind == "complete":
                    if (
                        kind != "complete"
                        or set(message) != {"protocol", "kind", "count"}
                        or message["count"] != len(results)
                    ):
                        raise ProducerInferenceWorkerError("worker_response_invalid")
                    complete = True
                else:
                    raise ProducerInferenceWorkerError("worker_response_invalid")
        except (ProducerInferenceWorkerError, NetworkInferenceError) as error:
            failure = error
        finally:
            if process.pid is not None:
                if complete and failure is None:
                    process.join(self._limits.cleanup_seconds)
                    cleaned = not process.is_alive() and not self._group_exists(
                        process, group_ready=group_ready
                    )
                    if not cleaned:
                        cleaned = self._stop(process, group_ready=group_ready)
                        failure = ProducerInferenceWorkerError("worker_cleanup_failed")
                    elif process.exitcode != 0:
                        failure = ProducerInferenceWorkerError("worker_crashed")
                    else:
                        try:
                            if receive.poll():
                                try:
                                    receive.recv_bytes(MAX_WORKER_MESSAGE_BYTES)
                                except EOFError:
                                    pass
                                else:
                                    failure = ProducerInferenceWorkerError(
                                        "worker_response_invalid"
                                    )
                        except OSError:
                            failure = ProducerInferenceWorkerError("worker_response_invalid")
                else:
                    cleaned = self._stop(process, group_ready=group_ready)
                    if not cleaned:
                        failure = ProducerInferenceWorkerError("worker_cleanup_failed")
                try:
                    process.close()
                except ValueError:
                    if failure is None:
                        failure = ProducerInferenceWorkerError("worker_cleanup_failed")
            receive.close()
        if failure is not None:
            raise failure
        self._completed_record_count += len(results)
        return tuple(results)
