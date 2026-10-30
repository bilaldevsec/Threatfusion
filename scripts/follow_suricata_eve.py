#!/usr/bin/env python3
"""Tail Suricata eve.json and post each flow to the live sensor route.

Alert lines are display text only. The frozen forest scores the adapted flow.
This script does not import the advisory, retrieval, or explanation modules.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

SOURCE_ROOT = Path(__file__).resolve().parents[1] / "backend/src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from threatfusion.datasets.adapters.base import SourceRowValidationError  # noqa: E402
from threatfusion.datasets.adapters.suricata_flow import SuricataFlowAdapter  # noqa: E402

SENSOR_NAMESPACE = "lab:range-bridge-01"
SENSOR_SOURCE_LABEL = "suricata_bridge"
_ALERT_CACHE_LIMIT = 256


def alert_key(src_ip: str, dst_ip: str, proto: str, dest_port: int) -> tuple[str, str, str, int]:
    return (src_ip, dst_ip, proto.lower(), int(dest_port))


def remember_alert(cache: dict[tuple[str, str, str, int], str], record: dict[str, Any]) -> None:
    """Keep a signature for one 4-tuple. The signature is not a model feature."""
    alert = record.get("alert")
    if not isinstance(alert, dict):
        return
    signature = alert.get("signature")
    if not isinstance(signature, str) or not signature.strip():
        return
    try:
        key = alert_key(
            str(record["src_ip"]),
            str(record["dest_ip"]),
            str(record["proto"]),
            int(record["dest_port"]),
        )
    except (KeyError, TypeError, ValueError):
        return
    if key in cache:
        del cache[key]
    cache[key] = signature.strip()
    while len(cache) > _ALERT_CACHE_LIMIT:
        cache.pop(next(iter(cache)))


def sensor_payload(
    record: dict[str, Any], cache: dict[tuple[str, str, str, int], str]
) -> dict[str, Any]:
    """Adapt one flow and attach a matched signature, or say that none matched."""
    adapted = SuricataFlowAdapter().adapt_eve_flow_record(
        record,
        sensor_namespace=SENSOR_NAMESPACE,
        clock_synchronized=True,
    )
    provenance = adapted.provenance
    src_ip = provenance.src_ip
    dst_ip = provenance.dst_ip
    proto = str(provenance.protocol or "")
    dest_port = int(provenance.service_or_port or record["dest_port"])
    if not src_ip or not dst_ip:
        raise SourceRowValidationError(
            "SuricataFlow", "src_ip", "bare address missing after adaptation"
        )
    signature = cache.get(alert_key(src_ip, dst_ip, proto, dest_port))
    features = {name: float(value) for name, value in adapted.features_14.items()}
    return {
        "source_label": SENSOR_SOURCE_LABEL,
        "source_event_id": adapted.source_event_id,
        "observed_at_utc": provenance.observed_at_utc,
        "features": features,
        "provenance": {
            "entity_namespace_id": SENSOR_NAMESPACE,
            "src_entity_id": src_ip,
            "dst_entity_id": dst_ip,
            "protocol": proto,
            "service_or_port": str(dest_port),
            "clock_synchronized": True,
        },
        "sensor_observation": {
            "proto": proto,
            "src_ip": src_ip,
            "src_port": int(record["src_port"]),
            "dst_ip": dst_ip,
            "dst_port": dest_port,
            "signature": signature,
        },
    }


def post_sensor(url: str, payload: dict[str, Any], timeout: float) -> tuple[int, dict[str, Any]]:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = json.loads(response.read().decode("utf-8"))
            return response.status, body if isinstance(body, dict) else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8")
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            parsed = {"error": raw}
        return exc.code, parsed if isinstance(parsed, dict) else {"error": raw}


def handle_line(
    line: str,
    cache: dict[tuple[str, str, str, int], str],
    url: str,
    timeout: float,
) -> str:
    text = line.strip()
    if not text:
        return "blank"
    try:
        record = json.loads(text)
    except json.JSONDecodeError:
        return "bad_json"
    if not isinstance(record, dict):
        return "ignored"
    event_type = record.get("event_type")
    if event_type == "alert":
        remember_alert(cache, record)
        return "alert"
    if event_type != "flow":
        return "ignored"
    try:
        payload = sensor_payload(record, cache)
    except (SourceRowValidationError, KeyError, TypeError, ValueError) as exc:
        print(f"sensor-skip: {exc}", file=sys.stderr)
        return "invalid_flow"
    status, body = post_sensor(url, payload, timeout)
    decision = body.get("decision")
    probability = body.get("rf_attack_probability")
    observation = (
        body.get("sensor_observation") if isinstance(body.get("sensor_observation"), dict) else {}
    )
    print(
        f"sensor-post: status={status} decision={decision} probability={probability} "
        f"line={observation.get('suricata_line')}",
        flush=True,
    )
    if status != 200:
        raise RuntimeError(
            f"sensor post failed: {status} {body.get('reason') or body.get('error')}"
        )
    return "posted"


def follow_eve(path: Path, url: str, timeout: float) -> None:
    """Read new lines. A file that already exists is followed from its current end."""
    cache: dict[tuple[str, str, str, int], str] = {}
    offset = 0
    partial = ""
    positioned = False
    while True:
        if not path.is_file():
            positioned = False
            offset = 0
            partial = ""
            time.sleep(0.4)
            continue
        size = path.stat().st_size
        if not positioned:
            offset = size
            positioned = True
            time.sleep(0.4)
            continue
        if size < offset:
            offset = 0
            partial = ""
        if size > offset:
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                handle.seek(offset)
                chunk = handle.read()
                offset = handle.tell()
            partial += chunk
            while "\n" in partial:
                line, partial = partial.split("\n", 1)
                handle_line(line, cache, url, timeout)
        time.sleep(0.4)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Follow Suricata eve.json into the live sensor route."
    )
    parser.add_argument(
        "--eve",
        default="docker/range/eve/eve.json",
        help="Path to eve.json on this machine.",
    )
    parser.add_argument(
        "--console-url",
        default="http://127.0.0.1:8766/api/v1/live/sensor",
        help="Live sensor route.",
    )
    parser.add_argument("--timeout", type=float, default=30.0)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    follow_eve(Path(args.eve), args.console_url, args.timeout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
