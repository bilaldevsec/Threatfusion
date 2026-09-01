from dataclasses import dataclass
from math import isclose

from threatfusion.schemas.flow import NetworkFlow


@dataclass(frozen=True)
class ParityMismatch:
    field: str
    left_value: object
    right_value: object


NETWORK_PARITY_FIELDS = (
    "duration_ms",
    "fwd_packets",
    "bwd_packets",
    "fwd_bytes",
    "bwd_bytes",
    "packets_per_second",
    "bytes_per_second",
    "fwd_packet_length_mean",
    "bwd_packet_length_mean",
    "src_port",
    "dst_port",
    "protocol",
    "label",
)


def compare_network_flows(
    left: NetworkFlow,
    right: NetworkFlow,
    fields: tuple[str, ...] = NETWORK_PARITY_FIELDS,
    float_tolerance: float = 1e-6,
) -> tuple[ParityMismatch, ...]:
    mismatches: list[ParityMismatch] = []

    for field in fields:
        left_value = getattr(left, field)
        right_value = getattr(right, field)

        if isinstance(left_value, float) and isinstance(right_value, float):
            equal = isclose(
                left_value,
                right_value,
                rel_tol=float_tolerance,
                abs_tol=float_tolerance,
            )
        else:
            equal = left_value == right_value

        if not equal:
            mismatches.append(ParityMismatch(field, left_value, right_value))

    return tuple(mismatches)
