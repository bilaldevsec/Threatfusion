from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, IPvAnyAddress, model_validator

Protocol = Literal["tcp", "udp", "icmp", "other"]


class NetworkFlow(BaseModel):
    """Canonical network-flow schema used before ML/DL inference."""

    schema_version: str = Field(default="flow_common_v1")
    source_dataset: Literal["unsw_nb15", "cse_cic_ids2018", "live_sensor"]

    flow_id: str
    timestamp_start: datetime
    timestamp_end: datetime

    src_ip: IPvAnyAddress
    dst_ip: IPvAnyAddress
    src_port: int = Field(ge=0, le=65535)
    dst_port: int = Field(ge=0, le=65535)
    protocol: Protocol

    duration_ms: float = Field(ge=0)

    fwd_packets: int = Field(ge=0)
    bwd_packets: int = Field(ge=0)
    fwd_bytes: int = Field(ge=0)
    bwd_bytes: int = Field(ge=0)

    packets_per_second: float = Field(ge=0)
    bytes_per_second: float = Field(ge=0)

    fwd_packet_length_mean: float = Field(ge=0)
    bwd_packet_length_mean: float = Field(ge=0)

    label: str | None = None
    attack_category: str | None = None

    @model_validator(mode="after")
    def validate_time_order(self) -> "NetworkFlow":
        if self.timestamp_end < self.timestamp_start:
            raise ValueError("timestamp_end must be greater than or equal to timestamp_start")
        return self

    @model_validator(mode="after")
    def validate_bidirectional_consistency(self) -> "NetworkFlow":
        if self.bwd_packets == 0 and self.bwd_bytes > 0:
            raise ValueError("bwd_bytes cannot be positive when bwd_packets is zero")
        if self.fwd_packets == 0 and self.fwd_bytes > 0:
            raise ValueError("fwd_bytes cannot be positive when fwd_packets is zero")
        return self
