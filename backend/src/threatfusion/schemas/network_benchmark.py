"""Typed records for portable network-behavior benchmarking."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from threatfusion.schemas.flow import Protocol


class NetworkBenchmarkRecord(BaseModel):
    """Feature-only network record that is never an incident-correlation event."""

    model_config = ConfigDict(allow_inf_nan=False)

    schema_version: Literal["network_benchmark_v1"] = "network_benchmark_v1"
    source_dataset: Literal["cse_cic_ids2018"]
    source_file: str
    source_row_number: int = Field(ge=1)
    source_timestamp: datetime

    duration_ms: float = Field(ge=0)
    fwd_packets: int = Field(ge=0)
    bwd_packets: int = Field(ge=0)
    fwd_bytes: int = Field(ge=0)
    bwd_bytes: int = Field(ge=0)
    packets_per_second: float = Field(ge=0)
    bytes_per_second: float = Field(ge=0)
    fwd_packet_length_mean: float = Field(ge=0)
    bwd_packet_length_mean: float = Field(ge=0)
    dst_port: int = Field(ge=0, le=65535)
    protocol: Protocol

    label: Literal["Normal", "Attack"]
    attack_name: str | None = None

    @field_validator("source_file")
    @classmethod
    def validate_source_file_basename(cls, source_file: str) -> str:
        value = source_file.strip()
        if not value or value in {".", ".."} or "/" in value or "\\" in value:
            raise ValueError("source_file must be a nonblank basename")
        return value

    @model_validator(mode="after")
    def validate_directional_consistency(self) -> "NetworkBenchmarkRecord":
        if self.bwd_packets == 0 and self.bwd_bytes > 0:
            raise ValueError("bwd_bytes cannot be positive when bwd_packets is zero")
        if self.fwd_packets == 0 and self.fwd_bytes > 0:
            raise ValueError("fwd_bytes cannot be positive when fwd_packets is zero")
        return self

    @model_validator(mode="after")
    def validate_attack_name(self) -> "NetworkBenchmarkRecord":
        if self.label == "Normal" and self.attack_name is not None:
            raise ValueError("normal records must not have an attack_name")
        if self.label == "Attack" and not self.attack_name:
            raise ValueError("attack records must retain an attack_name")
        return self
