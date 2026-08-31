from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field


DatasetName = Literal["unsw_nb15", "cse_cic_ids2018", "mordor"]


class DatasetFile(BaseModel):
    path: Path
    sha256: str | None = None
    rows: int | None = Field(default=None, ge=0)
    role: Literal["train", "test", "validation", "raw", "sample"]


class DatasetManifest(BaseModel):
    """Metadata record proving exactly which dataset files were used."""

    name: DatasetName
    version: str
    source_url: str | None = None
    license_note: str
    files: list[DatasetFile]
    notes: str | None = None
