from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, Field, field_validator

DatasetName = Literal["unsw_nb15", "cse_cic_ids2018", "mordor"]
Sha256Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class DatasetFile(BaseModel):
    path: Path
    sha256: Sha256Digest | None = None
    rows: int | None = Field(default=None, ge=0)
    role: Literal["train", "test", "validation", "raw", "sample"]

    @field_validator("path")
    @classmethod
    def validate_project_relative_path(cls, path: Path) -> Path:
        if path.is_absolute():
            raise ValueError("dataset file path must be project-relative")
        if ".." in path.parts:
            raise ValueError("dataset file path must not contain '..'")
        return path


class DatasetManifest(BaseModel):
    """Metadata record proving exactly which dataset files were used."""

    name: DatasetName
    version: str
    source_url: str | None = None
    license_note: str
    files: list[DatasetFile] = Field(min_length=1)
    notes: str | None = None
