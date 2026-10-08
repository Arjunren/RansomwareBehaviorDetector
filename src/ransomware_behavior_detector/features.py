"""Validated domain telemetry and deterministic feature engineering."""

from __future__ import annotations

import math

import numpy as np
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

RAW_FIELDS = (
    "window_seconds",
    "file_modify_count",
    "file_rename_count",
    "file_delete_count",
    "extension_change_count",
    "high_entropy_write_count",
    "mean_entropy_delta",
    "unique_directories_touched",
    "process_spawn_count",
    "bytes_written",
    "protected_file_touch_count",
)
FEATURE_NAMES = (
    "window_seconds",
    "file_modify_count",
    "file_rename_count",
    "file_delete_count",
    "extension_change_count",
    "high_entropy_write_count",
    "mean_entropy_delta",
    "unique_directories_touched",
    "process_spawn_count",
    "bytes_written",
    "protected_file_touch_count",
    "modifications_per_minute",
    "renames_per_minute",
    "extension_change_ratio",
    "high_entropy_write_ratio",
    "bytes_written_log",
)


class Observation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    window_seconds: float = Field(ge=60, le=86400)
    file_modify_count: int = Field(ge=0, le=1000000)
    file_rename_count: int = Field(ge=0, le=1000000)
    file_delete_count: int = Field(ge=0, le=1000000)
    extension_change_count: int = Field(ge=0, le=1000000)
    high_entropy_write_count: int = Field(ge=0, le=1000000)
    mean_entropy_delta: float = Field(ge=-8, le=8)
    unique_directories_touched: int = Field(ge=0, le=1000000)
    process_spawn_count: int = Field(ge=0, le=1000000)
    bytes_written: float = Field(ge=0, le=1000000000000)
    protected_file_touch_count: int = Field(ge=0, le=1000000)

    @field_validator("window_seconds", "mean_entropy_delta", "bytes_written")
    @classmethod
    def finite(cls, value: float) -> float:
        if not math.isfinite(value):
            raise ValueError("Feature must be finite")
        return value

    @model_validator(mode="after")
    def consistent_counts(self) -> Observation:
        if self.extension_change_count > self.file_rename_count:
            raise ValueError("Extension changes exceed file renames")
        if self.high_entropy_write_count > self.file_modify_count:
            raise ValueError("High-entropy writes exceed file modifications")
        if self.protected_file_touch_count > (
            self.file_modify_count + self.file_rename_count + self.file_delete_count
        ):
            raise ValueError("Protected-file touches exceed file operations")
        return self


def extract_features(observation: Observation) -> np.ndarray:
    values = observation.model_dump()
    result = [float(values[name]) for name in RAW_FIELDS]
    result.append(
        float(values["file_modify_count"] / max(values["window_seconds"] / 60, 1))
    )  # modifications_per_minute
    result.append(
        float(values["file_rename_count"] / max(values["window_seconds"] / 60, 1))
    )  # renames_per_minute
    result.append(
        float(values["extension_change_count"] / max(values["file_rename_count"], 1))
    )  # extension_change_ratio
    result.append(
        float(values["high_entropy_write_count"] / max(values["file_modify_count"], 1))
    )  # high_entropy_write_ratio
    result.append(float(math.log1p(values["bytes_written"])))  # bytes_written_log
    return np.asarray(result, dtype=np.float64)


def feature_matrix(observations: list[Observation]) -> np.ndarray:
    if not observations:
        raise ValueError("At least one observation is required")
    return np.vstack([extract_features(item) for item in observations])
