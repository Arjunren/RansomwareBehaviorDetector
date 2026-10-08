"""Group-disjoint binary training, validation selection, and held-out evaluation."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from pydantic import ValidationError
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import GroupShuffleSplit
from sklearn.preprocessing import StandardScaler

from ransomware_behavior_detector.artifact import load_model, save_model
from ransomware_behavior_detector.features import (
    FEATURE_NAMES,
    RAW_FIELDS,
    Observation,
    feature_matrix,
)


@dataclass(frozen=True)
class TrainingConfig:
    seed: int = 42
    test_fraction: float = 0.2
    validation_fraction: float = 0.2
    regularization_c: float = 1.0
    max_iterations: int = 1000
    maximum_rows: int = 500000
    maximum_dataset_bytes: int = 268435456

    @classmethod
    def load(cls, path: Path) -> TrainingConfig:
        values = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(values, dict) or set(values) != set(cls.__dataclass_fields__):
            raise ValueError("Invalid training configuration")
        config = cls(**values)
        if not 0 < config.test_fraction < 0.5 or not 0 < config.validation_fraction < 0.5:
            raise ValueError("Invalid split fractions")
        if config.regularization_c <= 0 or config.max_iterations < 100:
            raise ValueError("Invalid hyperparameters")
        return config


def load_dataset(
    path: Path, config: TrainingConfig
) -> tuple[list[Observation], np.ndarray, np.ndarray, str]:
    if not path.is_file() or path.stat().st_size > config.maximum_dataset_bytes:
        raise ValueError("Dataset missing or exceeds byte limit")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    columns = [*RAW_FIELDS, "group_id", "label"]
    frame = pd.read_csv(path, usecols=columns, nrows=config.maximum_rows + 1)
    if len(frame) < 50 or len(frame) > config.maximum_rows or frame[columns].isna().any().any():
        raise ValueError("Dataset has invalid row count or missing values")
    if (
        not frame["label"].isin([0, 1]).all()
        or frame["group_id"].astype(str).str.len().gt(128).any()
    ):
        raise ValueError("Invalid label or group identifier")
    if frame.groupby(list(RAW_FIELDS))["label"].nunique().gt(1).any():
        raise ValueError("Conflicting labels for identical observations")
    frame = frame.drop_duplicates(subset=list(RAW_FIELDS)).reset_index(drop=True)
    try:
        observations = [
            Observation.model_validate(row) for row in frame[list(RAW_FIELDS)].to_dict("records")
        ]
    except ValidationError as exc:
        raise ValueError("Invalid telemetry row") from exc
    labels = frame["label"].to_numpy(dtype=np.int64)
    groups = frame["group_id"].astype(str).to_numpy()
    if len(np.unique(labels)) != 2:
        raise ValueError("Both classes are required")
    return observations, labels, groups, digest


def split_indices(
    labels: np.ndarray, groups: np.ndarray, config: TrainingConfig
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    indices = np.arange(len(labels))
    first = GroupShuffleSplit(n_splits=1, test_size=config.test_fraction, random_state=config.seed)
    train_val, test = next(first.split(indices, labels, groups))
    second = GroupShuffleSplit(
        n_splits=1,
        test_size=config.validation_fraction / (1 - config.test_fraction),
        random_state=config.seed + 1,
    )
    train_rel, val_rel = next(second.split(train_val, labels[train_val], groups[train_val]))
    train, validation = train_val[train_rel], train_val[val_rel]
    if any(len(np.unique(labels[part])) != 2 for part in (train, validation, test)):
        raise ValueError("Each group split needs both classes")
    return train, validation, test


def calculate_metrics(truth: np.ndarray, scores: np.ndarray, threshold: float) -> dict[str, Any]:
    predicted = (scores >= threshold).astype(np.int64)
    tn, fp, fn, tp = (int(x) for x in confusion_matrix(truth, predicted, labels=[0, 1]).ravel())
    return {
        "precision": float(precision_score(truth, predicted, zero_division=0)),
        "recall": float(recall_score(truth, predicted, zero_division=0)),
        "f1": float(f1_score(truth, predicted, zero_division=0)),
        "roc_auc": float(roc_auc_score(truth, scores)),
        "pr_auc": float(average_precision_score(truth, scores)),
        "false_positive_rate": fp / (tn + fp),
        "false_negative_rate": fn / (tp + fn),
        "confusion_matrix": [[tn, fp], [fn, tp]],
        "support": {"benign": tn + fp, "ransomware_like": tp + fn},
    }


def train(
    dataset_path: Path, model_path: Path, config_path: Path, version: str = "1.0.0"
) -> dict[str, Any]:
    config = TrainingConfig.load(config_path)
    observations, labels, groups, digest = load_dataset(dataset_path, config)
    train_idx, validation, test = split_indices(labels, groups, config)
    matrix = feature_matrix(observations)
    scaler = StandardScaler().fit(matrix[train_idx])
    estimator = LogisticRegression(
        C=config.regularization_c,
        max_iter=config.max_iterations,
        class_weight="balanced",
        random_state=config.seed,
    )
    estimator.fit(scaler.transform(matrix[train_idx]), labels[train_idx])
    validation_scores = estimator.predict_proba(scaler.transform(matrix[validation]))[:, 1]
    thresholds = np.linspace(0.05, 0.95, 91)
    threshold = float(
        max(thresholds, key=lambda t: f1_score(labels[validation], validation_scores >= t))
    )
    test_scores = estimator.predict_proba(scaler.transform(matrix[test]))[:, 1]
    metrics = calculate_metrics(labels[test], test_scores, threshold)
    payload: dict[str, Any] = {
        "features": list(FEATURE_NAMES),
        "means": scaler.mean_.tolist(),
        "scales": scaler.scale_.tolist(),
        "coefficients": estimator.coef_[0].tolist(),
        "intercept": float(estimator.intercept_[0]),
        "threshold": threshold,
        "version": version,
    }
    save_model(model_path, payload)
    load_model(model_path)
    metadata = {
        "model_version": version,
        "dataset_sha256": digest,
        "config": asdict(config),
        "split_strategy": "group_id_group_shuffle",
        "threshold_selected_on": "validation_f1",
        "split_counts": {"train": len(train_idx), "validation": len(validation), "test": len(test)},
        "test_metrics": metrics,
    }
    model_path.with_suffix(".metadata.json").write_text(
        json.dumps(metadata, indent=2, sort_keys=True), encoding="utf-8"
    )
    return metadata
