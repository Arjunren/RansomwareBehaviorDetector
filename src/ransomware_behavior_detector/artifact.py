"""Strict JSON model artifact: no pickle or code-bearing deserialization."""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np

from ransomware_behavior_detector.features import FEATURE_NAMES, Observation, extract_features

ARTIFACT_FORMAT = "ransomware-behavior-detector-logreg-v1"
MAX_ARTIFACT_BYTES = 65536


@dataclass(frozen=True)
class Model:
    version: str
    threshold: float
    means: np.ndarray
    scales: np.ndarray
    coefficients: np.ndarray
    intercept: float

    def predict(self, observation: Observation) -> dict[str, Any]:
        features = extract_features(observation)
        scaled = (features - self.means) / self.scales
        logit = float(np.dot(scaled, self.coefficients) + self.intercept)
        probability = 1.0 / (1.0 + math.exp(-max(-700.0, min(700.0, logit))))
        malicious = probability >= self.threshold
        contributions = scaled * self.coefficients
        ranked = np.argsort(np.abs(contributions))[::-1][:5]
        return {
            "prediction": "ransomware_like" if malicious else "benign",
            "confidence": round(probability if malicious else 1 - probability, 6),
            "risk_score": round(probability * 100),
            "model_version": self.version,
            "top_contributing_features": [
                {
                    "feature": FEATURE_NAMES[index],
                    "contribution": round(float(contributions[index]), 5),
                }
                for index in ranked
            ],
        }


def _number(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise ValueError("Model artifact contains an invalid number")
    return float(value)


def load_model(path: Path) -> Model:
    if not path.is_file() or path.stat().st_size > MAX_ARTIFACT_BYTES:
        raise ValueError("Model artifact is missing or oversized")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(document, dict) or document.get("format") != ARTIFACT_FORMAT:
            raise ValueError("Unsupported model artifact format")
        payload = document["model"]
        if not isinstance(payload, dict) or payload["features"] != list(FEATURE_NAMES):
            raise ValueError("Model feature schema mismatch")
        digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
        if digest != document["sha256"]:
            raise ValueError("Model artifact checksum mismatch")
        means = np.asarray([_number(x) for x in payload["means"]], dtype=np.float64)
        scales = np.asarray([_number(x) for x in payload["scales"]], dtype=np.float64)
        coefficients = np.asarray([_number(x) for x in payload["coefficients"]], dtype=np.float64)
        if any(len(vector) != len(FEATURE_NAMES) for vector in (means, scales, coefficients)):
            raise ValueError("Model coefficient length mismatch")
        if np.any(scales <= 0):
            raise ValueError("Model scales must be positive")
        threshold = _number(payload["threshold"])
        if not 0 < threshold < 1:
            raise ValueError("Invalid model threshold")
        version = payload["version"]
        if not isinstance(version, str) or not version or len(version) > 64:
            raise ValueError("Invalid model version")
        return Model(version, threshold, means, scales, coefficients, _number(payload["intercept"]))
    except (KeyError, TypeError, json.JSONDecodeError, UnicodeError) as exc:
        raise ValueError("Invalid model artifact") from exc


def save_model(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
    document = {"format": ARTIFACT_FORMAT, "sha256": digest, "model": payload}
    candidate = path.with_suffix(path.suffix + ".tmp")
    candidate.write_text(json.dumps(document, indent=2, sort_keys=True), encoding="utf-8")
    candidate.replace(path)
