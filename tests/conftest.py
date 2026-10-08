from pathlib import Path

import pytest

from ransomware_behavior_detector.artifact import Model, load_model, save_model
from ransomware_behavior_detector.features import FEATURE_NAMES, Observation


@pytest.fixture
def observation() -> Observation:
    return Observation.model_validate(
        {
            "window_seconds": 300,
            "file_modify_count": 15,
            "file_rename_count": 2,
            "file_delete_count": 1,
            "extension_change_count": 0,
            "high_entropy_write_count": 1,
            "mean_entropy_delta": 0.1,
            "unique_directories_touched": 2,
            "process_spawn_count": 1,
            "bytes_written": 100000,
            "protected_file_touch_count": 0,
        }
    )


@pytest.fixture
def model(tmp_path: Path) -> Model:
    size = len(FEATURE_NAMES)
    payload = {
        "features": list(FEATURE_NAMES),
        "means": [0.0] * size,
        "scales": [1.0] * size,
        "coefficients": [0.001] * size,
        "intercept": -1.0,
        "threshold": 0.5,
        "version": "test-1",
    }
    path = tmp_path / "model.json"
    save_model(path, payload)
    return load_model(path)
