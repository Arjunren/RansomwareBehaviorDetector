import numpy as np
import pytest
from pydantic import ValidationError

from ransomware_behavior_detector.features import FEATURE_NAMES, Observation, extract_features


def test_features_are_finite_and_deterministic(observation: Observation) -> None:
    first = extract_features(observation)
    assert len(first) == len(FEATURE_NAMES)
    assert np.array_equal(first, extract_features(observation))
    assert np.all(np.isfinite(first))


def test_invalid_observation_rejected(observation: Observation) -> None:
    with pytest.raises(ValidationError):
        Observation.model_validate({**observation.model_dump(), "window_seconds": -1})
    with pytest.raises(ValidationError):
        Observation.model_validate({**observation.model_dump(), "unexpected": 1})
