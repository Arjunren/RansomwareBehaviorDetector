from pathlib import Path

import pytest

from ransomware_behavior_detector.artifact import load_model


def test_rejects_pickle_and_oversized_artifacts(tmp_path: Path) -> None:
    artifact = tmp_path / "model.json"
    artifact.write_bytes(b"\x80\x04pickle")
    with pytest.raises(ValueError):
        load_model(artifact)
    artifact.write_bytes(b" " * 65537)
    with pytest.raises(ValueError):
        load_model(artifact)
