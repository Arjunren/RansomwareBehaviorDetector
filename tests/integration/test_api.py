from fastapi.testclient import TestClient

from ransomware_behavior_detector.api import create_app
from ransomware_behavior_detector.artifact import Model
from ransomware_behavior_detector.config import Settings
from ransomware_behavior_detector.features import Observation


def test_api_validation_and_limits(observation: Observation, model: Model) -> None:
    api = TestClient(
        create_app(
            Settings(
                app_env="test", api_key="test-secret", max_batch_size=2, max_request_bytes=1024
            ),
            model,
        )
    )
    assert api.get("/health").status_code == 200
    assert api.get("/ready").status_code == 200
    assert api.get("/version").json()["model"] == "test-1"
    body = {"observation": observation.model_dump()}
    assert api.post("/api/v1/predict", json=body).status_code == 401
    headers = {"X-API-Key": "test-secret"}
    result = api.post("/api/v1/predict", headers=headers, json=body)
    assert result.status_code == 200
    assert result.json()["prediction"] in {"benign", "ransomware_like"}
    assert api.post("/api/v1/predict", headers=headers, json={}).status_code == 422
    assert api.post("/api/v1/predict", headers=headers, json={"observation": {}}).status_code == 422
    assert (
        api.post(
            "/api/v1/batch-predict",
            headers=headers,
            json={"observations": [observation.model_dump()] * 3},
        ).status_code
        == 413
    )
    assert (
        api.post(
            "/api/v1/predict", headers={**headers, "Content-Type": "text/plain"}, content="bad"
        ).status_code
        == 415
    )
    assert (
        api.post(
            "/api/v1/predict",
            headers={**headers, "Content-Type": "application/json"},
            content=b"x" * 1025,
        ).status_code
        == 413
    )
