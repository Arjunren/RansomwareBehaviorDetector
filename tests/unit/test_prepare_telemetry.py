import csv
import json
from pathlib import Path

import pytest

from scripts.prepare_telemetry import normalize, prepare


def test_safe_event_aggregation(tmp_path: Path) -> None:
    events = [
        {
            "timestamp": "2026-01-01T12:00:00Z",
            "operation": "modify",
            "process_group": "private-process",
            "directory_id": "private-directory",
            "bytes_written": 1024,
            "entropy_before": 3.0,
            "entropy_after": 7.5,
            "extension_changed": False,
            "protected_file": True,
            "reviewed_label": 1,
        },
        {
            "timestamp": "2026-01-01T12:00:01Z",
            "operation": "rename",
            "process_group": "private-process",
            "directory_id": "private-directory",
            "bytes_written": 0,
            "entropy_before": 0,
            "entropy_after": 0,
            "extension_changed": True,
            "protected_file": False,
            "reviewed_label": 1,
        },
    ]
    source = tmp_path / "events.jsonl"
    source.write_text("\n".join(json.dumps(item) for item in events) + "\n", encoding="utf-8")
    output = tmp_path / "training.csv"
    assert prepare(source, output) == 1
    with output.open(newline="", encoding="utf-8") as handle:
        row = next(csv.DictReader(handle))
    assert row["high_entropy_write_count"] == "1"
    assert row["extension_change_count"] == "1"
    assert "private" not in output.read_text(encoding="utf-8")


def test_rejects_inconsistent_event() -> None:
    with pytest.raises(ValueError):
        normalize(
            {
                "timestamp": "2026-01-01T12:00:00Z",
                "operation": "modify",
                "process_group": "one",
                "directory_id": "two",
                "bytes_written": 0,
                "entropy_before": 0,
                "entropy_after": 0,
                "extension_changed": True,
                "protected_file": False,
                "reviewed_label": 0,
            }
        )
