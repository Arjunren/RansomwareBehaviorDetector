"""Aggregate inert filesystem/process event metadata into reviewed windows."""

from __future__ import annotations

import argparse
import csv
import json
import math
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from ransomware_behavior_detector.features import RAW_FIELDS, Observation

OPERATIONS = {"modify", "rename", "delete", "create", "process_spawn"}
MAX_FILE_BYTES = 128 * 1024 * 1024
MAX_LINE_BYTES = 4096
MAX_EVENTS = 1_000_000


def normalize(record: dict[str, Any]) -> dict[str, Any]:
    raw_time = record.get("timestamp")
    if not isinstance(raw_time, str) or len(raw_time) > 64:
        raise ValueError("Invalid timestamp")
    try:
        timestamp = datetime.fromisoformat(raw_time.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("Invalid timestamp") from exc
    if timestamp.tzinfo is None:
        raise ValueError("Timestamp must include a timezone")
    operation = record.get("operation")
    if not isinstance(operation, str) or operation not in OPERATIONS:
        raise ValueError("Invalid operation")
    group = record.get("process_group")
    directory = record.get("directory_id")
    if not isinstance(group, str) or not 1 <= len(group) <= 128:
        raise ValueError("Invalid process_group")
    if not isinstance(directory, str) or not 1 <= len(directory) <= 128:
        raise ValueError("Invalid directory_id")
    extension_changed = record.get("extension_changed")
    protected_file = record.get("protected_file")
    if type(extension_changed) is not bool or type(protected_file) is not bool:
        raise ValueError("Event flags must be booleans")
    if extension_changed and operation != "rename":
        raise ValueError("Only a rename event can change an extension")
    label = record.get("reviewed_label")
    if type(label) is not int or label not in (0, 1):
        raise ValueError("reviewed_label must be 0 or 1")
    numeric: dict[str, float] = {}
    for name, maximum in (("bytes_written", 1e12), ("entropy_before", 8), ("entropy_after", 8)):
        value = record.get(name)
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            or not 0 <= value <= maximum
        ):
            raise ValueError(f"Invalid {name}")
        numeric[name] = float(value)
    return {
        "timestamp": timestamp.astimezone(UTC),
        "operation": operation,
        "group": group,
        "directory": directory,
        "extension_changed": extension_changed,
        "protected_file": protected_file,
        "label": label,
        **numeric,
    }


def prepare(source: Path, output: Path, window_seconds: int = 300) -> int:
    if source.resolve() == output.resolve():
        raise ValueError("Input and output paths must differ")
    if not 60 <= window_seconds <= 86400:
        raise ValueError("window_seconds must be between 60 and 86400")
    if source.stat().st_size > MAX_FILE_BYTES:
        raise ValueError("Source file is too large")
    windows: dict[tuple[str, int], list[dict[str, Any]]] = defaultdict(list)
    with source.open("rb") as handle:
        for number, raw in enumerate(handle, 1):
            if number > MAX_EVENTS or len(raw) > MAX_LINE_BYTES:
                raise ValueError("Source exceeds event or line limit")
            try:
                record = json.loads(raw)
                if not isinstance(record, dict):
                    raise ValueError("Event must be an object")
                event = normalize(record)
            except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
                raise ValueError(f"Invalid event at line {number}") from exc
            bucket = math.floor(event["timestamp"].timestamp() / window_seconds)
            windows[(event["group"], bucket)].append(event)
    if not windows:
        raise ValueError("No telemetry events")
    group_ids = {group: index for index, group in enumerate(sorted({key[0] for key in windows}))}
    rows: list[dict[str, Any]] = []
    for (group, _bucket), events in sorted(windows.items()):
        labels = {event["label"] for event in events}
        if len(labels) != 1:
            raise ValueError("Every event in a window needs the same reviewed_label")
        modifications = [event for event in events if event["operation"] == "modify"]
        file_events = [event for event in events if event["operation"] != "process_spawn"]
        fields = {
            "window_seconds": window_seconds,
            "file_modify_count": len(modifications),
            "file_rename_count": sum(event["operation"] == "rename" for event in events),
            "file_delete_count": sum(event["operation"] == "delete" for event in events),
            "extension_change_count": sum(event["extension_changed"] for event in events),
            "high_entropy_write_count": sum(
                event["entropy_after"] >= 7
                and event["entropy_after"] - event["entropy_before"] >= 1
                for event in modifications
            ),
            "mean_entropy_delta": (
                sum(event["entropy_after"] - event["entropy_before"] for event in modifications)
                / len(modifications)
                if modifications
                else 0.0
            ),
            "unique_directories_touched": len({event["directory"] for event in file_events}),
            "process_spawn_count": sum(event["operation"] == "process_spawn" for event in events),
            "bytes_written": sum(event["bytes_written"] for event in modifications),
            "protected_file_touch_count": sum(
                event["protected_file"]
                for event in events
                if event["operation"] in ("modify", "rename", "delete")
            ),
        }
        try:
            Observation.model_validate(fields)
        except ValidationError as exc:
            raise ValueError("Invalid window aggregate") from exc
        rows.append({**fields, "group_id": group_ids[group], "label": labels.pop()})
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=[*RAW_FIELDS, "group_id", "label"])
        writer.writeheader()
        writer.writerows(rows)
    return len(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--window-seconds", type=int, default=300)
    args = parser.parse_args()
    print(f"wrote {prepare(args.input, args.output, args.window_seconds)} windows")


if __name__ == "__main__":
    main()
