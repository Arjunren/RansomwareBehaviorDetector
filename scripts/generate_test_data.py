"""Deterministic synthetic telemetry for smoke tests only."""

import argparse
import csv
import random
from pathlib import Path

from ransomware_behavior_detector.features import RAW_FIELDS

BENIGN = {
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
POSITIVE = {
    "window_seconds": 300,
    "file_modify_count": 800,
    "file_rename_count": 750,
    "file_delete_count": 50,
    "extension_change_count": 700,
    "high_entropy_write_count": 700,
    "mean_entropy_delta": 2.5,
    "unique_directories_touched": 100,
    "process_spawn_count": 8,
    "bytes_written": 100000000,
    "protected_file_touch_count": 10,
}
BOUNDS = {
    "window_seconds": (60, 86400, "float"),
    "file_modify_count": (0, 1000000, "int"),
    "file_rename_count": (0, 1000000, "int"),
    "file_delete_count": (0, 1000000, "int"),
    "extension_change_count": (0, 1000000, "int"),
    "high_entropy_write_count": (0, 1000000, "int"),
    "mean_entropy_delta": (-8, 8, "float"),
    "unique_directories_touched": (0, 1000000, "int"),
    "process_spawn_count": (0, 1000000, "int"),
    "bytes_written": (0, 1000000000000, "float"),
    "protected_file_touch_count": (0, 1000000, "int"),
}


def generate(output: Path) -> None:
    rng = random.Random(42)  # noqa: S311  # nosec B311
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=[*RAW_FIELDS, "group_id", "label"])
        writer.writeheader()
        for label, baseline in ((0, BENIGN), (1, POSITIVE)):
            for index in range(80):
                row = {}
                for name, base in baseline.items():
                    lower, upper, kind = BOUNDS[name]
                    if kind == "int":
                        jitter = rng.randint(-2, 2)
                        row[name] = int(max(lower, min(upper, base + jitter)))
                    else:
                        jitter = rng.uniform(-0.05, 0.05) * max(abs(base), 1)
                        row[name] = float(max(lower, min(upper, base + jitter)))
                row["extension_change_count"] = min(
                    row["extension_change_count"], row["file_rename_count"]
                )
                row["high_entropy_write_count"] = min(
                    row["high_entropy_write_count"], row["file_modify_count"]
                )
                writer.writerow({**row, "group_id": f"{label}-{index}", "label": label})


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path("data/processed/synthetic.csv"))
    args = parser.parse_args()
    generate(args.output)
    print(args.output)


if __name__ == "__main__":
    main()
