# Dataset handling

The [MLRan research dataset](https://github.com/faithfulco/mlran) provides processed ransomware behavioral features and goodware comparisons. Consult its source license and citation requirements; this project does not download, bundle, execute, or redistribute raw binaries or source data. MLRan's published features are not a direct match to this schema, so select comparable safe telemetry fields locally and review labels before training. The repository's own `scripts/prepare_telemetry.py` converts authorized, structured process/file-operation metadata into windowed CSV without touching any actual files. Training CSVs require numeric fields listed in `src/ransomware_behavior_detector/features.py`, `group_id`, and reviewed binary `label` (0 benign, 1 ransomware-like). Related windows from the same collection campaign or process lineage must share a group. Raw and processed data are Git ignored.

`scripts/prepare_telemetry.py` reads local JSONL events. Each event needs timezone-aware ISO 8601 `timestamp`; `operation` as `modify`, `rename`, `delete`, `create`, or `process_spawn`; opaque `process_group` and `directory_id`; numeric `bytes_written`, `entropy_before`, and `entropy_after`; boolean `extension_changed` and `protected_file`; and integer `reviewed_label` 0 or 1. Entropies are precomputed safe metadata in the 0–8 bit range. No file contents or paths are read by this script. The `process_group` should identify a process lineage or collection campaign. Every event in a window must have the same reviewed label.

Example inert event:

```json
{"timestamp":"2026-01-01T12:00:00Z","operation":"modify","process_group":"reviewed-process-001","directory_id":"opaque-directory-1","bytes_written":1024,"entropy_before":3.0,"entropy_after":7.5,"extension_changed":false,"protected_file":true,"reviewed_label":1}
```

Run `python scripts/prepare_telemetry.py --input data/raw/events.jsonl --output data/processed/training.csv`. The script writes 5-minute process-group windows and replaces group identities with numeric IDs. It counts high-entropy writes when post-write entropy is at least 7 and rises by at least 1 bit. Review the provenance of these measurements and labels. Synthetic data from `scripts/generate_test_data.py` is a smoke-test fixture only; it does not simulate or execute ransomware. Both raw and aggregate telemetry may be sensitive.
