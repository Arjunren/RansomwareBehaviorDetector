# Model card — RansomwareBehaviorDetector 1.0.0

| Field | Description |
| --- | --- |
| Purpose | The detector scores process-level time windows for ransomware-like file modification, rename, entropy-change, and extension-change patterns using safe metadata only. |
| Model type | Standardized numeric features and class-weighted logistic regression. |
| Training dataset | Operator-provided, reviewed metadata windows; MLRan is a possible research source but needs local schema adaptation. No data bundled. |
| Feature set | window_seconds, file_modify_count, file_rename_count, file_delete_count, extension_change_count, high_entropy_write_count, mean_entropy_delta, unique_directories_touched, process_spawn_count, bytes_written, protected_file_touch_count, modifications_per_minute, renames_per_minute, extension_change_ratio, high_entropy_write_ratio, bytes_written_log. |
| Evaluation metrics | Precision, recall, F1, ROC-AUC, PR-AUC, FPR, FNR, confusion matrix, and class support in per-training metadata. No default score claimed. |
| Known limitations | Backup, migration, indexing, and bulk software updates can resemble rapid file operations; low-rate or selective attacks can evade short windows. |
| Bias considerations | Source coverage and labeling can differ across entities, time, and environments; inspect group-level error rates. |
| Security considerations | Validate telemetry, protect datasets against poisoning, and review artifact provenance. |
| Intended use | Analyst decision support and research baseline. |
| Out-of-scope use | Sole high-impact control or claim of confirmed maliciousness. |
| Version | JSON format `ransomware-behavior-detector-logreg-v1`; model version supplied at training. |

Confidence is a model estimate, not certainty. Local feature contributions describe the linear score and are not causal proof.
