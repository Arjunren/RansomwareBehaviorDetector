# Security review

## Threat model

An adversary may submit malformed or oversized filesystem and process telemetry, poison a training CSV, probe scores, or replace a writable model artifact. Protect availability, prediction integrity, sensitive telemetry, and the API credential. Predictions can affect analyst workload and must be reviewed.

## Attack surface and controls

- Pydantic rejects missing, extra, out-of-range, NaN, and infinite numeric fields. Feature engineering performs fixed-cost local calculations.
- The preparation script handles only locally supplied event metadata; it does not open target files, inspect file contents, execute malware, or perform destructive actions. File paths and process identifiers are omitted from the aggregate CSV. Labels and entropy measurements must come from a trusted collection pipeline.
- Body, batch, worker, queue, and inference-time limits reduce resource exhaustion. Put TLS, per-client rate limits, identity, and authorization at a gateway.
- Production requires a strong shared API key checked with constant-time comparison. The key is not tenant-level authorization; enforce server-side roles and object/function access for multi-tenant use. UUIDs are not authorization.
- Training validates labels and groups, rejects conflicting duplicates, keeps groups disjoint, and fits preprocessing only on training data. Review source records for poisoning.
- Strict JSON model artifacts validate format, feature order, finite numbers, dimensions, size, and checksum. No arbitrary Python deserialization is used. Trusted artifact storage and release review establish provenance.
- Logs include route template, status, and duration only; no raw observations, passwords, tokens, or sensitive identifiers. Docker runs non-root with read-only filesystem and dropped capabilities. CI runs Ruff, mypy, pytest, Bandit, and pip-audit.

## OWASP considerations and residual risks

No submitted value drives a shell command, SQL query, or outbound URL fetch. Errors use generic messages. Timed-out workers may finish after the HTTP timeout but remain counted against capacity. Shared-key mode lacks tenant roles. Dataset poisoning, model probing, drift, and false positives/negatives remain possible. Use reviewed releases, gateway controls, monitoring, and analyst decisions.
