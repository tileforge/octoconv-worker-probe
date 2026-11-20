# octoconv-worker-probe

Probe worker for OctoConv. One process serves one approved sanitize manifest over Worker Protocol v2.

The process reads `PROBE_PROTOCOL_CORE_URL`, `PROBE_PROTOCOL_CLIENT_CERT`, `PROBE_PROTOCOL_CLIENT_KEY`, `PROBE_PROTOCOL_CLIENT_CA`, `PROBE_PROTOCOL_WORKER_ID`, and `PROBE_PROTOCOL_MANIFEST_PATH`. It refuses to start when `DATABASE_URL` or `REDIS_ADDR` is set. `PROBE_WORKER_CONCURRENCY` must be unset or `1`.

`schema/manifest-probe-sanitize.json` is capability `octoconv.sanitize.probe` version 1. The client operation is sanitize. The legacy engine is probe. `parameter_schema` is empty. Any parameter key fails before sanitize starts. One source input is accepted. The primary output is the sanitized file. The report output is role `report`, ordinal 1, format `json`. Macro-enabled OOXML is delivered as its macro-free extension. pdf, jpg, and png stay identity pairs.

`gs`, `pdfinfo`, `unzip`, and `file` must be on `PATH`. The default attempt budget is 600s (`PROBE_ENGINE_TIMEOUT`). The input ceiling is 50 MiB. The assignment output ceiling is 100 MiB. `PROBE_MAX_PAGES` defaults to 200. Landlock uses the probe ruleset. `PROBE_SANDBOX_DISABLED=true` turns filesystem confinement off. A sandbox setup failure exits 78. The manifest is not approved.
