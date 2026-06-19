## Evaluation Table

Table 1 summarizes the ten-target Phase 3 evaluation.

| Target | Pattern | Raw Findings | LLM Clusters | Notes |
|---|---|---:|---:|---|
| myapp | Command injection | 3 | 1 | Confirmed user-controlled subprocess path |
| safeapp | Subprocess hardening | 1 | 1 | Likely false-positive / hardening-only case |
| evalapp | Eval/code injection | 3 | 1 | Confirmed user-controlled eval path |
| safeevalapp | Eval hardening | 1 | 1 | Likely false-positive / hardening-only case |
| sqlapp | SQL injection | 1 | 1 | Confirmed user-controlled SQL construction |
| pathapp | Path traversal | 2 | 1 | Confirmed user-controlled file path access |
| ssrfapp | SSRF and insecure transport | 3 | 2 | SSRF cluster plus insecure transport cluster |
| yamlapp | Unsafe YAML deserialization | 2 | 1 | Confirmed request body reaching yaml.load |
| pickleapp | Unsafe pickle deserialization | 2 | 1 | Confirmed user-controlled pickle.loads path |
| redirectapp | Open redirect | 1 | 1 | Confirmed user-controlled redirect target |
| **Overall** | **All targets** | **19** | **11** | **1.73x compression ratio** |

| Metric | Result |
|---|---:|
| Precision | 0.89 |
| Recall | 1.00 |
| Severity accuracy | 1.00 |
| False-positive triage accuracy | 1.00 |
| Missing check IDs | 0 |
| Extra check IDs | 0 |

The results show that the pipeline reduced 19 raw Semgrep findings into 11 triage clusters while preserving all scanner check IDs. This supports the scanner-first design goal: the LLM enriches the analyst-facing explanation, while deterministic validation protects the evidence trail.
