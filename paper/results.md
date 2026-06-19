# Results

## Dataset

The Phase 3 evaluation uses ten Python targets. The dataset includes confirmed vulnerability paths and hardening-oriented cases. The targets cover command injection, eval/code injection, SQL injection, path traversal, SSRF, insecure transport, unsafe YAML deserialization, unsafe pickle deserialization, open redirect, and two likely false-positive or hardening-only cases.

The evaluation remains intentionally controlled. Each Semgrep finding, label, and triage cluster can be manually inspected. The goal is to validate the scanner-first workflow and evidence-preservation behavior before scaling to larger real-world repositories.

## Overall Results

Across the ten targets, Semgrep produced 19 raw findings. The triage pipeline reduced these findings into 11 final clusters, giving an overall compression ratio of 1.73x. The evaluation produced 0.89 precision, 1.00 recall, 1.00 severity accuracy, and 1.00 false-positive triage accuracy.

No Semgrep check IDs were dropped or invented. Total missing check IDs were 0, and total extra check IDs were 0.

## Interpretation

The results show that the pipeline continues to preserve scanner evidence while expanding to additional vulnerability classes. The system grouped related Semgrep findings into fewer analyst-facing clusters while preserving the original check IDs, file paths, and line references.

The precision score remained below 1.00 because the dataset intentionally includes hardening-oriented and likely false-positive findings. This is useful for testing whether the workflow can distinguish confirmed exploit paths from findings that should receive lower-priority review.

The strongest result is evidence preservation. Even after clustering and LLM enrichment, the final output retained all Semgrep check IDs and did not introduce unsupported check IDs. This supports the paper claim that the LLM can be used as an explanation layer without becoming the source of truth.

## Phase 3 Result Summary

| Metric | Result |
|---|---:|
| Targets evaluated | 10 |
| Total raw findings | 19 |
| Total LLM clusters | 11 |
| Overall compression ratio | 1.73x |
| Overall precision | 0.89 |
| Overall recall | 1.00 |
| Overall severity accuracy | 1.00 |
| Overall false-positive triage accuracy | 1.00 |
| Total missing check IDs | 0 |
| Total extra check IDs | 0 |
