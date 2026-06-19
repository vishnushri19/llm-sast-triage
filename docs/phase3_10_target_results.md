# Phase 3 10-Target Evaluation Results

## Status

Phase 3 expanded the evaluation from 5 targets to 10 targets.

## Targets

| Target | Pattern |
|---|---|
| myapp | Command injection |
| safeapp | Subprocess hardening / likely false positive |
| evalapp | Eval/code injection |
| safeevalapp | Eval hardening / likely false positive |
| sqlapp | SQL injection |
| pathapp | Path traversal |
| ssrfapp | SSRF and insecure transport |
| yamlapp | Unsafe YAML deserialization |
| pickleapp | Unsafe pickle deserialization |
| redirectapp | Open redirect |

## Overall Results

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

## Interpretation

The 10-target evaluation confirms that the scanner-first pipeline continues to preserve Semgrep evidence while expanding to additional vulnerability classes. The pipeline reduced 19 raw Semgrep findings into 11 triage clusters while preserving all Semgrep check IDs. Recall, severity accuracy, and false-positive triage accuracy remained 1.00 in this controlled evaluation.

The precision score remained 0.89 because the dataset intentionally includes hardening-oriented and lower-risk findings. This is useful for testing whether the system can separate confirmed exploit paths from findings that require lower-priority review.

## Notes

This result should be treated as a controlled prototype result, not a broad benchmark claim. The next improvement should be testing larger real-world repositories and adding more vulnerability classes.
