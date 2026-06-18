# Results

This section summarizes the current prototype evaluation.

## Dataset

The current evaluation uses five small Python targets:

| Target | Purpose |
|---|---|
| `myapp` | Real subprocess command injection |
| `evalapp` | Real eval code injection |
| `sqlapp` | Real SQL injection |
| `safeapp` | Subprocess hardening / false-positive case |
| `safeevalapp` | Eval hardening / false-positive case |

## Overall Results

| Metric | Value |
|---|---:|
| Targets evaluated | 5 |
| Total raw Semgrep findings | 9 |
| Total LLM triage clusters | 5 |
| Overall compression ratio | 1.80x |
| Overall precision | 0.78 |
| Overall recall | 1.00 |
| Overall severity accuracy | 1.00 |
| Overall false-positive triage accuracy | 1.00 |
| Missing Semgrep check IDs | 0 |
| Extra Semgrep check IDs | 0 |

## Interpretation

The prototype reduced nine raw Semgrep findings into five triage clusters while preserving all scanner check IDs. The initial results show that deterministic clustering can reduce duplicate or related findings without losing scanner evidence.

The precision value is lower than 1.00 because the dataset intentionally includes false-positive or hardening-only findings. This is expected. The more important measurement for those cases is false-positive triage accuracy, which is currently 1.00 on the initial dataset.

The current result should be treated as an early validation of the pipeline design, not as a general claim about all SAST findings or all application frameworks.
