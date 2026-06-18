# Initial Evaluation Table

| Target | Purpose | Raw Findings | LLM Clusters | Compression | Labeled TP | Labeled FP | Severity Accuracy | FP Triage Accuracy |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| evalapp | Real eval code injection | 3 | 1 | 3.00x | 3 | 0 | 1.00 | 1.00 |
| myapp | Real subprocess command injection | 3 | 1 | 3.00x | 3 | 0 | 1.00 | 1.00 |
| safeapp | Subprocess hardening / false positive | 1 | 1 | 1.00x | 0 | 1 | 1.00 | 1.00 |
| safeevalapp | Eval hardening / false positive | 1 | 1 | 1.00x | 0 | 1 | 1.00 | 1.00 |
| sqlapp | Real SQL injection | 1 | 1 | 1.00x | 1 | 0 | 1.00 | 1.00 |

## Overall Results

| Metric | Value |
|---|---:|
| Targets evaluated | 5 |
| Total raw findings | 9 |
| Total LLM clusters | 5 |
| Overall compression ratio | 1.80x |
| Overall precision | 0.78 |
| Overall recall | 1.00 |
| Overall severity accuracy | 1.00 |
| Overall false-positive triage accuracy | 1.00 |
| Missing check IDs | 0 |
| Extra check IDs | 0 |
