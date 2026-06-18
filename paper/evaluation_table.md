## Evaluation Table

Table 1 summarizes the initial five-target evaluation.

| Target | Raw Findings | LLM Clusters | Compression | TP Labels | FP Labels | Precision | Recall | Severity Accuracy | FP Triage Accuracy |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| myapp | 3 | 1 | 3.00x | 3 | 0 | 1.00 | 1.00 | 1.00 | 1.00 |
| evalapp | 3 | 1 | 3.00x | 3 | 0 | 1.00 | 1.00 | 1.00 | 1.00 |
| sqlapp | 1 | 1 | 1.00x | 1 | 0 | 1.00 | 1.00 | 1.00 | 1.00 |
| safeapp | 1 | 1 | 1.00x | 0 | 1 | 0.00 | 0.00 | 1.00 | 1.00 |
| safeevalapp | 1 | 1 | 1.00x | 0 | 1 | 0.00 | 0.00 | 1.00 | 1.00 |
| **Overall** | **9** | **5** | **1.80x** | **7** | **2** | **0.78** | **1.00** | **1.00** | **1.00** |

The results show that the pipeline reduced nine raw findings into five clusters while preserving scanner evidence. The overall precision is lower than recall because the dataset intentionally includes hardening-only and likely false-positive cases, but severity accuracy and false-positive triage accuracy remained perfect in this initial evaluation.
