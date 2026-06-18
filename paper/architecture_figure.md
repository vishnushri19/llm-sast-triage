## Architecture Figure

Figure 1 shows the scanner-first workflow used in this project.

```text
+-------------------+    +---------------------------+    +------------------------+
| Python targets    | -> | Semgrep scan              | -> | Raw JSON findings      |
| (example apps)    |    | (security-audit, owasp,   |    | data/findings/*.json   |
|                   |    |  secrets rules)           |    |                        |
+-------------------+    +---------------------------+    +------------------------+
                                                                   |
                                                                   v
+-------------------+    +---------------------------+    +------------------------+
| Manual labels     | -> | Evaluation                | <- | Deterministic triage   |
| labels/*.json     |    | precision, recall,        |    | clustering, severity,  |
|                   |    | severity, FP accuracy     |    | evidence validation    |
+-------------------+    +---------------------------+    +------------------------+
                                                                   |
                                                                   v
                                                        +------------------------+
                                                        | Local Ollama           |
                                                        | impact + fix text      |
                                                        +------------------------+
                                                                   |
                                                                   v
                                                        +------------------------+
                                                        | Final triage output    |
                                                        | data/rankings/*.json   |
                                                        +------------------------+
```

The key design principle is that Semgrep remains the source of truth. Deterministic logic preserves scanner evidence and performs clustering before the local LLM is used only for explanation and remediation enrichment.
