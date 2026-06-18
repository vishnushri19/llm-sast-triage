# Abstract

Static application security testing (SAST) tools can identify vulnerable code patterns, but security teams often struggle with duplicate findings, severity noise, and false-positive or hardening-only results. This project presents a hybrid SAST triage workflow that keeps the scanner as the source of truth while using deterministic clustering and a local large language model (LLM) to improve finding readability and remediation guidance.

The prototype scans small Python applications with Semgrep, groups related findings without dropping scanner check IDs, applies deterministic rules for high-confidence vulnerability classes, and uses a local Ollama model to generate impact and minimal safe-fix explanations. The design intentionally limits LLM authority: the LLM does not invent findings, remove scanner evidence, or decide evidence integrity. Validation checks ensure that every Semgrep check ID remains represented in the final triage output.

An initial evaluation across five targets covers command injection, eval-based code injection, SQL injection, subprocess hardening, and eval hardening cases. The prototype reduced nine raw Semgrep findings into five triage clusters, achieving a 1.80x compression ratio while preserving all scanner check IDs. The initial dataset shows 1.00 recall, 1.00 severity accuracy, and 1.00 false-positive triage accuracy, with 0 missing and 0 extra check IDs.

These early results suggest that a controlled hybrid approach can make SAST output more actionable without treating the LLM as an independent security authority. The current work is an initial prototype and requires broader validation across larger applications, additional languages, more vulnerability classes, and multiple local LLMs.
