# System Design

The prototype is organized as a scanner-first SAST triage pipeline. The design separates evidence collection, deterministic triage, LLM enrichment, and evaluation so that each stage can be inspected independently. This separation is important because the project does not treat the LLM as the source of security truth. The scanner produces evidence, deterministic logic preserves and organizes that evidence, and the LLM improves readability only after validation constraints are applied.

## Design Goals

The system has four design goals.

First, scanner evidence must be preserved. Every Semgrep finding contains a check ID, file path, line number, message, severity, and code context. The triage pipeline must not drop or invent check IDs. This is enforced by validating the final LLM-enriched output against the original scanner output.

Second, related findings should be grouped into actionable clusters. A single vulnerable code path may trigger multiple Semgrep rules. Presenting each finding independently can increase reviewer effort. The pipeline therefore groups related findings by vulnerability pattern, file, and evidence signals.

Third, high-confidence vulnerability patterns should be handled deterministically. For cases such as command injection, eval-based code injection, and SQL injection, the pipeline checks whether user-controlled input reaches a dangerous operation. When that condition is present, the cluster is marked as a likely true positive. When only a dangerous API is present without demonstrated user-controlled input, the cluster can be treated as hardening or likely false positive.

Fourth, the LLM should improve explanation quality without controlling evidence integrity. The local LLM generates impact and minimal safe-fix text, but deterministic validation checks whether all scanner check IDs remain represented. If the LLM output drops or adds check IDs, the output is rejected.

## Pipeline Components

The system contains four main scripts.

`run_scans.py` runs Semgrep against the target applications and writes raw JSON findings into `data/findings/`. On Windows, the current workflow uses the Semgrep Docker image so that scanning remains reproducible across local environments.

`llm_rank.py` reads the raw Semgrep JSON files, clusters related findings, applies deterministic severity and false-positive rules, calls the local Ollama model for explanation text, and validates the final output. The output is written to `data/rankings/`.

`eval.py` compares raw findings, LLM-assisted clusters, and manually created labels. It reports raw finding count, cluster count, compression ratio, finding-level precision and recall, severity accuracy, false-positive triage accuracy, and missing or extra check IDs.

`run_pipeline.py` executes the complete pipeline in order: scan, triage, and evaluate.

## Evidence Preservation

Evidence preservation is the central safety property of the design. The pipeline extracts the set of Semgrep check IDs from raw scanner output and compares it with the set of check IDs present in the final triage output. The output is accepted only when the final set covers the scanner check IDs without adding unsupported check IDs.

This validation does not prove that every explanation is perfect, but it prevents a major class of LLM failure: silently dropping scanner evidence or inventing unsupported findings. The reviewer can still trace each cluster back to the original Semgrep rule, file, and line number.

## Deterministic Triage Rules

The prototype currently includes deterministic rules for several vulnerability classes:

- Command injection: user-controlled input reaches subprocess execution.
- Code injection: user-controlled input reaches eval-style execution.
- SQL injection: user-controlled input reaches SQL query construction or execution.
- Subprocess hardening: subprocess usage is present, but no user-controlled input is shown reaching the command.
- Eval hardening: eval usage is present, but no user-controlled input is shown reaching the expression.

These rules are intentionally conservative. Confirmed user-controlled flows are prioritized as true positives. Dangerous API usage without demonstrated user-controlled input is retained as a lower-risk hardening case rather than discarded completely.

## Local LLM Enrichment

The prototype uses a local Ollama model for enrichment. The model receives structured cluster context and is asked to generate concise impact and remediation guidance. The LLM is not allowed to define the set of findings. It does not decide which Semgrep check IDs exist, and its output is validated before being accepted.

Using a local model also supports reproducibility and privacy. Source snippets and findings do not need to be sent to an external API. This is useful for organizations that cannot share application code with third-party services.

## Evaluation Design

The evaluation uses small labeled targets so that each expected result can be inspected manually. Each target includes a label file describing the expected check ID, file, line, true-positive status, severity, and category. The evaluator then compares scanner output and triage output against those labels.

The current metrics are designed to answer three questions:

1. Does the scanner evidence remain covered after LLM-assisted triage?
2. Does clustering reduce duplicate or related findings?
3. Does the triage logic correctly distinguish confirmed vulnerabilities from hardening or false-positive cases?

The current results are early and should not be interpreted as broad generalization. They validate the architecture and measurement approach before scaling to larger datasets.
