# Methodology

The methodology evaluates whether a scanner-first LLM-assisted workflow can make SAST findings easier to triage while preserving scanner evidence. The experiment is designed around a conservative principle: Semgrep produces the security evidence, deterministic logic organizes and validates that evidence, and the local LLM is used only to enrich the final cluster with impact and remediation text.

## Experimental Setup

The prototype scans Python targets with Semgrep using Docker. Each target is a small application or code sample designed to exercise one vulnerability pattern or one hardening-only pattern. The scan output is stored as raw JSON under `data/findings/`. This raw output is treated as the source of truth for check IDs, file paths, line numbers, scanner messages, and matched code.

The LLM enrichment stage uses a local Ollama model. The model receives structured context derived from Semgrep findings and returns explanation-oriented fields such as impact, minimal safe fix, and false-positive rationale. The model is not trusted to decide which findings exist. The final output is accepted only after deterministic validation confirms that scanner check IDs have not been removed or invented.

## Target Selection

The initial dataset contains five Python targets. Three targets represent confirmed vulnerability paths: subprocess command injection, eval-based code injection, and SQL injection. Two targets represent hardening or likely false-positive cases: subprocess usage without demonstrated user-controlled input and eval usage without demonstrated user-controlled input.

The targets are intentionally small. This allows each Semgrep finding, cluster, and label to be manually inspected. The goal of this stage is not to claim broad generalization, but to validate the pipeline design, evidence-preservation logic, and evaluation metrics before scaling to larger applications.

## Labeling

Each target has a label file under `labels/`. A label records the expected Semgrep check ID, file path, line number, true-positive status, severity, and vulnerability category. A finding is labeled as a true positive when user-controlled input reaches a dangerous operation. A finding is labeled as false positive or hardening-only when the scanner reports a risky API or construct but the available code does not show user-controlled input reaching the operation.

Severity labels are assigned based on exploitability in the small target. Confirmed command injection, code injection, and SQL injection cases are labeled High. Hardening-only eval and subprocess cases are labeled Low.

## Evaluation Metrics

The evaluator reports raw Semgrep findings, LLM triage clusters, cluster compression ratio, finding-level precision, finding-level recall, severity accuracy, false-positive triage accuracy, missing check IDs, and extra check IDs.

The compression ratio measures how many raw findings are represented by each triage cluster. Precision and recall are computed against the manual labels. Severity accuracy checks whether the cluster severity matches the expected label severity. False-positive triage accuracy checks whether the pipeline correctly marks true vulnerabilities as not false positives and hardening-only cases as likely false positives. Missing and extra check ID counts measure evidence preservation.

## Reproducibility

The full experiment can be reproduced by running `python scripts/run_pipeline.py`. This executes scanning, triage, and evaluation in order. The repository also includes a results snapshot, evaluation table, experiment manifest, and reproducibility guide so that the reported baseline can be inspected without relying only on generated local artifacts.
