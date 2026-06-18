# LLM SAST Triage

A scanner-first prototype for controlled LLM-assisted Static Application Security Testing (SAST) triage.

This project combines Semgrep static analysis, deterministic clustering, evidence-preserving validation, and local LLM enrichment through Ollama. The goal is to make SAST findings easier to review without allowing the LLM to become the source of truth.

## Current Release

**Latest milestone:** `v0.2.0 - Phase 2 Paper Draft`

The Phase 2 release includes:

- Complete technical paper draft
- Architecture figure
- Evaluation table
- References
- DOCX and PDF exports
- Reproducible export script

Release artifacts:

- [Paper PDF](paper/exports/paper_draft.pdf)
- [Paper DOCX](paper/exports/paper_draft.docx)
- [Paper draft Markdown](paper/paper_draft.md)
- [Release v0.2.0](https://github.com/vishnushri19/llm-sast-triage/releases/tag/v0.2.0)

## Research Summary

SAST tools are useful for identifying risky code patterns, but their findings often require manual review, grouping, severity interpretation, and false-positive analysis. LLLMs can help explain and summarize findings, but they can also hallucinate, omit evidence, or invent details.

This project uses a conservative design:

1. Semgrep produces the original findings.
2. Deterministic logic clusters related findings.
3. Scanner check IDs, file paths, and line numbers are preserved.
4. A local Ollama model enriches the final output with impact and remediation text.
5. Validation checks ensure scanner evidence is not dropped or invented.

The LLM is used for explanation, not authority.

## What This Project Does

- Runs Semgrep against target applications.
- Saves raw findings as JSON.
- Groups duplicate or related findings deterministically.
- Classifies selected vulnerability patterns such as command injection, eval/code injection, and SQL injection.
- Marks likely false-positive or hardening-only findings when user-controlled input is not demonstrated.
- Uses a local LLM to enrich final triage output.
- Validates that Semgrep check IDs are preserved in final output.
- Evaluates precision, recall, severity accuracy, false-positive triage accuracy, and compression ratio.

## Current Evaluation Snapshot

The Phase 2 evaluation uses five small Python targets.

| Metric | Result |
|---|---:|
| Targets | 5 |
| Raw Semgrep findings | 9 |
| Final triage clusters | 5 |
| Compression ratio | 1.80x |
| Precision | 0.78 |
| Recall | 1.00 |
| Severity accuracy | 1.00 |
| False-positive triage accuracy | 1.00 |
| Missing check IDs | 0 |
| Extra check IDs | 0 |

This is an initial controlled evaluation. The dataset is intentionally small so each finding, label, and cluster can be manually inspected.

## Architecture

```text
Python targets
     |
     v
Semgrep scan
     |
     v
Raw JSON findings
     |
     v
Deterministic clustering and validation
     |
     v
Local Ollama enrichment
     |
     v
Final triage output
     |
     v
Evaluation against labels
```

The central principle is evidence preservation: Semgrep remains the source of truth, while the LLM enriches the analyst-facing explanation.

## Repository Layout

```text
docs/       Evaluation notes, reproducibility notes, roadmap, and experiment manifest
examples/    Small vulnerable and hardening-only target applications
labels/      Manual labels used for evaluation
paper/       Paper draft, sections, references, and exports
prompts/     LLM prompt material
scripts/     Scan, triage, evaluation, pipeline, and export scripts
```

## Quick Start

Install dependencies:

```cmd
pip install -r requirements.txt
```

Run the full pipeline:

```cmd
python scripts\run_pipeline.py
```

Export the paper draft:

```cmd
python scripts\export_paper.py
```

Generated outputs are written under:

```text
data/findings/
data/rankings/
paper/exports/
```

## Research Artifacts

- [Abstract](paper/abstract.md)
- [Methodology](paper/methodology.md)
- [Results](paper/results.md)
- [Limitations](paper/limitations.md)
- [Reproducibility guide](docs/reproducibility.md)
- [Evaluation table](docs/evaluation_table.md)
- [Experiment manifest](docs/experiment_manifest.json)
- [Roadmap](docs/roadmap.md)
- [Phase 2 experiment protocol](docs/phase2_experiment_protocol.md)

## Scope and Limitations

This is not a replacement for SAST, manual review, secure code review, or threat modeling. The current prototype is a research artifact focused on controlled triage behavior.

Current limitations include:

- Small synthetic dataset
- Python-focused targets
- Semgrep-dependent findings
- Local LLM variability
- Manual labels
- No claim of broad production readiness yet

Future work includes adding more targets, testing real-world repositories, comparing against baseline triage methods, and expanding evaluation across more vulnerability classes.

## Release History

- `v0.1.0`: Stable prototype baseline
- `v0.2.0`: Phase 2 paper draft, exports, architecture figure, evaluation table, and references

## Author

Vishnu Gatla
Senior Professional Services Consultant
F5 Inc.
Dallas, Texas, USA
