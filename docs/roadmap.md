# Roadmap

## v0.1.0 Baseline

The initial baseline includes a working LLM-assisted SAST triage prototype with five Python targets, Semgrep scanning, deterministic clustering, local LLM enrichment, validation checks, evaluation metrics, paper draft sections, and reproducibility documentation.

## Phase 2 Goals

- Add more vulnerability classes.
- Add more false-positive and hardening-only cases.
- Add safe SQL query hardening example.
- Compare results across multiple local Ollama models.
- Improve per-class evaluation reporting.
- Add larger real-world open-source targets.
- Convert the paper draft into a conference-style format.

## Candidate Next Targets

- Safe SQL parameterized query case.
- Path traversal case.
- Hardcoded secret case.
- Insecure deserialization case.
- SSRF case.

## Research Direction

The core research direction remains: keep SAST as the source of truth, use deterministic logic for evidence preservation and clustering, and use the LLM only for explanation and remediation enrichment.
