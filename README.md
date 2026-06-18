\# LLM SAST Triage



A lightweight prototype that combines Semgrep static analysis with a local LLM through Ollama to cluster, prioritize, and explain SAST findings.



\## What this project does



1\. Runs Semgrep against a target application.

2\. Saves findings as JSON.

3\. Groups duplicate or related findings deterministically.

4\. Uses a local LLM only to enrich the output with impact, fix guidance, and false-positive reasoning.

5\. Validates that all Semgrep check IDs are preserved in the final triage output.



\## Current scope



\- Scanner: Semgrep

\- LLM runtime: Ollama

\- Default model: llama3.2

\- Example target: Python Flask sample app

\- Platform support: macOS/Linux native Semgrep, Windows via Docker



\## Quick start



Create and activate a Python 3.12 virtual environment, then install dependencies:



```bash

pip install -r requirements.txt



## Research Artifacts

- Paper draft: `paper/paper_draft.md`
- Abstract: `paper/abstract.md`
- Methodology: `paper/methodology.md`
- Results: `paper/results.md`
- Limitations: `paper/limitations.md`
- Evaluation table: `docs/evaluation_table.md`
- Reproducibility guide: `docs/reproducibility.md`
- Results snapshot: `docs/results_snapshot.txt`
