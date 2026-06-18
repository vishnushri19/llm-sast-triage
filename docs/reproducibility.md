# Reproducibility Guide

This document explains how to reproduce the initial SAST triage evaluation.

## Requirements

- Python 3.12
- Docker Desktop
- Ollama
- Local Ollama model: `lamma3.2`
- Semgrep Docker image: `semgrep/semgrep:1.82.0`

## Setup

```cmd
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
ollama pull lamma3.2
```

## Run the Full Pipeline

```cmd
python scripts\run_pipeline.py
```

## Run Steps Manually

```cmd
python scripts\run_scans.py
python scripts\llm_rank.py
python scripts\eval.py
```

## Expected Initial Results


```text
Targets evaluated:                5
Total raw findings:               9
Total LLM clusters:               5
Overall compression ratio:        1.80x
Overall precision:                0.78
Overall recall:                   1.00
Overall severity accuracy:       1.00
Overall FP triage accuracy:      1.00
Total missing check IDs:          0
Total extra check IDs:            0
```

## Notes

- The `data/` directory is generated locally and is not tracked in Git.
- The `docs/results_snapshot.txt` file contains a tracked example of the current evaluation output.
- The LLM is only used to enrich triage explanations. Scanner evidence and check ID coverage are validated deterministically.
