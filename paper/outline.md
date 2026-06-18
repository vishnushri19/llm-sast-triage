\# LLM-Assisted SAST Triage



\## Working Title



LLM-Assisted Static Analysis Triage: Deterministic Clustering and Local LLM Enrichment for Actionable Security Findings



\## Research Question



Can a local LLM improve the usability of SAST output by clustering duplicate findings, preserving scanner evidence, prioritizing severity, and identifying likely false-positive or hardening-only cases?



\## Current Prototype



The prototype uses Semgrep to generate raw findings, deterministic logic to preserve check IDs and cluster related findings, and Ollama with llama3.2 to enrich each cluster with impact and remediation guidance.



\## Initial Evaluation



The initial evaluation uses two Python targets:



1\. `myapp`: confirmed command injection through user-controlled Flask input reaching subprocess execution.

2\. `safeapp`: lower-risk shell=True hardening case where no user-controlled input reaches the command.



Initial results show:

\- 4 raw Semgrep findings

\- 2 LLM triage clusters

\- 2.00x compression ratio

\- 1.00 severity accuracy

\- 1.00 false-positive triage accuracy

\- 0 missing check IDs

\- 0 extra check IDs



\## Contribution



This project does not claim that LLMs replace SAST tools. Instead, it shows a safer hybrid approach where SAST remains the source of truth and the LLM only improves explanation, prioritization, and remediation readability.



\## Next Work



\- Add more vulnerable examples.

\- Add more false-positive and hardening-only cases.

\- Compare raw Semgrep severity against LLM-assisted triage severity.

\- Add tables for precision, recall, clustering ratio, and false-positive triage accuracy.

\- Draft introduction and methodology sections.

