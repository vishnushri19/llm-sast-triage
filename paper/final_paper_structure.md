# Final Paper Structure

## Proposed Title

Controlled LLM-Assisted SAST Triage: Evidence-Preserving Clustering and Local LLM Enrichment for Security Findings

## Short Title

Controlled LLM-Assisted SAST Triage

## Core Research Question

Can a local LLM improve the usability of SAST findings when scanner evidence is preserved deterministically and the LLM is limited to explanation and remediation enrichment?

## Paper Structure

1. Abstract
2. Introduction
3. Background and Motivation
4. Related Work
5. System Design
6. Methodology
7. Evaluation
. Results and Discussion
9. Threats to Validity
10. Conclusion and Future Work
11. References

## Main Claim

This paper does not claim that LLMs replace SAST tools or manual security review. It argues that a safer hybrid approach can make SAST findings more actionable by using deterministic clustering and evidence validation first, then using a local LLM only for impact and fix explanations.

## Key Contributions

- An evidence-preserving SAST triage pipeline.
- Deterministic clustering and rule-safety logic for high-confidence triage.
- Local LLM enrichment for readable impact and remediation text.
- Validation that detects missing or invented scanner check IDs.
- A reproducible initial evaluation across command injection, eval code injection, SQL injection, and hardening-only cases.

## Recommended Paper Stance

The paper should sound conservative, engineering-driven, and evidence-first. The key message is not \"LLM finds bugs,\" but \"LLM helps teams read and act on SAST results more safely when evidence is preserved.\"

## Next Writing Step

Write Background and Motivation, then Related Work.
