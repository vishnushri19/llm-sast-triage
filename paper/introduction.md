# Introduction

Static application security testing (SAST) is an important part of application security programs because it can identify vulnerable code patterns early in the software development lifecycle. However, the value of SAST depends not only on detection, but also on how quickly developers and security engineers can understand, prioritize, and remediate the findings.

In practice, SAST output can be noisy. A single vulnerable code pattern may produce multiple related findings. Some findings are confirmed vulnerabilities, while others are hardening-only or false-positive cases. This creates triage friction, especially for teams that must review large numbers of findings across multiple applications.

Recent advances in large language models (LLMs) have created new opportunities to summarize, explain, and prioritize security findings. However, using an LLM directly as a security decision engine creates risk. An LLLM can omit details, overstate confidence, or generate explanations that are not fully supported by the scanner evidence.

This project takes a controlled hybrid approach. The SAST scanner remains the source of truth. Deterministic logic clusters related findings, preserves check IDs, and applies high-confidence triage rules. A local LLM is then used to enrich each cluster with impact and remediation guidance. This design aims to make SAST output more actionable without giving the LLM authority to invent, drop, or change scanner evidence.

## Contributions

This project makes three initial contributions:

- A hybrid SAST triage pipeline that combines Semgrep, deterministic clustering, and local LLM enrichment.
- A validation design that preserves scanner check IDs and flags missing or extra evidence.
- An initial evaluation across five Python targets covering command injection, code injection, SQL injection, and false-positive or hardening-only cases.

## Scope

The current work is an early prototype. It is not intended to replace SAST tools or manual security review. Instead, it explores whether a controlled LLM-assisted layer can reduce triage friction while preserving scanner evidence integrity.
