# Abstract

Static application security testing (SAST) tools can identify vulnerable code patterns, but security teams often struggle with duplicate findings, severity noise, and false-positive or hardening-only results. This project presents a hybrid SAST triage workflow that keeps the scanner as the source of truth while using deterministic clustering and a local large language model (LLM) to improve finding readability and remediation guidance.

The prototype scans small Python applications with Semgrep, groups related findings without dropping scanner check IDs, applies deterministic rules for high-confidence vulnerability classes, and uses a local Ollama model to generate impact and minimal safe-fix explanations. The design intentionally limits LLM authority: the LLM does not invent findings, remove scanner evidence, or decide evidence integrity. Validation checks ensure that every Semgrep check ID remains represented in the final triage output.

An initial evaluation across five targets covers command injection, eval-based code injection, SQL injection, subprocess hardening, and eval hardening cases. The prototype reduced nine raw Semgrep findings into five triage clusters, achieving a 1.80x compression ratio while preserving all scanner check IDs. The initial dataset shows 1.00 recall, 1.00 severity accuracy, and 1.00 false-positive triage accuracy, with 0 missing and 0 extra check IDs.

These early results suggest that a controlled hybrid approach can make SAST output more actionable without treating the LLM as an independent security authority. The current work is an initial prototype and requires broader validation across larger applications, additional languages, more vulnerability classes, and multiple local LLMs.

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

# Methodology

This project evaluates a hybrid SAST triage workflow. The scanner remains the source of truth, while deterministic logic and a local LLM are used to make findings easier to review.

## Pipeline

1. Semgrep scans each target application and produces raw JSON findings.
2. Deterministic clustering groups related findings while preserving Semgrep check IDs, file paths, and line numbers.
3. Deterministic rules classify high-confidence patterns such as command injection, code injection, SQL������ѥ����������ɑ���������䁍�̸͕(и��������=��������������ɥ���́���������ѕȁݥѠ������Ё������������ͅ��������ե������(Ը�Y�����ѥ��������́�����ɴ�ѡ�Ё���M���ɕ��������%́�ɔ��ɽ������ȁ��ٕ�ѕ����ѡ��114������и((���Q�ɝ���()Q������ѥ�����х͕Ё����Ց�́ɕ����ձ��Ʌ�����䁍�͕́�������͔���ͥѥٔ��ȁ��ɑ���������䁍�͕��((����������͕ȵ����ɽ�������ͬ�����Ёɕ����́�Չ�ɽ���́�ᕍ�ѥ���(����م�������͕ȵ����ɽ�������ͬ�����Ёɕ����́��م�����(����ű������͕ȵ����ɽ�������ͬ�����Ёɕ����́ME0��Օ�䁍�����Սѥ���(���ͅ��������Չ�ɽ���́�ͅ���ݥѡ��Ё�������Ʌѕ���͕ȵ����ɽ���������и(���ͅ���م�����聁�م������ͅ���ݥѡ��Ё�������Ʌѕ���͕ȵ����ɽ���������и((���5��ɥ��()Q����م�Յѥ���ɕ������((��I�܁M���ɕ���������̸(��114��ɥ��������ѕ�̸(�����ɕ�ͥ���Ʌѥ��(�����������ٕ���ɕ��ͥ���(�����������ٕ��ɕ�����(��M�ٕɥ�䁅���Ʌ��(����͔���ͥѥٔ��ɥ��������Ʌ��(��5��ͥ����ȁ���Ʉ�������%̸((���M�����Aɥ������()Q���114��́��Ё����ѕ��Ѽ���������٥��������ѕ�ɥ�丁%Ё�́�����͕����ѕȁ��ѕɵ����ѥ���ɽ����������م����ѥ����Q���͍����ȁ�٥�������́�ɕ͕�ٕ������������������ɔ�ɕ�ձ�́�ɔ������ѕ��(

# Results

This section summarizes the current prototype evaluation.

## Dataset

The current evaluation uses five small Python targets:

| Target | Purpose |
|---|---|
| `myapp` | Real subprocess command injection |
| `evalapp` | Real eval code injection |
| `sqlapp` | Real SQL injection |
| `safeapp` | Subprocess hardening / false-positive case |
| `safeevalapp` | Eval hardening / false-positive case |

## Overall Results

| Metric | Value |
|---|---:|
| Targets evaluated | 5 |
| Total raw Semgrep findings | 9 |
| Total LLM triage clusters | 5 |
| Overall compression ratio | 1.80x |
| Overall precision | 0.78 |
| Overall recall | 1.00 |
| Overall severity accuracy | 1.00 |
| Overall false-positive triage accuracy | 1.00 |
| Missing Semgrep check IDs | 0 |
| Extra Semgrep check IDs | 0 |

## Interpretation

The prototype reduced nine raw Semgrep findings into five triage clusters while preserving all scanner check IDs. The initial results show that deterministic clustering can reduce duplicate or related findings without losing scanner evidence.

The precision value is lower than 1.00 because the dataset intentionally includes false-positive or hardening-only findings. This is expected. The more important measurement for those cases is false-positive triage accuracy, which is currently 1.00 on the initial dataset.

The current result should be treated as an early validation of the pipeline design, not as a general claim about all SAST findings or all application frameworks.

# Limitations and Threats to Validity

This prototype is an initial research artifact and should not be interpreted as a production-ready SAST triage system.

## Dataset Size

The initial evaluation uses a small set of python examples. This is sufficient for prototyping the pipeline and measurements, but it is not large enough to claim general effectiveness across all languages, frameworks, or vulnerability classes.

## Synthetic Targets

The current targets are small and controlled. Real-World applications may include more complex data flows, framework abstractions, indirect function calls, and dependency-driven behavior that may change scanner and triage results.

## Scanner Dependency

The pipeline depends on Semgrep check IDs, finding format, and rule behavior. Different Semgrep versions, proprietary rule packs, or custom rules could produce different findings.

## LLM Variability

The project uses a local Ollama model for enrichment. Different models may generate different impact and fix text. The prototype mitigates this risk by preserving SAST check IDs deterministically and validating that the LLM does not drop invent evidence.

## Label Bias

Labels are manually created for this initial dataset. False-positive labels and severity labels may require additional internal review or external benchmarking before publication.

## Next Validation Steps

- Add more applications and frameworks.
- Add more false-positive hardening cases.
- Report per-class results.
- Compare against raw Semgrep severity and a baseline manual triage workflow.
- Test different local LLM models for stability and output consistency.
