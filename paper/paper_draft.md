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

# Background and Motivation

Static application security testing (SAST) is widely used to identify vulnerable code patterns before software reaches production. SAST tools are valuable because they operate early in the development lifecycle, integrate into developer workflows, and provide concrete evidence such as rule identifiers, file paths, line numbers, and matched code. This evidence makes SAST useful for both developer remediation and security review.

However, SAST output is not always easy to act on. A single vulnerable code path can trigger multiple related rules. For example, a user-controlled input that reaches a dangerous subprocess call may produce one finding for command injection, another for shell usage, and another for dangerous subprocess invocation. These findings are related, but they may appear as separate issues in the scanner output. Without clustering, reviewers may spend time reading multiple findings that describe the same underlying risk.

Severity is also difficult to interpret from raw SAST output alone. A rule may correctly identify a dangerous API such as `eval()` or `subprocess(..., shell=True)`, but exploitability depends on whether untrusted input reaches that operation. Some findings represent confirmed vulnerability paths, while others are better treated as hardening recommendations. This distinction matters because teams need to prioritize exploitable issues without ignoring security-relevant hardening opportunities.

False positives and hardening-only findings create another source of triage friction. A scanner may flag a dangerous API even when the current code uses only internal constants or allowlisted values. These findings are still useful because they identify risky constructs, but they should not be presented with the same urgency as a confirmed injection path. A useful triage system should separate confirmed vulnerabilities from lower-risk hardening cases while preserving the original scanner evidence.

Large language models (LLMs) appear attractive for this problem because they can summarize technical findings, explain impact, and produce remediation guidance in developer-friendly language. But using an LLM as the primary security decision engine is risky. LLMs may omit details, overstate certainty, invent unsupported evidence, or change the meaning of scanner output. For SAST triage, these risks are especially important because file paths, rule IDs, and line numbers are part of the evidence trail.

This project is motivated by a safer design principle: the scanner remains the source of truth, while the LLM is used only as an enrichment layer. Deterministic logic first groups related findings, preserves Semgrep check IDs, identifies high-confidence patterns, and validates that no scanner evidence is dropped or invented. Only after this evidence-preserving step is the local LLM used to generate impact and minimal safe-fix explanations.

The motivation is not to replace manual review or claim that an LLM can independently determine exploitability. Instead, the goal is to reduce the reading burden for security teams and developers. A reviewer should be able to move from several raw findings to a smaller set of evidence-preserving clusters, each with a clear explanation, severity decision, false-positive assessment, and remediation suggestion.

The initial prototype demonstrates this idea across five small Python targets. Confirmed vulnerability cases include subprocess command injection, eval-based code injection, and SQL injection. Hardening or false-positive cases include subprocess usage without demonstrated user-controlled input and eval usage without demonstrated user-controlled input. These examples are intentionally small so the pipeline, validation logic, and evaluation metrics can be inspected directly.

The broader research question is whether controlled LLM-assisted triage can make SAST findings more usable without weakening evidence integrity. This requires a conservative architecture: deterministic evidence preservation first, local LLM enrichment second, and validation checks before accepting the final triage output.

# Related Work

## Static Analysis and SAST Triage

Static application security testing (SAST) is a common approach for identifying security-relevant code patterns before deployment. SAST tools are useful because they can provide repeatable evidence such as rule identifiers, source locations, matched code, and data-flow traces. At the same time, static analysis often produces findings that require manual interpretation. OWASP notes that static code analysis tools can report false positives when the tool cannot fully determine whether data is safe as it flows through an application. This creates a practical triage problem: reviewers must distinguish confirmed vulnerabilities from lower-confidence or hardening-only findings.

Semgrep is used in this project as the scanner because it provides structured JSON output, rule identifiers, source locations, and security rule packs that are easy to integrate into an experiment pipeline. This project treats Semgrep output as the source of truth and does not allow the LLM layer to invent or remove scanner evidence.

## LLM-Assisted Vulnerability Analysis

Recent work has explored combining large language models (LLMs) with static analysis for vulnerability detection and contextual reasoning. IRIS, for example, proposes a neuro-symbolic approach that uses LLMs with static analysis to support repository-level vulnerability reasoning and taint specification inference. This direction shows that LLMs can help security analysis when they are combined with structured program-analysis signals rather than used as standalone text generators.

The present project is narrower and more conservative. It does not ask the LLM to discover vulnerabilities independently or infer missing scanner evidence. Instead, deterministic logic first clusters findings and preserves check IDs, file paths, and line numbers. The LLM is then used only for impact and remediation explanation after the scanner evidence has already been organized.

## LLMs for False-Positive Reduction

Several recent studies focus on using LLMs to reduce SAST false positives. ZeroFalse frames static analyzer output as structured contracts and uses LLMs with contextual evidence and CWE-specific knowledge to improve precision while preserving coverage. QASecClaw proposes a multi-agent approach where a SAST engine first reports candidate vulnerabilities and LLM-based agents then review findings with source-code context to classify likely true positives and false positives. Other recent work studies LLM agents for vulnerability false-positive reduction and reports large reductions in SAST noise on benchmark and real-world datasets.

This project aligns with that general direction but differs in scope and safety posture. The current prototype is not a multi-agent system and does not claim broad benchmark performance. Its contribution is an inspectable, local, evidence-preserving workflow: SAST evidence is kept intact, deterministic rules handle high-confidence cases, and local LLM enrichment is constrained to explanation and remediation text.

## Benchmarks and Evaluation

Benchmarking is important because SAST triage systems can appear useful on small examples while failing on larger or more diverse codebases. SASTBench introduces a benchmark for evaluating SAST triage agents using real CVEs as true positives and filtered SAST findings as false-positive candidates. Such benchmarks are useful for future validation of this project because they provide a path beyond small synthetic examples.

The current evaluation is intentionally small. It uses five Python targets covering command injection, eval-based code injection, SQL injection, subprocess hardening, and eval hardening. The goal is to validate the pipeline design, metrics, and evidence-preservation checks before expanding to larger benchmarks and real-world projects.

## Positioning of This Work

The related work suggests a growing interest in LLM-assisted vulnerability detection, SAST triage, and false-positive reduction. This project takes a conservative position within that space. It does not position the LLM as the authority over scanner results. Instead, it uses a scanner-first architecture where deterministic clustering, check-ID preservation, and validation occur before LLM-generated explanations are accepted.

This makes the project most relevant to teams that want LLM assistance for developer readability and triage efficiency, but do not want to weaken the evidence trail provided by SAST tools.

## References

[1] OWASP, "Static Code Analysis." OWASP Community Pages.

[2] Semgrep, "Semgrep documentation" and "semgrep/semgrep: Lightweight static analysis for many languages."

[3] Z. Li et al., "IRIS: LLM-Assisted Static Analysis for Detecting Security Vulnerabilities." arXiv, 2024.

[4] M. Iranmanesh et al., "ZeroFalse: Improving Precision in Static Analysis with LLMs." arXiv, 2025.

[5] M. R. Ameen, M. T. U. Alam, and A. Islam, "QASecClaw: A Multi-Agent LLM Approach for False Positive Reduction in Static Application Security Testing." arXiv, 2026.

[6] J. Feiglin et al., "SastBench: A Benchmark for Testing Agentic SAST Triage." arXiv, 2026.

[7] Y. Xiong et al., "A Comparative Study of LLM Agents in Vulnerability False Positive Reduction." arXiv, 2026.

[8] "Reducing False Positives in Static Bug Detection with LLMs." arXiv, 2026.

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
