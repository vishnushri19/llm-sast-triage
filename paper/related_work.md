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
