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
