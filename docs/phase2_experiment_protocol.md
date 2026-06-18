# Phase 2 Experiment Protocol

Phase 2 experiments must follow this order:

1. Create or modify a candidate target.
2. Run Semgrep scan first.
3. Confirm the generated `data/findings/<target>-semgrep.json` contains at least one result.
4. Only then run LLM triage.
5. Inspect the LLM triage output.
6. If needed, add deterministic triage logic.
7. Create the label file.
8. Run the full pipeline.
9. Update results docs only after evaluation succeeds.

This prevents adding targets that do not produce scanner findings and avoids silent gaps in evaluation.
