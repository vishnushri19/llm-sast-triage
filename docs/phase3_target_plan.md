# Phase 3 Target Plan

Phase 3 expands the evaluation from 5 targets to 10 targets.

## New Candidate Targets

| Target | Vulnerability Pattern | Expected Purpose |
|---|---|---|
| pathapp | Path traversal / arbitrary file read | Confirm scanner detection of user-controlled file path reaching file read |
| ssrfapp | Server-side request forgery | Confirm scanner detection of user-controlled URL reaching outbound request |
| yamlapp | Unsafe YAML deserialization | Confirm scanner detection of yaml.load on request body |
| pickleapp | Unsafe pickle deserialization | Confirm scanner detection of pickle.loads on user-controlled payload |
| redirectapp | Open redirect | Confirm scanner detection of user-controlled redirect target |

## Execution Rule

Do not add labels or update paper results until Semgrep confirms at least one finding for each target.

Execution order:

1. Create target app.
2. Run Semgrep scan.
3. Confirm at least one Semgrep finding.
4. Inspect check IDs and line numbers.
5. Add labels using actual scanner output.
6. Run LLM triage.
7. Run full evaluation.
8. Update paper results only after evaluation succeeds.
