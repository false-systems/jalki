# Review Diff

Review the diff as an independent reviewer. Do not re-argue the original idea
unless the diff violates the task contract or product boundaries.

## Focus

- Behavioral bugs.
- Security or privacy regressions.
- Public API drift.
- Missing tests.
- Generated-file mistakes.
- Linux/macOS verification gaps.
- Product-boundary violations.

## Output

Lead with findings, ordered by severity:

```md
## Findings

- Severity: ...
  File: ...
  Issue: ...
  Fix: ...

## Open Questions

## Verification Gaps

## Summary
```

If there are no findings, say that clearly and list remaining verification risk.
