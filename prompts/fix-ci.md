# Fix CI

Fix failing checks without redesigning the feature.

## Input

- Branch:
- Failing check:
- Relevant log excerpt:
- Task contract:

## Rules

- Only address failures from tests, lint, formatting, type checking, generated
  files, or environment assumptions.
- Do not change acceptance criteria.
- Do not expand feature scope.
- Do not weaken tests unless the test is demonstrably wrong and the reason is
  documented.
- Run the failing command locally when possible.

## Output

```md
## Fix

## Commands Run

## Remaining Failures

## Scope Check
```
