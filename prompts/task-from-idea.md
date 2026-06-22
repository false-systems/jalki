# Task From Idea

Turn rough product or engineering intent into a bounded agent task contract.

## Input

- Idea:
- Repo:
- Relevant docs or issues:
- Deadline or urgency:

## Output

Produce a task contract with these sections:

```md
# Task

## Goal

## Scope

## Non-goals

## Acceptance

## Commands

## Risks

## Open Questions
```

## Rules

- Keep the ticket small enough for one focused branch.
- Separate product intent from implementation details.
- Include explicit non-goals.
- Include test, lint, or oracle commands where relevant.
- If architecture boundaries are unclear, require human approval before build.
