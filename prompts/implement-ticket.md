# Implement Ticket

Implement one approved task contract on one branch.

## Workflow

1. Read `AGENTS.md` and `CLAUDE.md`.
2. Confirm the task goal, scope, non-goals, and acceptance criteria.
3. Inspect the owning code and tests.
4. Make the smallest coherent change.
5. Add or update tests for behavior changes.
6. Run the relevant verification commands.
7. Summarize changed files, commands run, residual risks, and follow-up rules.

## Rules

- Do not change public APIs without a migration note.
- Do not add production dependencies without approval.
- Do not hand-edit generated SDK files.
- Do not weaken oracle cases to make implementation pass.
- Do not merge to main.
- If the same correction appears twice, propose an `AGENTS.md` update.
