# Agentic Dev Lane

Jalki uses agents as workers inside the normal engineering system, not as owners
of truth.

## Lane

```text
idea -> structured ticket -> agent plan -> branch -> PR -> independent review -> tests -> human merge -> rules updated
```

## Invariants

- All non-trivial agent work starts from a structured task contract.
- Agents work on branches, not directly on main.
- The author and reviewer should be different models or tools when practical.
- CI, tests, specs, and reviewed docs decide whether behavior is acceptable.
- Humans own merge decisions.
- Repeated corrections become durable repo guidance.

## Ledger Fields

Agent-authored PRs or automation summaries should preserve:

```json
{
  "actor": "",
  "task_id": "",
  "repo": "jalki",
  "branch": "",
  "base_commit": "",
  "head_commit": "",
  "prompt_hash": "",
  "files_changed": [],
  "commands_run": [],
  "tests_passed": false,
  "reviewed_by": "",
  "human_approved_by": ""
}
```

The ledger can live in a PR body, GitHub Action summary, or artifact. It should
not become a second source of product truth.
