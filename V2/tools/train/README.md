# V2 Feature Train

A worktree-based "feature train" for shipping work into `users/jstatia/v2_clean_slate` without PRs and without regressing the `V2/collect-coverage.ps1` ≥95% line-coverage gate.

Mirrors the worktree pattern used in `C:\src\repos\ai-cookbook`, adapted for local-merge workflow.

## Concepts

- **Integration branch:** `users/jstatia/v2_clean_slate`. The "main" of this train.
- **Phase:** a unit of work with its own worktree. Examples: `spec`, `frontend-json`, `fact-registry`, `conformance`.
- **Phase worktree:** sibling-pathed at `C:\src\repos\CoseSignTool-tp-<phase>`, **detached HEAD** off the current integration HEAD when the phase is added.
- **Quality gate:** `V2/collect-coverage.ps1`. Refuses to merge a phase if line coverage drops below 95%.
- **Merge strategy:** `git merge --no-ff` from the integration branch checkout. No PRs. Audit trail = merge commits.

## Lifecycle

```
  add ──▶ work on detached HEAD ──▶ commit locally ──▶ gate ──▶ merge ──▶ remove
                                                          │
                                                       (fail)
                                                          │
                                                          ▼
                                                  fix and re-gate
```

## Commands

```powershell
# From any checkout of the v2 worktree (typically C:\src\repos\CoseSignTool-v2):
cd V2\tools\train

# Create a phase worktree (detached HEAD off integration-branch HEAD)
.\train.ps1 add spec

# Show all phase worktrees with ahead/behind/dirty status
.\train.ps1 list

# Run the coverage gate against a phase worktree
.\train.ps1 gate spec
.\train.ps1 gate spec -Filter CoseSign1.Validation        # narrow to one project

# Merge a phase back into the integration branch (gates first; --no-ff merge; removes worktree)
.\train.ps1 merge spec

# Discard a phase without merging (-Force required; commits in the worktree are LOST)
.\train.ps1 remove spec -Force
```

## Authoring on a phase worktree

1. `cd C:\src\repos\CoseSignTool-tp-spec` (or whichever phase).
2. You're on a detached HEAD. Make changes, `git add`, `git commit` as normal — commits accumulate on the detached HEAD without affecting any branch.
3. When ready: `cd back to the integration worktree` and run `.\train.ps1 merge <phase>`.

## Quality gate semantics

- Gate runs `V2\collect-coverage.ps1` inside the phase worktree.
- Default scope = full solution. Use `-Filter <project-name>` to scope to one project's coverage if the phase only adds code to that project.
- `merge` requires the gate to pass. Override with `-SkipGate` only when conflict resolution forced a re-merge after a successful prior gate run.

## Anti-patterns

- **Don't push the integration branch with un-rebased train commits.** Train commits are local-only until you intentionally `git push`.
- **Don't run two `merge` commands concurrently.** The integration-branch checkout is a single working directory and `collect-coverage.ps1` already serializes its own clean/build via a file lock — but cross-phase merges should still be sequential.
- **Don't reuse a phase name after merging.** The merge commit captures the phase identity; re-using the name later loses the audit link.
- **Don't `-SkipGate` to ship work that fails the gate.** That regresses the integration branch and defeats the train's only quality property.

## Adding/removing phases

Phase set is mutable. Hey Jeromy review of the integration branch may surface that a phase needs to split, or that two phases should collapse. The train doesn't enforce a phase manifest — `add` creates whatever worktree you ask for; `remove` retires it.

For the trust-policy port specifically, the initial phase plan lives in:
`C:\Users\jstatia\.copilot\session-state\f7bd6a84-9462-4b40-ae85-5fda2fca86a8\files\eval-trust-policy-translation-contract.md`
