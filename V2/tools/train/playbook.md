# Release Train — V2 Trust-Policy Port

This is the operational playbook for the v2_clean_slate trust-policy port train. It adapts `release-train-playbook.md` (the canonical version that ships in `ai-cookbook`) for this repo's constraints:

- **Integration branch:** `users/jstatia/v2_clean_slate` (NOT `main`)
- **No PRs:** merges happen locally via `V2/tools/train/train.ps1 merge`
- **No GitHub issue poller:** the work set is a closed list of 5 phases derived from the design doc
- **Quality gate:** D11 double-gate — `V2/collect-coverage.ps1 -ProjectFilter <new-project>` ≥ 95% AND full-solution ≥ 95%
- **Hey Jeromy review:** `jeromy_review` (path-based) at A+ across all 9 perspectives before each merge

The full design (D1–D11 decisions, §6.5 walkthrough, phase definitions) lives at:
`C:\Users\jstatia\.copilot\session-state\f7bd6a84-9462-4b40-ae85-5fda2fca86a8\files\eval-trust-policy-translation-contract.md`

Reference playbook (full version) lives at:
`C:\Users\jstatia\.copilot\session-state\c0bff423-7f8f-4707-878b-feb2bb4c102b\files\release-train-playbook.md`

---

## Phase manifest (closed set, ordered)

```
tp-spec          → tp-fact-registry → tp-frontend-json → tp-conformance → tp-frontend-rego
   │                    │                    │                  │                  │
   ├ no deps            ├ no deps            ├ deps spec+reg    ├ deps json+reg    ├ deps conformance
   └ Phase 1            └ Phase 3            └ Phase 2          └ Phase 4          └ Phase 5a
```

Sequential dispatch: ONE phase agent in flight at a time. Each phase agent runs in its own detached-HEAD worktree at `C:\src\repos\CoseSignTool-tp-<phase>`; the orchestrator waits on `system_notification` for completion, verifies, merges, then dispatches the next.

## Operator (orchestrator) responsibilities

1. **Dispatch** the next ready phase as a `task` background agent.
2. **Wait** for `system_notification` of completion. Don't poll.
3. **Verify** on the integration branch (don't trust the agent's self-verification):
   - Worktree HEAD changed; commits look right
   - `V2\tools\train\train.ps1 gate <phase>` (full-solution) re-runs PASSING locally — independent of the agent
   - `V2\tools\train\train.ps1 gate <phase> -Filter <new-project>` PASSES — D11 second gate
   - `jeromy_review path:<worktree>` returns A+ — independent re-run
4. **Merge** via `train.ps1 merge <phase> -Project <new-project>`. If gate fails, surface as blocker — DO NOT `-SkipGate`.
5. **Update** SQL todos: phase done; next phase in_progress; dispatch.

## Anti-deferral (verbatim from canonical playbook §2.1)

> REASONING EFFORT: extra-high — take whatever time needed without deferring.
>
> ANTI-DEFERRAL HARD RULE: no scope reduction, no "deferred to next phase", no "left as future work", no "out of scope for this phase". STOP and surface a blocker for human intervention if any layer cannot complete in the time budget.

## Phase agent contract (every dispatch enforces)

1. **Environment**
   - Working directory is the assigned phase worktree. Do not touch the integration-branch worktree at `C:\src\repos\CoseSignTool-v2`.
   - Worktree starts at detached HEAD off integration-branch HEAD; commits accumulate on detached HEAD.
   - `git status` MUST be clean before signaling completion.

2. **Investigation (NEVER SKIP)**
   - Read the eval doc (`eval-trust-policy-translation-contract.md`) — at minimum sections §6.5 walkthrough, the relevant phase definition, and ALL D1–D11 decisions.
   - Read existing code surfaces the phase touches (e.g. Phase 1 reads `TrustPlanPolicy`, `TrustRules`, `CompiledTrustPlan`).
   - Reproduce edge cases with a focused failing test BEFORE writing the fix.

3. **Commits** — small, themed commits that tell the story of the phase. NOT one giant commit. NOT noise commits.

4. **Tests**
   - Per-phase project test coverage ≥ 95% (D11 first gate).
   - Full-solution coverage ≥ 95% (D11 second gate).
   - Run gate from inside the worktree: `cd V2 && .\collect-coverage.ps1 -ProjectFilter <new-project>` and `.\collect-coverage.ps1`.
   - Capture all output to `$env:TEMP\tp-<phase>-<step>.txt` per the capture-don't-rerun rule (canonical §2.3).
   - Pytest hygiene equivalent: ONE `dotnet test` invocation per gate; no retries.

5. **Hey Jeromy review (A+ contract)**
   - `jeromy_review path:<worktree-path>` after gates pass.
   - Iterate until A+ across all 9 perspectives. Anything below A+ blocks the merge.

6. **Final report** (structured)
   - Phase name, worktree HEAD SHA, commit count
   - Files added / changed (high-level summary)
   - Per-project coverage % + full-solution coverage %
   - `jeromy_review` final grade (must be A+)
   - Open issues / follow-ups that go on the next phase
   - Ship statement: "Ready to merge into users/jstatia/v2_clean_slate"

## Capture-don't-rerun (verbatim from canonical §2.3)

PowerShell:
```powershell
<command> 2>&1 | Tee-Object -FilePath "$env:TEMP\tp-<phase>-<step>.txt"

# Search captured output:
Select-String -Path "$env:TEMP\tp-<phase>-*.txt" -Pattern "FAIL|error|coverage"
```

Never re-run `collect-coverage.ps1` to "see if it passes this time". One run is the contract; debug from captured output.

## D11 double-gate (non-negotiable)

```
1. cd <worktree>\V2
2. .\collect-coverage.ps1 -ProjectFilter <new-project>     # per-project ≥ 95%
3. .\collect-coverage.ps1                                  # full-solution ≥ 95%
4. Both passed → proceed to jeromy_review
5. Either failed → debug; do NOT advance
```

## Hey Jeromy review at A+ (non-negotiable)

```
1. jeromy_review path:<worktree-path>
2. Read returned grades — 9 perspectives
3. If overall_grade != A+:
     read findings; address each
     return to step 1
4. Repeat until A+ achieved
5. Then signal phase complete
```

A or below is a contract violation under §2.2. The dispatch prompt forbids "good enough"; the agent iterates or surfaces a blocker.

## Sequencing rules (adapted from canonical §5)

- **Default:** strict topological order from the phase manifest above.
- **No CRITICAL-jump:** this train has no inbound bug stream. The order is pre-set.
- **Defense-in-depth pair handling:** none of these phases is a paired writer/reader pair; each is independent.
- **Convergence-guard:** if one phase produces >3 unplanned follow-up issues that block other phases, pause and revisit the design doc before dispatching the next phase. (Hey Jeromy review of the integration branch can also surface that a phase needs to split.)

## Communication protocol

When user asks "status":

```
| Stream | Status |
|---|---|
| ✅ Merged | <list of merged phases with SHAs and merge times> |
| 🔄 In flight | <active background agent with elapsed time + worktree HEAD> |
| ⏸️ Queued | <pending phases in topological order> |
| 📋 Design | closed — D1–D11 + Phase 5 decisions locked |
```

Brief. Lead with the in-flight stream.

When system_notification arrives (background agent done):

```
1. read_agent — get terminal report
2. Verify on integration branch (worktree HEAD, gates re-run, jeromy_review re-run)
3. train.ps1 merge <phase> -Project <new-project>
4. Update SQL: phase done; next phase in_progress
5. Dispatch next phase as background agent
6. Acknowledge to user with merge SHA + Hey Jeromy grade
```

## Troubleshooting (deltas from canonical Appendix D)

**Symptom:** Coverage gate fails at full-solution but passes per-project.
**Cause:** new project pulled solution rollup down (e.g. consumes a previously-untested API). Or unrelated drift since last merge.
**Fix:** investigate which assembly dropped; either add tests in that assembly OR (per canonical §9.4) reduce the underlying code. NEVER `-SkipGate`.

**Symptom:** Hey Jeromy review returns B+ on `red-team` perspective with "treat untrusted documents as security boundary" finding.
**Cause:** translator probably didn't sandbox parsing strictly per §6.5.4 #6.
**Fix:** address the finding; re-run review. The contract is A+ across ALL 9 perspectives — `red-team` is the most likely sub-A grade for this work.

**Symptom:** Worktree at `C:\src\repos\CoseSignTool-tp-<phase>` has uncommitted changes after agent reports completion.
**Cause:** agent stopped mid-stream or didn't `git add` final output.
**Fix:** `train.ps1 merge` refuses to merge a dirty worktree. Read the agent's terminal report; either dispatch a follow-up to clean up, or commit the leftover yourself before merge.

**Symptom:** Two phase worktrees somehow exist for the same phase.
**Cause:** previous `train.ps1 add` failed mid-creation, or manual `git worktree add` was used.
**Fix:** `git worktree list` to inspect; `git worktree remove --force` for the stale one.

## Final note

This playbook lives in the repo at `V2/tools/train/playbook.md` so every dispatched phase agent reads the same contract. The canonical version (in ai-cookbook) is the source of truth for general patterns; this version diverges only where the v2_clean_slate train's constraints require.
