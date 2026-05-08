# Rust Feature Train — `users/jstatia/native_ports_final`

Adapted from `V2/tools/train/playbook.md`. Same lifecycle, same anti-deferral contract; deltas below.

## Deltas vs V2 train

| Aspect | V2 train | Rust train |
|--------|----------|-----------|
| Integration branch | `users/jstatia/v2_clean_slate` | `users/jstatia/native_ports_final` |
| Worktree prefix | `CoseSignTool-tp-<phase>` | `CoseSignTool-np-<phase>` |
| Coverage script | `V2/collect-coverage.ps1` | `native/rust/collect-coverage.ps1` |
| Per-scope gate | 95% absolute (`.NET` convention) | **90% absolute** (existing repo Rust convention) |
| Workspace/full gate | NoRegress vs integration baseline | NoRegress vs integration baseline |
| Build/test runner | `dotnet build` / `dotnet test` | `cargo build` / `cargo test` / `cargo llvm-cov` |
| Header generation | n/a | `cbindgen` regen step (Phase 4.5+) |

## Phase manifest

```
np-spec ─┐                                  ┌─ np-frontend-rego (Phase 5a)
         ├─ np-frontend-json ─ np-conformance ─┤
np-fact-registry ─┘                            └─ np-ffi (NEW, Phase 4.5)
```

## Operator (orchestrator) responsibilities

Same as V2 playbook §"Operator responsibilities", with:
- Verify gates via `native\rust\tools\train\train.ps1 gate <phase>` and (when applicable) `gate <phase> -Package <crate>`.
- Merge via `train.ps1 merge <phase> -Package <crate> -NoRegress`.

## Anti-deferral

Verbatim from V2 playbook §2.1.

## Phase agent contract

Same as V2 playbook with substitutions:
- `dotnet test` → `cargo test --workspace --all-features`
- `collect-coverage.ps1 -ProjectFilter` → `collect-coverage.ps1 -Package <crate>`
- Per-project gate target → 90% (was 95%)
- `jeromy_review path:<worktree>` unchanged
- New for Phase 4.5+: `cbindgen` must produce a header that's byte-identical to the committed `.h` (CI gate)

## Capture-don't-rerun

Same pattern. Capture to `$env:TEMP\np-<phase>-<step>.txt`.

## D11 double-gate (Rust amendment)

```
1. cd <worktree>\native\rust
2. .\collect-coverage.ps1 -Package <new-crate> -FailUnderLines 90       # per-crate ≥ 90%
3. .\collect-coverage.ps1 -SkipGates                                     # capture workspace number
4. Compare workspace number to integration baseline (orchestrator does this via -NoRegress)
5. Both passed → proceed to jeromy_review
6. Either failed → debug; do NOT advance
```

## Hey Jeromy review at A across 9 perspectives

Same as V2 contract. `jeromy_review path:<worktree>` after gates pass; iterate; A or above ships.

## Cross-train independence

The Rust train and the V2 train are independent:
- Different integration branches.
- Different worktree path prefixes.
- Different coverage scripts.
- Per playbook §2.5: trains can run in parallel (different worktrees, no shared state). Within a train, sequential dispatch.

The orchestrator dispatches at most one V2 phase agent + one Rust phase agent concurrently. Two Rust phase agents in parallel is forbidden (cargo lockfile + target/ contention).
