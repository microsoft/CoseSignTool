# CoseSignTool V2 Migration & Release Strategy

## Overview

This document proposes the branch strategy, release plan, and step-by-step execution for shipping CoseSignTool V2 as the primary codebase while maintaining V1 long-term support for existing consumers.

## Goals

1. **Ship V2 on `main`** — V2 becomes the primary development branch
2. **Preserve V1 on `release/v1`** — V1 remains buildable, testable, and releasable for bug/security fixes
3. **Zero disruption to V1 consumers** — NuGet semver handles the transition; users pin `<2.0.0` to stay on V1
4. **Clean root layout** — V2 projects move from `V2/` subdirectory to repo root

## Branch Strategy

```
                        v1.7.4 (current)
    main ─────────────────●
                          │
                          ├── release/v1  ← V1 maintenance (default branch during transition)
                          │     │
                          │     ├── v1.7.5, v1.7.6, ... (bug fixes, security patches)
                          │     └── (supported until announced deprecation date)
                          │
    v2_clean_slate ───────●
                          │
    main (post-merge) ────●── V2 code at root
                          │
                          ├── v2.0.0-preview.1
                          ├── v2.0.0-preview.2
                          ├── v2.0.0-rc.1
                          └── v2.0.0 (GA)
```

### Branch Roles

| Branch | Purpose | Protected | CI Workflow | Tag Pattern |
|--------|---------|-----------|-------------|-------------|
| `main` | V2 active development (post-merge) | Yes | `dotnet.yml` | `v2.x.y` |
| `release/v1` | V1 maintenance (LTS) | Yes | `dotnet-v1.yml` | `v1.x.y` |
| `v2_clean_slate` | V2 development (pre-merge, archived after) | No | — | — |

### Default Branch During Transition

During the migration window, **`release/v1` is set as the default branch** so that:
- Existing PRs and forks continue to target V1 code
- No accidental V2 merges into an unprepared `main`
- CI/CD continues uninterrupted for V1

Once V2 is merged and validated on `main`, the default branch switches back to `main`.

## NuGet Package Strategy

### Same Package IDs, Major Version Bump

Packages that exist in both V1 and V2 keep their NuGet IDs. SemVer handles the transition:

| Package | V1 Version | V2 Version |
|---------|-----------|-----------|
| CoseSign1.Abstractions | 1.7.x | 2.0.0-preview → 2.0.0 |
| CoseSign1.Certificates | 1.7.x | 2.0.0-preview → 2.0.0 |
| CoseSign1.Headers | 1.7.x | 2.0.0-preview → 2.0.0 |
| CoseSign1.Transparent.MST | 1.7.x | 2.0.0-preview → 2.0.0 |
| CoseSignTool.Abstractions | 1.7.x | 2.0.0-preview → 2.0.0 |

### New Packages (V2 Only)

| Package | Version | Description |
|---------|---------|-------------|
| Cose.Abstractions | 2.0.0-preview | Generic COSE header contribution (RFC 9052) |
| Cose.Headers | 2.0.0-preview | CWT Claims, generic header implementations |
| CoseSign1.Validation | 2.0.0-preview | Staged validation pipeline with trust engine |
| CoseSign1.Factories | 2.0.0-preview | Direct/Indirect signature factories |
| CoseSign1.AzureKeyVault | 2.0.0-preview | Azure Key Vault signing service |
| CoseSign1.Certificates.Local | 2.0.0-preview | Local certificate key provider |

### Consumer Guidance

- **Stay on V1**: Pin `<PackageReference Version="[1.7.*, 2.0.0)" />`
- **Upgrade to V2**: Update to `Version="2.0.0-preview.*"` (pre-release) or `Version="2.0.0"` (GA)
- **Migration guide**: Published with V2 GA release

## V1 Long-Term Support Policy

| Aspect | Policy |
|--------|--------|
| **Scope** | Security fixes, critical bug fixes, dependency updates |
| **New features** | Not accepted — new work goes to V2 |
| **Versioning** | Continue `1.x.y` semver on `release/v1` |
| **PR target** | `release/v1` branch |
| **CI** | Dedicated `dotnet-v1.yml` workflow |
| **Release process** | Tag `v1.x.y` → CI builds/tests/publishes NuGet |
| **Support timeline** | Until announced deprecation date (recommend minimum 12 months post-V2 GA) |

## Root Layout Migration

V2 projects currently live in `V2/` subdirectory. As part of this migration, they move to the repo root for a clean layout.

### Before → After

```
CoseSignTool2/                          CoseSignTool2/
├── CoseHandler/            ❌ DELETE    ├── Cose.Abstractions/
├── CoseSign1/              ❌ DELETE    ├── Cose.Headers/
├── CoseSign1.Abstractions/ ❌ DELETE    ├── CoseSign1.Abstractions/
├── CoseSign1.Tests/        ❌ DELETE    ├── CoseSign1.Certificates/
├── ... (30 more V1 dirs)   ❌ DELETE    ├── CoseSign1.Factories/
├── CoseSignTool.sln        ❌ REPLACE   ├── CoseSign1.Validation/
├── CoseSign1.md            ❌ DELETE    ├── ... (40+ V2 projects)
├── Directory.Build.props   🔀 REPLACE   ├── CoseSignTool.sln  ← renamed from CoseSignToolV2.sln
├── Directory.Packages.props 🔀 MERGE    ├── Directory.Build.props  ← V2 version
│                                        ├── Directory.Packages.props  ← merged
├── V2/                     ❌ REMOVE    │
│   └── (all V2 projects)   ↗ MOVE UP   │
│                                        │
├── .github/                ✅ KEEP      ├── .github/
├── native/                 ✅ KEEP      ├── native/
├── docs/                   🔀 MERGE     ├── docs/
├── StrongNameKeys/         🔀 MERGE     ├── StrongNameKeys/
├── README.md               🔀 MERGE     ├── README.md
├── .editorconfig           ✅ KEEP ROOT ├── .editorconfig  ← root version (more complete)
├── LICENSE                 ✅ KEEP      ├── LICENSE
├── .gitignore              ✅ KEEP      ├── .gitignore
├── global.json             ✅ KEEP      ├── global.json
├── Nuget.config            ✅ KEEP      ├── Nuget.config
└── CHANGELOG.md            ✅ KEEP      └── CHANGELOG.md
```

### Migration Risk Assessment

| Risk | Severity | Mitigation |
|------|----------|------------|
| .csproj path breakage | **None** | All paths use `$(MSBuildThisFileDirectory)` — zero edits needed |
| CI workflow breakage | **Low** | No hardcoded `V2/` paths in workflows; update solution name only |
| NuGet package confusion | **Low** | SemVer `1.x` vs `2.x` is unambiguous |
| Cherry-pick conflicts (V1↔V2) | **Medium** | Architectures differ; may require manual port |
| V1 users surprised | **Low** | Pre-release packages; pinning guidance; migration doc |

## Execution Plan

### Phase 1: Prepare V1 LTS (before touching main)

1. **Create `release/v1` branch** from current `main` (at `v1.7.4`)
2. **Set `release/v1` as default branch** in GitHub repo settings
3. **Configure branch protection** on `release/v1` (same rules as main)
4. **Create `dotnet-v1.yml`** CI workflow:
   - Triggers on pushes/PRs to `release/v1`
   - Builds `CoseSignTool.sln` (root, V1 solution)
   - Runs V1 tests
   - Publishes `v1.x.y` NuGet packages on release
5. **Tag `v1.7.5`** from `release/v1` to validate the V1 pipeline end-to-end
6. **Announce V1 LTS** to stakeholders

### Phase 2: Prepare V2 for Root

On `v2_clean_slate` branch:

7. **Delete V1 root directories** (33 project dirs + `CoseSignTool.sln` + `CoseSign1.md`)
8. **Move V2 contents to root**: `git mv V2/* .` then remove empty `V2/`
9. **Rename** `CoseSignToolV2.sln` → `CoseSignTool.sln`
10. **Merge conflicting files**:
    - `Directory.Build.props`: use V2 version (has complete config)
    - `Directory.Packages.props`: merge V1 + V2 package versions
    - `.editorconfig`: keep root version (more complete)
    - `README.md`: update for V2
    - `docs/`, `StrongNameKeys/`: consolidate duplicates
11. **Update `dotnet.yml`** to build root `CoseSignTool.sln` (now the V2 solution)
12. **Build & test** to verify all 2,900+ tests pass
13. **Commit** with clear message describing the migration

### Phase 3: Merge V2 to Main

14. **Open PR** from `v2_clean_slate` → `main`
    - Title: "V2: Architecture rewrite — COSE generic layer, staged validation, trust engine"
    - Body: Link to this migration document
    - Label: `breaking-change`, `v2`
15. **Review & merge** (squash merge recommended for clean history)
16. **Tag `v2.0.0-preview.1`**
17. **Switch default branch** back to `main`
18. **Archive** `v2_clean_slate` branch

### Phase 4: Post-Merge

19. **Verify V2 CI** publishes pre-release NuGet packages correctly
20. **Publish migration guide** (V1 → V2 API mapping)
21. **Update GitHub repo** description/topics
22. **Create GitHub Discussion** for V1 deprecation timeline

## CI Configuration

### V2 Workflow (`dotnet.yml` — main branch)

```yaml
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  release:
    types: [published]

# Build CoseSignTool.sln (now V2 at root)
# Publish v2.x.y NuGet packages
# Tag pattern: v2.*
```

### V1 Workflow (`dotnet-v1.yml` — release/v1 branch)

```yaml
on:
  push:
    branches: [release/v1]
  pull_request:
    branches: [release/v1]
  release:
    types: [published]

# Build CoseSignTool.sln (V1 preserved on release/v1)
# Publish v1.x.y NuGet packages
# Tag pattern: v1.*
```

## Cross-Branch Fix Process

When a fix applies to both V1 and V2:

```bash
# Option A: Fix V1 first, cherry-pick to V2
git checkout release/v1
# ... fix, PR, merge → v1.7.6
git checkout main
git cherry-pick <sha>  # may need conflict resolution

# Option B: Fix V2 first, backport to V1
git checkout main
# ... fix, PR, merge
git checkout release/v1
git cherry-pick <sha>  # adapt to V1 architecture
```

## Timeline

| Milestone | Target | Notes |
|-----------|--------|-------|
| Create `release/v1` + set as default | Week 1 | Non-disruptive; V1 continues as-is |
| Validate V1 CI on `release/v1` | Week 1 | Tag `v1.7.5` to prove pipeline |
| Root migration on `v2_clean_slate` | Week 2 | Move V2 to root, verify build |
| PR: V2 → main | Week 2-3 | Review period |
| Merge + tag `v2.0.0-preview.1` | Week 3 | Default branch back to main |
| V2 GA (`v2.0.0`) | TBD | After preview stabilization |
| V1 deprecation announcement | V2 GA + 30 days | Minimum 12 month support window |
