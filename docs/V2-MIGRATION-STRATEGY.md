# CoseSignTool V2 Migration & Release Strategy

> **Status**: Proposed  
> **Authors**: CoseSignTool Maintainers  
> **Last Updated**: 2026-03-23

## Overview

This document proposes the complete strategy for shipping CoseSignTool V2 as the primary codebase while maintaining V1 long-term support. It covers branching, project layout, CI/CD automation, version management, and the release process.

Both V1 and V2 use the same automated CI/CD model:
- `Directory.Build.props` is the **single source of truth** for all versions
- Every push auto-increments the pre-release number and publishes a pre-release
- GA releases are minted manually via `workflow_dispatch` with 2-maintainer approval
- V1 is locked to major version `1`; V2 starts at major version `2`

## Goals

1. **Ship V2 on `main`** — V2 becomes the primary development branch with projects at the repo root
2. **Preserve V1 on `release/v1`** — V1 remains buildable, testable, and releasable for bug/security fixes
3. **Zero disruption to V1 consumers** — NuGet semver handles the transition naturally
4. **Fully automated versioning** — CI manages all version bumps, tags, and releases from `Directory.Build.props`
5. **Gated releases** — GA releases require 2 maintainer approvals via GitHub environment protection
6. **Identical CI model** — Both branches use the same workflow pattern (auto pre-release + manual mint)

---

## 1. Branch Strategy

```
                        v1.7.4 (current main)
    main ─────────────────●
                          │
                          ├─→ release/v1  ← V1 LTS (default branch during transition)
                          │     ├── v1.7.5-preview.1 (auto, first push)
                          │     ├── v1.7.5 (minted GA)
                          │     ├── v1.7.6-preview.1
                          │     └── ... (locked to major version 1)
                          │
    v2_clean_slate ───────●─→ main (V2 merged, projects at root)
                                ├── v2.0.0-preview.1 (auto, first push)
                                ├── v2.0.0-preview.2
                                ├── v2.0.0 (minted GA)
                                ├── v2.1.0-preview.1 (next cycle)
                                └── ...
```

### Branch Roles

| Branch | Purpose | Protected | Major Version Lock | CI Workflow | Tag Pattern |
|--------|---------|-----------|-------------------|-------------|-------------|
| `main` | V2 active development | Yes | `2` | `dotnet.yml` | `v2.x.y` |
| `release/v1` | V1 maintenance (LTS) | Yes | `1` | `dotnet-v1.yml` | `v1.x.y` |

### Default Branch Transition

| Phase | Default Branch | Reason |
|-------|---------------|--------|
| **Before merge** | `release/v1` | Protect existing PRs and forks; V1 CI continues uninterrupted |
| **After V2 merge + validation** | `main` | V2 is primary; new PRs target V2 |

---

## 2. Root Layout Migration

V2 projects currently live in the `V2/` subdirectory. As part of this migration, they move to the repo root.

### Before → After

```
BEFORE (current main)                   AFTER (post-merge main)
─────────────────────                   ───────────────────────
├── CoseHandler/          ❌ DELETE      ├── Cose.Abstractions/
├── CoseSign1/            ❌ DELETE      ├── Cose.Headers/
├── CoseSign1.Tests/      ❌ DELETE      ├── CoseSign1.Abstractions/
├── ... (30 more V1 dirs) ❌ DELETE      ├── CoseSign1.Certificates/
├── CoseSignTool.sln      ❌ REPLACE    ├── CoseSign1.Factories/
├── CoseSign1.md          ❌ DELETE      ├── CoseSign1.Validation/
├── Directory.Build.props  🔀 REPLACE   ├── ... (40+ V2 projects)
├── Directory.Packages.props 🔀 MERGE   ├── CoseSignTool.sln  ← renamed from CoseSignToolV2.sln
│                                        ├── Directory.Build.props  ← V2 version
├── V2/                   ❌ REMOVE     ├── Directory.Packages.props  ← merged
│   └── (all V2 projects) ↗ MOVE UP    │
│                                        ├── .github/  ✅ kept
├── .github/              ✅ KEEP       ├── native/   ✅ kept
├── native/               ✅ KEEP       ├── docs/     🔀 merged
├── docs/                 🔀 MERGE      ├── LICENSE   ✅ kept
├── .editorconfig         ✅ KEEP ROOT  └── README.md 🔀 updated
├── LICENSE               ✅ KEEP
└── README.md             🔀 UPDATE
```

### Migration Risk: Minimal

- **0 .csproj edits needed** — all paths use `$(MSBuildThisFileDirectory)`, which resolves relative to `Directory.Build.props` location
- **0 CI path updates** — no hardcoded `V2/` in workflow files
- V1 code preserved on `release/v1` — nothing is lost

---

## 3. Version Management

### Single Source of Truth

Both V1 and V2 branches use `Directory.Build.props` to control all versions:

```xml
<PropertyGroup>
    <VersionPrefix>2.0.0</VersionPrefix>       <!-- The next release version -->
    <VersionSuffix>preview.3</VersionSuffix>    <!-- Pre-release iteration -->
    <!-- Derived automatically: -->
    <!-- Version         = 2.0.0-preview.3 -->
    <!-- PackageVersion  = 2.0.0-preview.3 -->
    <!-- AssemblyVersion = 2.0.0.0 -->
</PropertyGroup>
```

Every NuGet package, assembly, release tag, and GitHub release derives from these two properties. There is no separate version management anywhere.

### Identical Flow for Both Branches

Both `main` (V2) and `release/v1` (V1) use the exact same CI model:

#### Automatic Pre-release (every push)

```
Developer merges PR → push to branch

  CI reads Directory.Build.props:    X.Y.Z-preview.N
  CI increments:                     X.Y.Z-preview.(N+1)
  CI commits:                        "Bump version to X.Y.Z-preview.(N+1) [skip ci]"
  CI tags:                           vX.Y.Z-preview.(N+1)
  CI creates GitHub pre-release with:
    - Platform executables (win-x64, linux-x64, osx-x64, osx-arm64)
    - NuGet packages (all library projects)
```

#### Manual "Mint Release" (workflow_dispatch)

```
Maintainer navigates to Actions → workflow → "Run workflow"
  Selects release_type: "minor" or "patch"
  Clicks "Run workflow"

  → GitHub requests approval from "release-approvers" environment
  → 2 maintainers approve

  CI executes:
    1. Strip VersionSuffix:         X.Y.Z-preview.N → X.Y.Z
    2. Build + test (all platforms)
    3. If tests pass:
       a. Commit:                   "Release X.Y.Z"
       b. Tag:                      vX.Y.Z
       c. Bump to next cycle:       X.(Y+1).0-preview.1  (minor)
                                    or X.Y.(Z+1)-preview.1 (patch)
       d. Commit:                   "Begin X.(Y+1).0-preview.1 development [skip ci]"
       e. Push commits + tag
    4. Create GitHub GA release with executables + NuGet packages
```

### V1 Major Version Lock

The `release/v1` workflow enforces that the major version stays at `1`:

```yaml
# In dotnet-v1.yml, the version bump step validates:
MAJOR=$(echo "$PREFIX" | cut -d. -f1)
if [ "$MAJOR" != "1" ]; then
  echo "❌ ERROR: release/v1 branch must stay on major version 1 (found: $MAJOR)"
  exit 1
fi
```

This prevents accidental version `2.x` releases from the V1 branch. The V1 branch can only produce `v1.x.y` tags and `1.x.y` NuGet packages.

### Version Lifecycle Examples

**V2 (main branch):**
```
v2.0.0-preview.1  ← first push after merge
v2.0.0-preview.2  ← PR merged
v2.0.0-preview.3  ← PR merged
v2.0.0            ← maintainers mint GA (minor bump selected)
v2.1.0-preview.1  ← next dev cycle begins automatically
v2.1.0-preview.2  ← PR merged
v2.1.0            ← maintainers mint GA
v2.2.0-preview.1  ← continues...
```

**V1 (release/v1 branch):**
```
v1.7.5-preview.1  ← first push after branch creation
v1.7.5            ← maintainers mint GA (patch bump selected)
v1.7.6-preview.1  ← security fix PR merged
v1.7.6            ← maintainers mint patch release
v1.8.0-preview.1  ← minor fix PR merged (minor bump selected)
v1.8.0            ← maintainers mint GA
```

---

## 4. CI/CD Workflows

### Shared Model

Both workflows follow the identical three-trigger pattern. The only differences are the branch name, solution file path, and the major version lock on V1.

| Trigger | V2 (`dotnet.yml` on `main`) | V1 (`dotnet-v1.yml` on `release/v1`) |
|---------|---------------------------|--------------------------------------|
| **Pull Request** | Build + test + changelog | Build + test + changelog |
| **Push** | Bump preview, tag, pre-release | Bump preview, tag, pre-release (locked to `1.x`) |
| **Manual dispatch** | Mint GA release (v2.x.y) | Mint GA release (v1.x.y, major=1 enforced) |

### Key Differences

| Aspect | V2 (`main`) | V1 (`release/v1`) |
|--------|------------|-------------------|
| .NET SDK | 10.0.x | 8.0.x |
| Solution file | `CoseSignTool.sln` (root, V2) | `CoseSignTool.sln` (root, V1) |
| Test execution | `dotnet test` on solution | Individual test project invocations |
| Major version | `2` (no lock needed — it's the active stream) | `1` (enforced by CI guard) |
| NuGet packages | 15+ library projects | 9 library projects |

### Required GitHub Configuration

**Environment: `release-approvers`**
- Settings → Environments → New environment
- Name: `release-approvers`
- Required reviewers: 2 (select maintainers)
- Used by both V1 and V2 "Mint Release" workflows

**Branch protection: `release/v1`**
- Same rules as current `main` protection
- Required status checks: `dotnet-v1.yml` build + test

---

## 5. NuGet Package Strategy

### Same Package IDs, Major Version Bump

Packages that exist in both V1 and V2 keep their NuGet package IDs. SemVer handles the transition:

| Package | V1 (`release/v1`) | V2 (`main`) |
|---------|-------------------|-------------|
| CoseSign1.Abstractions | 1.7.x → 1.8.x | 2.0.0+ |
| CoseSign1.Certificates | 1.7.x → 1.8.x | 2.0.0+ |
| CoseSign1.Headers | 1.7.x → 1.8.x | 2.0.0+ |
| CoseSign1.Transparent.MST | 1.7.x → 1.8.x | 2.0.0+ |
| CoseSignTool.Abstractions | 1.7.x → 1.8.x | 2.0.0+ |

### New V2-Only Packages

| Package | Description |
|---------|-------------|
| Cose.Abstractions | Generic COSE header contribution (RFC 9052) |
| Cose.Headers | CWT Claims, generic header implementations |
| CoseSign1.Validation | Staged validation pipeline with trust engine |
| CoseSign1.Factories | Direct/Indirect signature factories |
| CoseSign1.AzureKeyVault | Azure Key Vault signing service |
| CoseSign1.Certificates.Local | Local certificate key provider |
| DIDx509 | DID:x509 parser, builder, resolver, validator |

### Consumer Guidance

| I want to... | Do this |
|-------------|---------|
| Stay on V1 | Pin `<PackageReference Version="[1.7.*, 2.0.0)" />` |
| Try V2 preview | Update to `Version="2.0.0-preview.*"` |
| Use V2 GA | Update to `Version="2.0.0"` |

---

## 6. V1 Long-Term Support Policy

| Aspect | Policy |
|--------|--------|
| Branch | `release/v1` |
| Scope | Security fixes, critical bug fixes, dependency updates |
| New features | Not accepted — new work goes to V2 on `main` |
| Versioning | `1.x.y` only (major version `1` enforced by CI) |
| CI model | Same as V2: auto pre-release on push, manual mint for GA |
| Release gating | Same `release-approvers` environment (2 approvals) |
| Support timeline | Minimum 12 months after V2 GA; deprecation announced 90 days in advance |

### Cross-Branch Fixes

When a fix applies to both V1 and V2:

```bash
# Fix on release/v1 first, then cherry-pick to main
git checkout release/v1
# ... fix, PR, merge (auto-creates v1.x.y-preview.N)
# ... mint release → v1.x.y

git checkout main
git cherry-pick <sha>   # resolve conflicts if architectures differ
# ... auto-creates v2.x.y-preview.N on next push
```

---

## 7. Execution Checklist

### Phase 1: Prepare V1 LTS *(Week 1)*

- [ ] Create `release/v1` branch from current `main` (at v1.7.4)
- [ ] Set `release/v1` as default branch in GitHub settings
- [ ] Configure branch protection on `release/v1`
- [ ] Update V1 `Directory.Build.props` to use `VersionPrefix`/`VersionSuffix` pattern if not already
- [ ] Create `dotnet-v1.yml` CI workflow (with major version `1` lock)
- [ ] Create `release-approvers` GitHub environment (2 required reviewers)
- [ ] Tag `v1.7.5-preview.1` from `release/v1` to validate auto-versioning pipeline
- [ ] Mint `v1.7.5` GA to validate full release pipeline
- [ ] Announce V1 LTS plan to stakeholders

### Phase 2: Prepare V2 for Root *(Week 2)*

- [ ] On `v2_clean_slate`: delete 33 V1 root project directories
- [ ] Move `V2/*` to repo root
- [ ] Rename `CoseSignToolV2.sln` → `CoseSignTool.sln`
- [ ] Merge/consolidate: `Directory.Build.props`, `Directory.Packages.props`, `docs/`, `StrongNameKeys/`
- [ ] Replace `dotnet.yml` with V2 version (auto-versioning, mint release)
- [ ] Build + run all 2,900+ tests to verify
- [ ] Commit with clear message describing the migration

### Phase 3: Merge V2 to Main *(Week 2-3)*

- [ ] Open PR from `v2_clean_slate` → `main` with this document linked
- [ ] Review period (team)
- [ ] Merge (squash commit recommended)
- [ ] First push auto-triggers: version bump to `2.0.0-preview.1`, pre-release created
- [ ] Verify NuGet packages and executables published correctly

### Phase 4: Post-Merge *(Week 3+)*

- [ ] Switch default branch back to `main`
- [ ] Archive `v2_clean_slate` branch
- [ ] Publish V1 → V2 migration guide
- [ ] Update GitHub repo description/topics
- [ ] Announce V2 preview availability

---

## 8. Risk Assessment

| Risk | Severity | Mitigation |
|------|----------|------------|
| V1 users surprised by breaking change | Low | Pre-release `-preview` suffix; V1 pinning guidance; 12-month LTS |
| V1 needs urgent security fix post-merge | None | `release/v1` always available with dedicated CI and mint release |
| .csproj path breakage during root migration | None | All paths use `$(MSBuildThisFileDirectory)` — zero edits needed |
| NuGet package ID confusion | Low | Same IDs + semver `1.x` vs `2.x` is unambiguous |
| CI complexity with two branches | Low | Separate workflow files with identical structure |
| Cherry-pick conflicts between V1 and V2 | Medium | Architectures differ significantly; some fixes may need manual port |
| Accidental GA release | None | `release-approvers` environment requires 2 maintainer approvals |
| Accidental V2 version on V1 branch | None | Major version `1` lock enforced in CI — workflow fails if major ≠ 1 |

---

## Appendix A: Workflow File Reference

| File | Branch | Purpose |
|------|--------|---------|
| `.github/workflows/dotnet.yml` | `main` | V2 build/test/publish with auto-versioning + mint release |
| `.github/workflows/dotnet-v1.yml` | `release/v1` | V1 build/test/publish with auto-versioning + mint release (major=1 locked) |
| `.github/workflows/codeql.yml` | Both | Security scanning (unchanged) |
| `.github/workflows/dependency-review.yml` | Both | Supply chain security (unchanged) |

## Appendix B: GitHub Environment Setup

### `release-approvers` Environment

Both V1 and V2 "Mint Release" workflows use this environment for gating:

1. Navigate to **Settings → Environments → New environment**
2. Name: `release-approvers`
3. Configure **Required reviewers**: select 2 maintainers
4. (Optional) Add **wait timer**: 0 minutes (immediate after approval)
5. (Optional) Restrict to protected branches only

When a maintainer triggers "Mint Release", GitHub will:
- Show a pending approval in the Actions UI
- Notify the configured reviewers
- Wait for 2 approvals before executing the release jobs
- If rejected, the workflow is cancelled — no version changes, no tags, no releases
