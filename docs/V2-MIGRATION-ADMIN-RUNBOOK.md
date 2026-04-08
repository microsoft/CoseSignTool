# CoseSignTool V2 Migration — Admin Runbook

> **Repo**: [microsoft/CoseSignTool](https://github.com/microsoft/CoseSignTool)  
> **Purpose**: Prepare the repository for the V1→V2 cutover as described in `docs/V2-MIGRATION-STRATEGY.md`  
> **Requires**: Repository Admin (or Microsoft org-level admin with repo config access)  
> **Estimated time**: ~15 minutes  

---

## Context

We are migrating CoseSignTool from V1 (current `main`) to V2 (on branch `users/jstatia/v2_clean_slate`).
The migration requires:
- Preserving V1 on a long-term support branch (`release/v1`)
- Merging V2 to become the new `main`
- Gating GA releases behind a 2-maintainer approval environment

The dev team can handle all code changes, PRs, and workflow files.
**Only the items below require admin privileges.**

---

## Actions Required (in order)

### Step 1: Create `release-approvers` GitHub Environment

This environment gates GA releases for both V1 and V2, requiring 2 maintainer approvals before a release is published.

**Via UI:**
1. Go to **Settings → Environments → New environment**
2. Name: `release-approvers`
3. Under **Environment protection rules**:
   - ✅ **Required reviewers**: Add at least 2 maintainers (e.g., `elantiguamsft`, `JeromySt`, `lemccomb`)
   - (Optional) Check "Prevent self-review" if desired
4. Under **Deployment branches and tags**:
   - Select **Protected branches only** (or "Selected branches" → `main`, `release/v1`)
5. Click **Save protection rules**

**Via `gh` CLI (if you prefer scripting):**
```bash
# Create the environment
gh api repos/microsoft/CoseSignTool/environments/release-approvers \
  -X PUT \
  -f wait_timer=0 \
  -f prevent_self_review=true \
  --input - <<'EOF'
{
  "reviewers": [
    {"type": "User", "id": USER_ID_1},
    {"type": "User", "id": USER_ID_2}
  ],
  "deployment_branch_policy": {
    "protected_branches": true,
    "custom_branch_policies": false
  }
}
EOF
```
> Replace `USER_ID_1`, `USER_ID_2` with actual GitHub user IDs of the approving maintainers.
> Get user IDs with: `gh api users/USERNAME --jq .id`

---

### Step 2: Create and Protect the `release/v1` Branch

**2a. Create the branch** (dev team can do this, but listed here for completeness):
```bash
# Create release/v1 from current main HEAD
gh api repos/microsoft/CoseSignTool/git/refs \
  -X POST \
  -f ref="refs/heads/release/v1" \
  -f sha="$(gh api repos/microsoft/CoseSignTool/git/ref/heads/main --jq .object.sha)"
```

**2b. Add branch protection to `release/v1`** (admin only):

Apply the same rules as `main`. At minimum:
- ✅ Require pull request reviews before merging (1+ approvals)
- ✅ Require status checks to pass (add `build` from `dotnet-v1.yml` once it runs)
- ✅ Require branches to be up to date
- ✅ Do not allow bypassing the above settings
- (Optional) Require signed commits
- (Optional) Restrict who can push

**Via `gh` CLI:**
```bash
gh api repos/microsoft/CoseSignTool/branches/release%2Fv1/protection \
  -X PUT \
  --input - <<'EOF'
{
  "required_status_checks": {
    "strict": true,
    "contexts": []
  },
  "enforce_admins": true,
  "required_pull_request_reviews": {
    "required_approving_review_count": 1,
    "dismiss_stale_reviews": true
  },
  "restrictions": null
}
EOF
```
> **Note**: The `microsoft-production-ruleset` (org-level) may already cover `release/v1` if it matches the pattern. Check the org ruleset to confirm. If so, repo-level protection may be redundant but won't conflict.

---

### Step 3: Temporarily Set `release/v1` as Default Branch

This protects existing V1 PRs and forks during the merge window.

```bash
gh api repos/microsoft/CoseSignTool \
  -X PATCH \
  -f default_branch="release/v1"
```

**Via UI:** Settings → General → Default branch → Change to `release/v1` → Update

> **Timing**: Do this AFTER the `release/v1` branch exists (Step 2a) and BEFORE the V2→main merge PR.

---

### Step 4: After V2 Merge — Switch Default Branch Back to `main`

Once the V2 merge PR is merged and validated:

```bash
gh api repos/microsoft/CoseSignTool \
  -X PATCH \
  -f default_branch="main"
```

**Via UI:** Settings → General → Default branch → Change to `main` → Update

---

## Summary Checklist

| # | Action | When | Admin? |
|---|--------|------|--------|
| 1 | Create `release-approvers` environment (2 reviewers) | Before any release | ✅ Yes |
| 2a | Create `release/v1` branch from `main` | Phase 1 start | ❌ Dev team |
| 2b | Add branch protection to `release/v1` | After 2a | ✅ Yes |
| 3 | Set default branch → `release/v1` | Before V2 merge | ✅ Yes |
| — | *Dev team: open & merge V2 → main PR* | Phase 3 | ❌ Dev team |
| — | *Dev team: validate CI, pre-release, NuGet* | Phase 3 | ❌ Dev team |
| 4 | Set default branch → `main` | After V2 validated | ✅ Yes |

---

## Alternative: Grant Temporary Admin

If it's simpler, granting `JeromySt` temporary **admin** access on `microsoft/CoseSignTool` would allow the dev team to handle all 4 steps during the migration window, then revoke admin afterward.

This can be done via:
- Microsoft org team management (Azure AD group that maps to repo admin)
- Or: Settings → Collaborators → Change `JeromySt` role to Admin

The migration window is estimated at ~1 week. Admin can be revoked after Step 4.

---

## Questions for Admin

1. Does the `microsoft-production-ruleset` auto-apply to `release/v1`? If so, Step 2b may be unnecessary.
2. Are there any org-level policies that restrict creating GitHub Environments with reviewers?
3. Is temporary admin access an option, or do we prefer the checklist approach?
