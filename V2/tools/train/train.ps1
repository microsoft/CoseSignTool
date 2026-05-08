# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# train.ps1 — feature-train manager for the users/jstatia/v2_clean_slate integration branch.
#
# Pattern (mirrors C:\src\repos\ai-cookbook):
# - The integration branch is users/jstatia/v2_clean_slate.
# - Each "phase" gets a sibling worktree at C:\src\repos\CoseSignTool-tp-<phase>
#   with a DETACHED HEAD pointing at the integration-branch HEAD at add-time.
# - Work happens on the detached HEAD; commits accumulate.
# - Merge-back is gated by V2/collect-coverage.ps1 ≥ 95% line coverage.
# - No PRs — successful gate => `git merge --no-ff` into integration branch locally.
#
# Commands:
#   .\train.ps1 add     <phase>          # create a phase worktree (detached HEAD)
#   .\train.ps1 list                     # show all phase worktrees and ahead/behind
#   .\train.ps1 gate    <phase> [-Filter <project>]
#                                        # run collect-coverage.ps1 inside the phase worktree
#   .\train.ps1 merge   <phase> [-Project <name>] [-NoRegress]
#                                        # gate(s) + git merge --no-ff back into integration; remove worktree
#                                        # -Project triggers D11 per-project gate (≥95% absolute)
#                                        # -NoRegress triggers D11 (amended) full-solution non-regression check
#                                        #   instead of ≥95% absolute (use when integration baseline is below 95%)
#   .\train.ps1 remove  <phase>          # discard worktree without merging (DESTRUCTIVE; requires -Force)
#
# Coverage gate is non-negotiable: the script refuses to merge if the gate fails.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet('add', 'list', 'gate', 'merge', 'remove')]
    [string]$Command,

    [Parameter(Position = 1)]
    [string]$Phase,

    [string]$Filter = '',
    [string]$Project = '',
    [switch]$Force,
    [switch]$SkipGate,
    [switch]$NoRegress
)

$ErrorActionPreference = 'Stop'

$IntegrationBranch = 'users/jstatia/v2_clean_slate'
$RepoRoot = (git rev-parse --show-toplevel).Trim().Replace('/', '\')
$WorktreeRootParent = Split-Path -Parent $RepoRoot
$PhasePrefix = 'CoseSignTool-tp-'
$CoverageScript = Join-Path $RepoRoot 'V2\collect-coverage.ps1'
$CoverageTargetPercent = 95

function Get-PhaseWorktreePath {
    param([string]$P)
    return Join-Path $WorktreeRootParent ("$PhasePrefix$P")
}

function Assert-PhaseName {
    param([string]$P)
    if ([string]::IsNullOrWhiteSpace($P)) {
        throw "Phase name is required. Example: .\train.ps1 add spec"
    }
    if ($P -notmatch '^[a-z0-9][a-z0-9-]*$') {
        throw "Phase name '$P' must be lowercase alphanumeric + hyphen, starting with a letter or digit."
    }
}

function Get-IntegrationHead {
    return (git rev-parse $IntegrationBranch).Trim()
}

function Get-PhaseWorktrees {
    $output = git worktree list --porcelain
    $entries = @()
    $current = @{}
    foreach ($line in $output) {
        if ([string]::IsNullOrWhiteSpace($line)) {
            if ($current.Count -gt 0) { $entries += [pscustomobject]$current; $current = @{} }
            continue
        }
        $parts = $line -split ' ', 2
        $current[$parts[0]] = if ($parts.Count -gt 1) { $parts[1] } else { $true }
    }
    if ($current.Count -gt 0) { $entries += [pscustomobject]$current }

    return $entries | Where-Object {
        $_.worktree -and (Split-Path -Leaf $_.worktree).StartsWith($PhasePrefix)
    } | ForEach-Object {
        $name = (Split-Path -Leaf $_.worktree).Substring($PhasePrefix.Length)
        [pscustomobject]@{
            Phase    = $name
            Path     = $_.worktree
            Head     = $_.HEAD
            Detached = $_.PSObject.Properties['detached'] -ne $null
            Branch   = $_.PSObject.Properties['branch'] | ForEach-Object { $_.Value }
        }
    }
}

function Invoke-Add {
    Assert-PhaseName $Phase
    $worktreePath = Get-PhaseWorktreePath $Phase
    if (Test-Path $worktreePath) {
        throw "Worktree path already exists: $worktreePath"
    }
    $head = Get-IntegrationHead
    Write-Host "Creating detached worktree for phase '$Phase'" -ForegroundColor Cyan
    Write-Host "  Path:   $worktreePath"
    Write-Host "  Base:   $IntegrationBranch @ $head"

    git worktree add --detach $worktreePath $head | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "git worktree add failed." }

    Write-Host "Worktree created. cd '$worktreePath' to begin work." -ForegroundColor Green
}

function Invoke-List {
    $integrationHead = Get-IntegrationHead
    Write-Host "Integration branch: $IntegrationBranch @ $integrationHead" -ForegroundColor Cyan
    $worktrees = @(Get-PhaseWorktrees)
    if ($worktrees.Count -eq 0) {
        Write-Host "No phase worktrees." -ForegroundColor Yellow
        return
    }

    $rows = foreach ($w in $worktrees) {
        $ahead = (git -C $w.Path rev-list --count "$integrationHead..$($w.Head)" 2>$null)
        $behind = (git -C $w.Path rev-list --count "$($w.Head)..$integrationHead" 2>$null)
        $dirty = (git -C $w.Path status --porcelain 2>$null)
        [pscustomobject]@{
            Phase  = $w.Phase
            Head   = $w.Head.Substring(0, [Math]::Min(8, $w.Head.Length))
            Ahead  = "$ahead"
            Behind = "$behind"
            Dirty  = if ($dirty) { 'yes' } else { 'no' }
            Path   = $w.Path
        }
    }
    $rows | Format-Table -AutoSize
}

function Invoke-Gate {
    Assert-PhaseName $Phase
    $worktreePath = Get-PhaseWorktreePath $Phase
    if (-not (Test-Path $worktreePath)) {
        throw "Phase worktree not found: $worktreePath"
    }

    Write-Host "Running coverage gate for phase '$Phase'..." -ForegroundColor Cyan
    Push-Location (Join-Path $worktreePath 'V2')
    try {
        $args = @()
        if ($Filter) { $args += @('-ProjectFilter', $Filter) }
        & .\collect-coverage.ps1 @args
        $exit = $LASTEXITCODE
        if ($exit -eq 0) {
            Write-Host "Gate PASSED for phase '$Phase' (≥ $CoverageTargetPercent% line coverage)." -ForegroundColor Green
            return $true
        } else {
            Write-Host "Gate FAILED for phase '$Phase' (exit $exit)." -ForegroundColor Red
            return $false
        }
    } finally {
        Pop-Location
    }
}

function Get-CoverageFromSummary {
    param([string]$ReportDir)
    $summary = Join-Path $ReportDir 'Summary.txt'
    if (-not (Test-Path $summary)) { return $null }
    $line = (Get-Content $summary | Select-String 'Line coverage:' | Select-Object -First 1)
    if (-not $line) { return $null }
    $match = [regex]::Match($line.ToString(), 'Line coverage:\s*(\d+(?:\.\d+)?)%')
    if ($match.Success) { return [double]$match.Groups[1].Value }
    return $null
}

function Invoke-NoRegressFullGate {
    param([string]$WorktreePath)

    Write-Host "Running NoRegress full-solution gate (vs integration baseline)..." -ForegroundColor Cyan

    $integrationV2 = Join-Path $RepoRoot 'V2'
    $worktreeV2 = Join-Path $WorktreePath 'V2'

    Write-Host "  [1/2] Capturing baseline coverage at $IntegrationBranch..." -ForegroundColor Gray
    Push-Location $integrationV2
    try {
        & .\collect-coverage.ps1 2>&1 | Tee-Object -FilePath "$env:TEMP\train-baseline-cov.txt" | Out-Null
    } finally { Pop-Location }
    $baseline = Get-CoverageFromSummary (Join-Path $integrationV2 'coverage-report')
    if ($null -eq $baseline) {
        Write-Host "  Could not parse baseline coverage. Refusing to merge." -ForegroundColor Red
        return $false
    }

    Write-Host "  [2/2] Capturing post-merge coverage at phase worktree..." -ForegroundColor Gray
    Push-Location $worktreeV2
    try {
        & .\collect-coverage.ps1 2>&1 | Tee-Object -FilePath "$env:TEMP\train-phase-cov.txt" | Out-Null
    } finally { Pop-Location }
    $phase = Get-CoverageFromSummary (Join-Path $worktreeV2 'coverage-report')
    if ($null -eq $phase) {
        Write-Host "  Could not parse phase coverage. Refusing to merge." -ForegroundColor Red
        return $false
    }

    $delta = [math]::Round($phase - $baseline, 2)
    $arrow = if ($delta -ge 0) { "↑" } else { "↓" }
    Write-Host "  Baseline: $baseline%  |  Phase: $phase%  |  Delta: $arrow $([math]::Abs($delta))%" -ForegroundColor Cyan

    if ($phase -lt $baseline) {
        Write-Host "  NoRegress gate FAILED: phase regresses full-solution coverage." -ForegroundColor Red
        return $false
    }
    Write-Host "  NoRegress gate PASSED." -ForegroundColor Green
    return $true
}

function Invoke-Merge {
    Assert-PhaseName $Phase
    $worktreePath = Get-PhaseWorktreePath $Phase
    if (-not (Test-Path $worktreePath)) {
        throw "Phase worktree not found: $worktreePath"
    }

    $worktreeHead = (git -C $worktreePath rev-parse HEAD).Trim()
    $integrationHead = Get-IntegrationHead
    $ahead = [int](git -C $worktreePath rev-list --count "$integrationHead..$worktreeHead").Trim()
    if ($ahead -eq 0) {
        Write-Host "Phase '$Phase' has no commits ahead of $IntegrationBranch. Nothing to merge." -ForegroundColor Yellow
        return
    }

    $dirty = git -C $worktreePath status --porcelain
    if ($dirty) {
        throw "Phase worktree '$Phase' has uncommitted changes. Commit or stash before merging."
    }

    if (-not $SkipGate) {
        # D11 (amended) — per-project gate must hit ≥95% absolute; full-solution gate must not regress.
        if ($Project) {
            Write-Host "Per-project gate ($Project) — requires ≥95% absolute." -ForegroundColor Cyan
            $savedFilter = $script:Filter
            $script:Filter = $Project
            try {
                $perProjectPassed = Invoke-Gate
                if (-not $perProjectPassed) {
                    throw "Refusing to merge: per-project coverage gate failed for '$Project'."
                }
            } finally {
                $script:Filter = $savedFilter
            }
        }

        if ($NoRegress) {
            $fullPassed = Invoke-NoRegressFullGate -WorktreePath $worktreePath
            if (-not $fullPassed) {
                throw "Refusing to merge: full-solution coverage regressed vs integration baseline."
            }
        } else {
            # Legacy path: full-solution must hit ≥95% absolute.
            $script:Filter = ''
            $fullPassed = Invoke-Gate
            if (-not $fullPassed) {
                throw "Refusing to merge: full-solution coverage gate failed for phase '$Phase'. Add -NoRegress to enforce non-regression vs baseline instead of ≥95% absolute."
            }
        }
    } else {
        Write-Host "WARNING: -SkipGate specified — gate not enforced." -ForegroundColor Yellow
    }

    # Merge from the integration-branch checkout (this script's repo root).
    Push-Location $RepoRoot
    try {
        $current = (git rev-parse --abbrev-ref HEAD).Trim()
        if ($current -ne $IntegrationBranch) {
            throw "Run train.ps1 merge from a checkout on $IntegrationBranch (currently on '$current')."
        }
        $msg = "train: merge phase '$Phase' (gate ≥ $CoverageTargetPercent% line coverage)"
        Write-Host "Merging $worktreeHead into $IntegrationBranch with --no-ff..." -ForegroundColor Cyan
        git merge --no-ff --no-edit -m $msg $worktreeHead
        if ($LASTEXITCODE -ne 0) {
            throw "git merge failed. Resolve conflicts, then re-run: .\train.ps1 merge $Phase -SkipGate"
        }
    } finally {
        Pop-Location
    }

    Write-Host "Removing worktree for phase '$Phase'..." -ForegroundColor Cyan
    git worktree remove $worktreePath
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Failed to remove worktree at $worktreePath; clean up manually." -ForegroundColor Yellow
    } else {
        Write-Host "Phase '$Phase' merged and worktree removed." -ForegroundColor Green
    }
}

function Invoke-Remove {
    Assert-PhaseName $Phase
    $worktreePath = Get-PhaseWorktreePath $Phase
    if (-not (Test-Path $worktreePath)) {
        throw "Phase worktree not found: $worktreePath"
    }
    if (-not $Force) {
        throw "Refusing to discard phase '$Phase' without -Force. Any unmerged commits in the worktree will be lost."
    }
    Write-Host "DISCARDING worktree for phase '$Phase' (commits NOT merged)." -ForegroundColor Red
    git worktree remove --force $worktreePath
    if ($LASTEXITCODE -ne 0) { throw "git worktree remove failed." }
    Write-Host "Phase '$Phase' worktree removed without merging." -ForegroundColor Yellow
}

switch ($Command) {
    'add'    { Invoke-Add }
    'list'   { Invoke-List }
    'gate'   { [void](Invoke-Gate) }
    'merge'  { Invoke-Merge }
    'remove' { Invoke-Remove }
}
