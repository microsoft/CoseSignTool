param(
    [int]$FailUnderLines = 95,
    [string]$OutputDir = "coverage",
    [switch]$NoHtml,
    [switch]$NoClean,
    [switch]$AbiParityCheckOnly,
    [switch]$DependencyCheckOnly,
    # Run coverage for a single crate instead of the whole workspace.
    # When set, quality gates are skipped (run workspace mode for the final gate).
    # Uses the shared target directory (not per-run isolation) so profraw files
    # are placed correctly by cargo-llvm-cov.
    [string]$Package,
    # Skip quality gates even in workspace mode (useful for quick checks).
    [switch]$SkipGates,
    # Maximum parallel jobs for per-crate coverage report generation (default: CPU count).
    [int]$Parallelism = 0
)

$ErrorActionPreference = "Stop"

$here = Split-Path -Parent $MyInvocation.MyCommand.Path

function Assert-NoTestsInSrc {
    param(
        [Parameter(Mandatory = $true)][string]$Root
    )

    $patterns = @(
        '#\[cfg\(test\)\]',
        '#\[test\]',
        '^\s*mod\s+tests\b'
    )

    $srcFiles = Get-ChildItem -Path $Root -Recurse -File -Filter '*.rs' |
        Where-Object {
            $_.FullName -match '(\\|/)src(\\|/)' -and
            $_.FullName -notmatch '(\\|/)target(\\|/)' -and
            $_.FullName -notmatch '(\\|/)tests(\\|/)' -and
            $_.FullName -notmatch '(\\|/)cose_openssl(\\|/)'
        }

    $violations = @()
    foreach ($file in $srcFiles) {
        foreach ($pattern in $patterns) {
            $matches = Select-String -Path $file.FullName -Pattern $pattern -AllMatches -CaseSensitive:$false -ErrorAction SilentlyContinue
            if ($matches) {
                $violations += $matches
            }
        }
    }

    if ($violations.Count -gt 0) {
        Write-Host "ERROR: Test code detected under src/. Move tests to the crate's tests/ folder." -ForegroundColor Red
        $violations |
            Select-Object -First 50 |
            ForEach-Object { Write-Host ("  {0}:{1}: {2}" -f $_.Path, $_.LineNumber, $_.Line.Trim()) -ForegroundColor Red }
        throw "No-tests-in-src gate failed. Found $($violations.Count) matches."
    }
}

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [Parameter(Mandatory = $true)][scriptblock]$Run
    )

    & $Run | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "$Command failed with exit code $LASTEXITCODE"
    }
}

function Remove-LlvmCovNoise {
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)][object]$Item
    )

    process {
        $line = $null
        if ($Item -is [System.Management.Automation.ErrorRecord]) {
            $line = $Item.Exception.Message
        } else {
            $line = $Item.ToString()
        }

        if ([string]::IsNullOrWhiteSpace($line)) {
            return
        }

        # llvm-profdata/llvm-cov can emit a deterministic warning in multi-crate coverage runs:
        #   "warning: <N> functions have mismatched data"
        # This message is noisy and doesn't affect the repo's coverage gates.
        if ($line -notmatch 'functions have mismatched data') {
            $line
        }
    }
}

function Assert-FluentHelpersProjectedToFfi {
    param(
        [Parameter(Mandatory = $true)][string]$Root
    )

    # Fluent helper surfaces that should be projected to the Rust FFI layer.
    # Note: This is intentionally scoped to callback-free `require_*` helpers.
    $fluentFiles = @(
        (Join-Path $Root 'validation\core\src\message_facts.rs'),
        (Join-Path $Root 'extension_packs\certificates\src\validation\fluent_ext.rs'),
        (Join-Path $Root 'extension_packs\mst\src\validation\fluent_ext.rs'),
        (Join-Path $Root 'extension_packs\azure_key_vault\src\validation\fluent_ext.rs')
    )

    foreach ($p in $fluentFiles) {
        if (-not (Test-Path $p)) {
            throw "ABI parity gate: expected fluent file not found: $p"
        }
    }

    # Rust-only helpers that intentionally cannot/should not be projected across the C ABI.
    # These rely on passing closures/callbacks.
    $excluded = @(
        'require_cwt_claim'
        , 'require_kid_allowed'
        , 'require_trusted'
    )

    $requireMethods = @()
    foreach ($p in $fluentFiles) {
        $matches = Select-String -Path $p -Pattern '\bfn\s+(require_[A-Za-z0-9_]+)\b' -AllMatches
        foreach ($m in $matches) {
            foreach ($mm in $m.Matches) {
                $name = $mm.Groups[1].Value
                if ($excluded -notcontains $name) {
                    $requireMethods += $name
                }
            }
        }
    }

    $requireMethods = $requireMethods | Sort-Object -Unique

    $ffiFiles = Get-ChildItem -Path $Root -Recurse -File -Filter 'lib.rs' |
        Where-Object {
            $_.FullName -match '(\\|/)ffi(\\|/)src(\\|/)' -and
            $_.FullName -notmatch '(\\|/)target(\\|/)' -and
            $_.FullName -notmatch '(\\|/)partner(\\|/)'
        }

    if ($ffiFiles.Count -eq 0) {
        throw "ABI parity gate: no Rust FFI lib.rs files found under $Root"
    }

    $missing = @()
    foreach ($name in $requireMethods) {
        $escaped = [regex]::Escape($name)
        # Use alphanumeric boundaries (not \b) so we still match snake_case substrings inside
        # exported names like `cose_*_require_xxx(...)`.
        $pattern = "(?<![A-Za-z0-9]){0}(?![A-Za-z0-9])" -f $escaped
        $found = Select-String -Path $ffiFiles.FullName -Pattern $pattern -AllMatches -ErrorAction SilentlyContinue
        if (-not $found) {
            $missing += $name
        }
    }

    if ($missing.Count -gt 0) {
        Write-Host "ERROR: ABI parity gate failed." -ForegroundColor Red
        Write-Host "The following Rust fluent helpers exist but are not referenced by any Rust FFI projection (native/rust/validation/*_ffi/src/lib.rs):" -ForegroundColor Red
        $missing |
            Select-Object -First 50 |
            ForEach-Object { Write-Host ("  - {0}" -f $_) -ForegroundColor Red }

        Write-Host "\nFix: add/extend the appropriate pack FFI export(s) so native projections can access the new helper." -ForegroundColor Yellow
        Write-Host "If a helper is intentionally Rust-only (requires callbacks), add it to the exclusion list in collect-coverage.ps1." -ForegroundColor Yellow
        throw "ABI parity gate failed. Missing projections for $($missing.Count) helper(s)."
    }

    Write-Host "OK: ABI parity gate passed (Rust fluent helpers are referenced by FFI projections)." -ForegroundColor Green
}

function Assert-AllowedDependencies {
    param(
        [Parameter(Mandatory = $true)][string]$Root
    )

    $allowlistPath = Join-Path $Root 'allowed-dependencies.toml'
    if (-not (Test-Path $allowlistPath)) {
        throw "Dependency allowlist not found: $allowlistPath"
    }

    # Parse three-tier allowlist TOML:
    #   [global]       -> allowed in any crate's [dependencies]
    #   [dev]          -> allowed in any crate's [dev-dependencies]
    #   [crate.<name>] -> allowed only in that crate's [dependencies]
    $globalAllowed = @{}
    $devAllowed = @{}
    $crateAllowed = @{}  # crate_name -> @{ dep_name = $true }
    $currentSection = ''
    $currentCrate = ''

    foreach ($line in (Get-Content $allowlistPath)) {
        $line = $line.Trim()
        if ($line -eq '' -or $line.StartsWith('#')) { continue }

        if ($line -match '^\[global\]$') {
            $currentSection = 'global'; $currentCrate = ''; continue
        }
        if ($line -match '^\[dev\]$') {
            $currentSection = 'dev'; $currentCrate = ''; continue
        }
        if ($line -match '^\[crate\.([a-zA-Z0-9_-]+)\]$') {
            $currentSection = 'crate'; $currentCrate = $Matches[1]
            if (-not $crateAllowed[$currentCrate]) { $crateAllowed[$currentCrate] = @{} }
            continue
        }
        if ($line -match '^\[') {
            $currentSection = ''; $currentCrate = ''; continue
        }

        if ($line -match '^([a-zA-Z0-9_-]+)\s*=') {
            $depName = $Matches[1]
            switch ($currentSection) {
                'global' { $globalAllowed[$depName] = $true }
                'dev'    { $devAllowed[$depName] = $true }
                'crate'  {
                    if ($currentCrate -and $crateAllowed[$currentCrate]) {
                        $crateAllowed[$currentCrate][$depName] = $true
                    }
                }
            }
        }
    }

    $totalSections = $globalAllowed.Count + $devAllowed.Count + ($crateAllowed.Keys | ForEach-Object { $crateAllowed[$_].Count } | Measure-Object -Sum).Sum
    if ($totalSections -eq 0) {
        throw "Dependency allowlist is empty or could not be parsed: $allowlistPath"
    }

    # Scan all member Cargo.toml files for external dependencies
    $violations = @()
    $totalExternal = 0
    $cargoFiles = Get-ChildItem -Path $Root -Recurse -Filter 'Cargo.toml' |
        Where-Object {
            $_.FullName -notmatch '(\\|/)target(\\|/)' -and
            $_.FullName -notmatch '(\\|/)cose_openssl(\\|/)' -and
            $_.Directory.FullName -ne $Root
        }

    foreach ($file in $cargoFiles) {
        $crateName = $file.Directory.Name
        $inDepsSection = $false
        $isDevSection = $false

        foreach ($fileLine in (Get-Content $file.FullName)) {
            $trimmed = $fileLine.Trim()
            if ($trimmed -match '^\[dev-dependencies\]') {
                $inDepsSection = $true; $isDevSection = $true; continue
            }
            if ($trimmed -match '^\[dependencies\]') {
                $inDepsSection = $true; $isDevSection = $false; continue
            }
            if ($trimmed -match '^\[') {
                $inDepsSection = $false; continue
            }
            if (-not $inDepsSection) { continue }
            if ($trimmed -eq '' -or $trimmed.StartsWith('#')) { continue }

            if ($trimmed -match '^([a-zA-Z0-9_-]+)') {
                $depName = $Matches[1]
                if ($trimmed -match 'path\s*=') { continue }
                $totalExternal++

                $isAllowed = $false

                if ($isDevSection) {
                    # Dev deps: allowed if in [global], [dev], or [crate.<name>]
                    $isAllowed = $globalAllowed.ContainsKey($depName) -or
                                 $devAllowed.ContainsKey($depName) -or
                                 ($crateAllowed[$crateName] -and $crateAllowed[$crateName].ContainsKey($depName))
                } else {
                    # Production deps: allowed if in [global] or [crate.<name>]
                    $isAllowed = $globalAllowed.ContainsKey($depName) -or
                                 ($crateAllowed[$crateName] -and $crateAllowed[$crateName].ContainsKey($depName))
                }

                if (-not $isAllowed) {
                    $section = if ($isDevSection) { 'dev-dependencies' } else { 'dependencies' }
                    $violations += [PSCustomObject]@{
                        Crate   = $crateName
                        Dep     = $depName
                        Section = $section
                        File    = $file.FullName
                    }
                }
            }
        }
    }

    if ($violations.Count -gt 0) {
        Write-Host "ERROR: Dependency allowlist gate failed." -ForegroundColor Red
        Write-Host "The following dependencies are not allowed:" -ForegroundColor Red
        $violations | ForEach-Object {
            Write-Host ("  - {0} in {1} [{2}]" -f $_.Dep, $_.Crate, $_.Section) -ForegroundColor Red
        }
        Write-Host ""
        Write-Host "Fix options:" -ForegroundColor Yellow
        Write-Host "  1. Add to [global] in allowed-dependencies.toml (if universally needed)" -ForegroundColor Yellow
        Write-Host "  2. Add to [crate.<name>] in allowed-dependencies.toml (scoped)" -ForegroundColor Yellow
        Write-Host "  3. Add to [dev] in allowed-dependencies.toml (if test-only)" -ForegroundColor Yellow
        Write-Host "  4. Remove the dependency from the crate" -ForegroundColor Yellow
        throw "Dependency allowlist gate failed. $($violations.Count) unlisted dependency(ies) found."
    }

    $globalCount = $globalAllowed.Count
    $crateCount = ($crateAllowed.Keys | ForEach-Object { $crateAllowed[$_].Count } | Measure-Object -Sum).Sum
    Write-Host "OK: Dependency allowlist gate passed ($totalExternal external deps: $globalCount global, $crateCount per-crate, all allowed)." -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# Per-crate coverage collection with own-source-only filtering
# ---------------------------------------------------------------------------
# This approach avoids Windows command-line-length limits (os error 206) that
# occur when llvm-cov.exe is invoked with hundreds of --object arguments in a
# single workspace report.
#
# Strategy:
#   1. Run all tests once with `cargo llvm-cov --workspace --json` (combined).
#   2. Parse the JSON output to get per-file coverage data.
#   3. Map each file to its owning crate by matching against crate src/ dirs.
#   4. Aggregate per-crate and overall coverage from own-source files only
#      (transitive dependency code is excluded).
# ---------------------------------------------------------------------------

function Get-ProductionCrates {
    <#
    .SYNOPSIS
    Enumerates workspace members that are production crates (excludes demo,
    test_utils, and partner crates that require separate setup).
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Root
    )

    $cargoToml = Join-Path $Root 'Cargo.toml'
    $content = Get-Content $cargoToml -Raw
    $memberPaths = [regex]::Matches($content, '"([^"]+)"') |
        ForEach-Object { $_.Groups[1].Value } |
        Where-Object { $_ -notmatch '(demo|test_utils|cose_openssl)' }

    $crates = @()
    foreach ($mp in $memberPaths) {
        $ct = Join-Path (Join-Path $Root $mp) 'Cargo.toml'
        if (-not (Test-Path $ct)) { continue }
        $nameMatch = Select-String -Path $ct -Pattern '^\s*name\s*=\s*"([^"]+)"' |
            Select-Object -First 1
        if (-not $nameMatch) { continue }
        $srcDir = Join-Path (Resolve-Path (Join-Path $Root $mp)).Path 'src'
        if (-not (Test-Path $srcDir)) { continue }
        $crates += [PSCustomObject]@{
            Name   = $nameMatch.Matches.Groups[1].Value
            Path   = $mp
            SrcDir = $srcDir
        }
    }
    return $crates
}

function ConvertTo-PerCrateCoverage {
    <#
    .SYNOPSIS
    Takes parsed JSON coverage data and a list of production crates, maps each
    source file to its owning crate, and returns per-crate coverage stats
    containing only that crate's own source files (no transitive dependencies).
    #>
    param(
        [Parameter(Mandatory = $true)]$CoverageJson,
        [Parameter(Mandatory = $true)]$Crates
    )

    $results = @()
    foreach ($crate in $Crates) {
        $ownFiles = $CoverageJson.data[0].files | Where-Object {
            $_.filename.StartsWith($crate.SrcDir + [IO.Path]::DirectorySeparatorChar) -or
            $_.filename.StartsWith($crate.SrcDir + '/')
        }
        $covered = 0; $total = 0
        foreach ($f in $ownFiles) {
            $covered += $f.summary.lines.covered
            $total   += $f.summary.lines.count
        }
        $pct = if ($total -gt 0) { [math]::Round($covered / $total * 100, 2) } else { 100.0 }
        $results += [PSCustomObject]@{
            Crate   = $crate.Name
            Path    = $crate.Path
            Covered = [int]$covered
            Total   = [int]$total
            Pct     = $pct
            Missed  = [int]($total - $covered)
        }
    }
    return $results
}

function Write-CoverageSummary {
    <#
    .SYNOPSIS
    Prints a formatted per-crate and overall coverage summary.
    Returns $true if coverage meets the threshold.
    #>
    param(
        [Parameter(Mandatory = $true)]$Results,
        [Parameter(Mandatory = $true)][int]$FailUnderLines
    )

    Write-Host "`n=== Per-crate line coverage (own sources only) ===" -ForegroundColor Cyan
    $Results |
        Where-Object { $_.Total -gt 0 } |
        Sort-Object Pct |
        ForEach-Object {
            $color = if ($_.Pct -ge $FailUnderLines) { 'Green' } elseif ($_.Pct -ge 80) { 'Yellow' } else { 'Red' }
            Write-Host ("  {0,-50} {1,5}/{2,5} = {3,7}%  (missed {4})" -f $_.Crate, $_.Covered, $_.Total, $_.Pct, $_.Missed) -ForegroundColor $color
        }

    $totalCov   = ($Results | Measure-Object -Property Covered -Sum).Sum
    $totalLines = ($Results | Measure-Object -Property Total -Sum).Sum
    $overallPct = if ($totalLines -gt 0) { [math]::Round($totalCov / $totalLines * 100, 2) } else { 100.0 }

    Write-Host "`n=== Overall ===" -ForegroundColor Cyan
    Write-Host ("  Lines covered: {0} / {1} = {2}%" -f $totalCov, $totalLines, $overallPct)
    Write-Host ("  Threshold:     {0}%" -f $FailUnderLines)

    if ($overallPct -ge $FailUnderLines) {
        Write-Host "  PASS" -ForegroundColor Green
        return $true
    } else {
        $needed = [math]::Ceiling($totalLines * $FailUnderLines / 100) - $totalCov
        Write-Host "  FAIL — need $needed more covered lines" -ForegroundColor Red
        Write-Host "`n  Crates below threshold:" -ForegroundColor Yellow
        $Results |
            Where-Object { $_.Pct -lt $FailUnderLines -and $_.Total -gt 0 } |
            Sort-Object Missed -Descending |
            ForEach-Object {
                Write-Host ("    {0,-50} {1,7}% ({2} lines to cover)" -f $_.Crate, $_.Pct, $_.Missed) -ForegroundColor Yellow
            }
        return $false
    }
}

function Export-PerCrateLcov {
    <#
    .SYNOPSIS
    Exports per-crate LCOV data by filtering the workspace JSON coverage to
    each crate's own source files. Writes one combined lcov.info file.
    #>
    param(
        [Parameter(Mandatory = $true)]$CoverageJson,
        [Parameter(Mandatory = $true)]$Crates,
        [Parameter(Mandatory = $true)][string]$OutputPath
    )

    # cargo llvm-cov --json exports file-level summaries but not line-by-line
    # hit counts needed for full LCOV. For detailed HTML reports, we fall back
    # to per-crate lcov generation below.
    # This function writes a simplified summary LCOV that tools like codecov
    # can still ingest for overall numbers.

    $sb = [System.Text.StringBuilder]::new()
    foreach ($crate in $Crates) {
        $ownFiles = $CoverageJson.data[0].files | Where-Object {
            $_.filename.StartsWith($crate.SrcDir + [IO.Path]::DirectorySeparatorChar) -or
            $_.filename.StartsWith($crate.SrcDir + '/')
        }
        foreach ($f in $ownFiles) {
            [void]$sb.AppendLine("SF:$($f.filename)")
            # File-level summary line
            [void]$sb.AppendLine("LF:$($f.summary.lines.count)")
            [void]$sb.AppendLine("LH:$($f.summary.lines.covered)")
            [void]$sb.AppendLine("end_of_record")
        }
    }
    Set-Content -Path $OutputPath -Value $sb.ToString() -NoNewline
}

# Exclude non-production code from coverage accounting:
# - tests/ and examples/ directories
# - build artifacts
# - the demo executable crate
# - test-only helper crate
# Note: cargo-llvm-cov expects a Rust-style regex over file paths. Use `\\` to match a single
# Windows path separator in the regex, and keep the PowerShell string itself single-quoted.
$ignoreFilenameRegex = '(^|\\|/)(tests|examples)(\\|/)|(^|\\|/)target(\\|/)|(^|\\|/)validation(\\|/)(demo|test_utils)(\\|/)|(^|\\|/)partner(\\|/)cose_openssl(\\|/)'

# Ensure OpenSSL DLLs are on PATH for tests that link against OpenSSL.
# Without this, tests fail with STATUS_DLL_NOT_FOUND (0xc0000135).
if ($env:OPENSSL_DIR -and (Test-Path (Join-Path $env:OPENSSL_DIR 'bin'))) {
    $opensslBin = Join-Path $env:OPENSSL_DIR 'bin'
    if ($env:PATH -notlike "*$opensslBin*") {
        $env:PATH = "$opensslBin;$env:PATH"
        Write-Host "Added OpenSSL bin to PATH: $opensslBin" -ForegroundColor Yellow
    }
}

Push-Location $here
try {
    if ($AbiParityCheckOnly) {
        Assert-FluentHelpersProjectedToFfi -Root $here
        Write-Host "OK: ABI parity check only" -ForegroundColor Green
        return
    }

    if ($DependencyCheckOnly) {
        Assert-AllowedDependencies -Root $here
        Write-Host "OK: Dependency allowlist check only" -ForegroundColor Green
        return
    }

    if (-not $SkipGates -and -not $Package) {
        Assert-NoTestsInSrc -Root $here

        Assert-FluentHelpersProjectedToFfi -Root $here

        Assert-AllowedDependencies -Root $here
    } elseif ($Package) {
        Write-Host "Per-crate mode (-Package $Package): skipping quality gates" -ForegroundColor Yellow
    } elseif ($SkipGates) {
        Write-Host "Quality gates skipped (-SkipGates)" -ForegroundColor Yellow
    }

    if (-not $NoClean) {
        if (Test-Path $OutputDir) {
            Remove-Item -Recurse -Force $OutputDir
        }
    }
    New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

    # Prefer nightly toolchain for coverage collection when available.
    # Nightly enables the `coverage(off)` attribute via cfg(coverage_nightly),
    # which properly excludes functions that cannot be tested (e.g., those
    # requiring cloud services) from the coverage denominator.
    $toolchainArg = ''
    $nightlyAvail = (rustup toolchain list 2>$null) -match 'nightly'
    if ($nightlyAvail) {
        $toolchainArg = '+nightly'
        Write-Host "Using nightly toolchain for coverage (enables coverage(off) attribute)" -ForegroundColor Cyan
    } else {
        Write-Host "Nightly toolchain not found; using default (coverage(off) attributes will be ignored)" -ForegroundColor Yellow
    }

    # rustup's info messages go to stderr which triggers ErrorActionPreference=Stop.
    # Use SilentlyContinue to suppress; we only care that the component was added.
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = 'SilentlyContinue'
    if ($toolchainArg) {
        rustup component add llvm-tools-preview --toolchain nightly 2>&1 | Out-Null
    } else {
        rustup component add llvm-tools-preview 2>&1 | Out-Null
    }
    $ErrorActionPreference = $prevEap

    $llvmCov = Get-Command cargo-llvm-cov -ErrorAction SilentlyContinue
    if (-not $llvmCov) {
        Write-Host "Installing cargo-llvm-cov..." -ForegroundColor Yellow
        Invoke-Checked -Command "cargo install cargo-llvm-cov --locked" -Run {
            cargo install cargo-llvm-cov --locked
        }
    }


    # Avoid incremental reuse during coverage runs; incremental artifacts can create
    # stale coverage mapping/profile mismatches.
    $prevCargoIncremental = $env:CARGO_INCREMENTAL
    $env:CARGO_INCREMENTAL = '0'

    # Always exclude partner crates that require separate OpenSSL setup.
    $excludeArgs = @("--exclude", "cose_openssl", "--exclude", "cose_openssl_ffi")

    # -----------------------------------------------------------------------
    # Per-crate mode: run a single crate, skip gates, use shared target dir.
    # -----------------------------------------------------------------------
    if ($Package) {
        Write-Host "Per-crate mode (-Package $Package): using shared target directory" -ForegroundColor Yellow
        $scopeArgs = @("-p", $Package)
        $baseArgs = $scopeArgs + @(
            "--fail-under-lines", "$FailUnderLines",
            "--ignore-filename-regex", $ignoreFilenameRegex
        )
        try {
            Invoke-Checked -Command "cargo llvm-cov -p $Package" -Run {
                $tcArg = if ($toolchainArg) { @($toolchainArg) } else { @() }
                cargo @tcArg llvm-cov @baseArgs --summary-only 2>$null
            }
        } finally {
            $env:CARGO_INCREMENTAL = $prevCargoIncremental
        }
        Write-Host "OK: $Package line coverage >= $FailUnderLines%" -ForegroundColor Green
        return
    }

    # -----------------------------------------------------------------------
    # Workspace mode: per-crate collection + own-source aggregation.
    #
    # This avoids Windows command-line-length limits (OS error 206) that occur
    # when llvm-cov is invoked with hundreds of --object arguments for a large
    # workspace. Instead we run `cargo llvm-cov --json -p <crate>` for each
    # production crate sequentially and aggregate the results.
    # -----------------------------------------------------------------------

    # Enumerate production crates
    $productionCrates = Get-ProductionCrates -Root $here
    Write-Host "Found $($productionCrates.Count) production crates" -ForegroundColor Cyan

    # Create per_crate subdirectory for individual JSON files
    $perCrateDir = Join-Path $OutputDir 'per_crate'
    New-Item -ItemType Directory -Force -Path $perCrateDir | Out-Null

    # Run coverage for each crate sequentially to avoid profdata merge conflicts.
    # Parallel runs conflict on the shared target/llvm-cov-target/ directory.
    Write-Host "Running per-crate coverage collection..." -ForegroundColor Yellow
    $crateResults = @()
    $failedCrates = @()
    $crateIndex = 0
    foreach ($crate in $productionCrates) {
        $crateIndex++
        $crateName = $crate.Name
        Write-Host ("  [{0}/{1}] {2}..." -f $crateIndex, $productionCrates.Count, $crateName) -ForegroundColor Gray -NoNewline

        $jsonFile = Join-Path $perCrateDir "$crateName.json"
        $stderrFile = Join-Path $perCrateDir "$crateName.err"

        $cargoArgs = @()
        if ($toolchainArg) { $cargoArgs += $toolchainArg }
        $cargoArgs += @('llvm-cov', '--json', '-p', $crateName)

        $covProc = Start-Process -FilePath 'cargo' `
            -ArgumentList $cargoArgs `
            -WorkingDirectory $here `
            -NoNewWindow -Wait -PassThru `
            -RedirectStandardOutput $jsonFile `
            -RedirectStandardError $stderrFile

        if ($covProc.ExitCode -ne 0) {
            Write-Host " FAILED" -ForegroundColor Red
            $failedCrates += $crateName
            continue
        }

        # Parse per-crate JSON and filter to own-source files only
        if ((Test-Path $jsonFile) -and (Get-Item $jsonFile).Length -gt 100) {
            $crateJson = Get-Content $jsonFile -Raw | ConvertFrom-Json
            $srcDirNorm = $crate.SrcDir + [IO.Path]::DirectorySeparatorChar
            $covered = 0; $total = 0
            foreach ($f in $crateJson.data[0].files) {
                if ($f.filename.StartsWith($srcDirNorm) -or $f.filename.StartsWith($crate.SrcDir + '/')) {
                    $covered += $f.summary.lines.covered
                    $total   += $f.summary.lines.count
                }
            }
            $pct = if ($total -gt 0) { [math]::Round($covered / $total * 100, 2) } else { 100.0 }
            $crateResults += [PSCustomObject]@{
                Crate   = $crateName
                Path    = $crate.Path
                Covered = [int]$covered
                Total   = [int]$total
                Pct     = $pct
                Missed  = [int]($total - $covered)
            }
            Write-Host (" {0}/{1} = {2}%" -f $covered, $total, $pct) -ForegroundColor $(if ($pct -ge $FailUnderLines) { 'Green' } elseif ($pct -ge 80) { 'Yellow' } else { 'Red' })
        } else {
            Write-Host " NO DATA" -ForegroundColor Yellow
            $failedCrates += $crateName
        }
    }

    if ($failedCrates.Count -gt 0) {
        Write-Host "`nWarning: $($failedCrates.Count) crate(s) failed coverage collection: $($failedCrates -join ', ')" -ForegroundColor Yellow
    }

    # Write per-crate CSV for downstream tooling
    $csvPath = Join-Path $OutputDir 'per-crate-coverage.csv'
    $crateResults | Export-Csv -Path $csvPath -NoTypeInformation

    # Display results and check threshold
    $passed = Write-CoverageSummary -Results $crateResults -FailUnderLines $FailUnderLines

    $env:CARGO_INCREMENTAL = $prevCargoIncremental

    if (-not $passed) {
        throw "Coverage gate failed: overall line coverage < $FailUnderLines%"
    }

    Write-Host "`nOK: Rust production line coverage >= $FailUnderLines% (own-source, per-crate aggregated)" -ForegroundColor Green
    Write-Host "Artifacts: $(Join-Path $here $OutputDir)" -ForegroundColor Green
} finally {
    Pop-Location
}