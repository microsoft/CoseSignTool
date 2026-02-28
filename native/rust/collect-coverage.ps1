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
    [switch]$SkipGates
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

    # rustup's info messages go to stderr which triggers ErrorActionPreference=Stop.
    # Use SilentlyContinue to suppress; we only care that the component was added.
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = 'SilentlyContinue'
    rustup component add llvm-tools-preview 2>&1 | Out-Null
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

    # Per-crate mode uses shared target dir (no per-run isolation) because
    # cargo-llvm-cov's profraw file placement depends on the default llvm-cov-target dir.
    # Workspace mode uses per-run isolation to avoid stale profile data.
    $prevLlvmCovTargetDir = $env:CARGO_LLVM_COV_TARGET_DIR
    $prevLlvmCovBuildDir = $env:CARGO_LLVM_COV_BUILD_DIR
    $prevLlvmProfileFile = $env:LLVM_PROFILE_FILE
    $prevCargoTargetDir = $env:CARGO_TARGET_DIR
    $llvmCovWorkDir = $null
    if (-not $NoClean -and -not $Package) {
        $stamp = (Get-Date -Format 'yyyyMMdd-HHmmss')
        $llvmCovWorkDir = Join-Path $here ("target\\llvm-cov-work\\run-{0}-{1}" -f $stamp, $PID)
        $cargoTargetDir = Join-Path $llvmCovWorkDir 'cargo-target'
        New-Item -ItemType Directory -Force -Path $cargoTargetDir | Out-Null

        # Ensure cargo and cargo-llvm-cov both write artifacts into the per-run directory.
        $env:CARGO_TARGET_DIR = $cargoTargetDir
        $env:CARGO_LLVM_COV_TARGET_DIR = $cargoTargetDir
        $env:CARGO_LLVM_COV_BUILD_DIR = $cargoTargetDir
        $env:LLVM_PROFILE_FILE = (Join-Path $cargoTargetDir 'rust-%p-%m.profraw')

        Write-Host "Using cargo-llvm-cov work dir: $llvmCovWorkDir" -ForegroundColor Yellow
        Write-Host "Using CARGO_TARGET_DIR: $cargoTargetDir" -ForegroundColor Yellow
    } elseif ($Package) {
        Write-Host "Per-crate mode: using shared target directory" -ForegroundColor Yellow
    }

    # Build scope args: per-crate (-p) or workspace
    # Always exclude partner crates that require separate OpenSSL setup.
    $excludeArgs = @("--exclude", "cose_openssl", "--exclude", "cose_openssl_ffi")
    $scopeArgs = if ($Package) {
        @("-p", $Package)
    } else {
        @("--workspace") + $excludeArgs
    }

    $baseArgs = $scopeArgs + @(
        "--fail-under-lines", "$FailUnderLines",
        "--ignore-filename-regex", $ignoreFilenameRegex
    )

    $summaryArgs = $scopeArgs + @(
        "--ignore-filename-regex", $ignoreFilenameRegex,
        "--summary-only"
    )

    $reportArgs = @(
        "--ignore-filename-regex", $ignoreFilenameRegex,
        "--fail-under-lines", "$FailUnderLines"
    )

    $summaryReportArgs = @(
        "--ignore-filename-regex", $ignoreFilenameRegex,
        "--summary-only"
    )

    try {
        # Run tests once to produce profiling data, then generate multiple report formats from
        # the same merged profile to avoid stale/mixed-profile "mismatched data" warnings.
        Invoke-Checked -Command "cargo llvm-cov (run tests)" -Run {
            cargo llvm-cov @baseArgs --no-report --quiet 2>$null
        }

        if (-not $NoHtml) {
            Invoke-Checked -Command "cargo llvm-cov report (html)" -Run {
                $prevEap = $ErrorActionPreference
                $ErrorActionPreference = 'Continue'
                try {
                    cargo llvm-cov report @reportArgs --html --output-dir $OutputDir *>&1 | Remove-LlvmCovNoise
                } finally {
                    $ErrorActionPreference = $prevEap
                }
            }
        }

        Invoke-Checked -Command "cargo llvm-cov report (lcov)" -Run {
            $prevEap = $ErrorActionPreference
            $ErrorActionPreference = 'Continue'
            try {
                cargo llvm-cov report @reportArgs --lcov --output-path (Join-Path $OutputDir "lcov.info") *>&1 | Remove-LlvmCovNoise
            } finally {
                $ErrorActionPreference = $prevEap
            }
        }
    } catch {
        Write-Host "Coverage gate failed; current production-code summary:" -ForegroundColor Yellow
        try {
            $prevEap = $ErrorActionPreference
            $ErrorActionPreference = 'Continue'
            try {
                & cargo llvm-cov report --lcov @summaryReportArgs *>&1 | Remove-LlvmCovNoise | Out-Host
            } finally {
                $ErrorActionPreference = $prevEap
            }
        } catch {
            & cargo llvm-cov @summaryArgs | Out-Host
        }
        throw
    } finally {
        $env:CARGO_INCREMENTAL = $prevCargoIncremental
        $env:CARGO_LLVM_COV_TARGET_DIR = $prevLlvmCovTargetDir
        $env:CARGO_LLVM_COV_BUILD_DIR = $prevLlvmCovBuildDir
        $env:LLVM_PROFILE_FILE = $prevLlvmProfileFile
        $env:CARGO_TARGET_DIR = $prevCargoTargetDir
    }

    Write-Host "OK: Rust production line coverage >= $FailUnderLines%" -ForegroundColor Green
    Write-Host "Artifacts: $(Join-Path $here $OutputDir)" -ForegroundColor Green
} finally {
    Pop-Location
}