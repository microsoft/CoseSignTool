param(
    [int]$FailUnderLines = 95,
    [string]$OutputDir = "coverage",
    [switch]$NoHtml,
    [switch]$NoClean,
    [switch]$AbiParityCheckOnly
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
            $_.FullName -notmatch '(\\|/)tests(\\|/)'
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
        (Join-Path $Root 'cose_sign1_validation\src\message_facts.rs'),
        (Join-Path $Root 'cose_sign1_validation_certificates\src\fluent_ext.rs'),
        (Join-Path $Root 'cose_sign1_validation_transparent_mst\src\fluent_ext.rs'),
        (Join-Path $Root 'cose_sign1_validation_azure_key_vault\src\fluent_ext.rs')
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
            $_.FullName -match '(\\|/)cose_sign1_validation_ffi' -and
            $_.FullName -match '(\\|/)src(\\|/)' -and
            $_.FullName -notmatch '(\\|/)target(\\|/)'
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
        Write-Host "The following Rust fluent helpers exist but are not referenced by any Rust FFI projection (native/rust/cose_sign1_validation_ffi*/src/lib.rs):" -ForegroundColor Red
        $missing |
            Select-Object -First 50 |
            ForEach-Object { Write-Host ("  - {0}" -f $_) -ForegroundColor Red }

        Write-Host "\nFix: add/extend the appropriate pack FFI export(s) so native projections can access the new helper." -ForegroundColor Yellow
        Write-Host "If a helper is intentionally Rust-only (requires callbacks), add it to the exclusion list in collect-coverage.ps1." -ForegroundColor Yellow
        throw "ABI parity gate failed. Missing projections for $($missing.Count) helper(s)."
    }

    Write-Host "OK: ABI parity gate passed (Rust fluent helpers are referenced by FFI projections)." -ForegroundColor Green
}

# Exclude non-production code from coverage accounting:
# - tests/ and examples/ directories
# - build artifacts
# - the demo executable crate
# - test-only helper crate
# Note: cargo-llvm-cov expects a Rust-style regex over file paths. Use `\\` to match a single
# Windows path separator in the regex, and keep the PowerShell string itself single-quoted.
$ignoreFilenameRegex = '(^|\\|/)(tests|examples)(\\|/)|(^|\\|/)target(\\|/)|(^|\\|/)cose_sign1_validation_(demo|test_utils)(\\|/)'

Push-Location $here
try {
    if ($AbiParityCheckOnly) {
        Assert-FluentHelpersProjectedToFfi -Root $here
        Write-Host "OK: ABI parity check only" -ForegroundColor Green
        return
    }

    Assert-NoTestsInSrc -Root $here

    Assert-FluentHelpersProjectedToFfi -Root $here

    if (-not $NoClean) {
        if (Test-Path $OutputDir) {
            Remove-Item -Recurse -Force $OutputDir
        }
    }
    New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

    Invoke-Checked -Command "rustup component add llvm-tools-preview" -Run {
        rustup component add llvm-tools-preview
    }

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

    # Use a unique per-run target/build directory for cargo-llvm-cov so we never reuse stale
    # compiled objects/profile data. This avoids the common Windows issue where attempts
    # to clean/delete the shared llvm-cov build directory can fail due to transient file locks.
    $prevLlvmCovTargetDir = $env:CARGO_LLVM_COV_TARGET_DIR
    $prevLlvmCovBuildDir = $env:CARGO_LLVM_COV_BUILD_DIR
    $prevLlvmProfileFile = $env:LLVM_PROFILE_FILE
    $prevCargoTargetDir = $env:CARGO_TARGET_DIR
    $llvmCovWorkDir = $null
    if (-not $NoClean) {
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
    }

    $baseArgs = @(
        "--workspace",
        "--fail-under-lines", "$FailUnderLines",
        "--ignore-filename-regex", $ignoreFilenameRegex
    )

    $summaryArgs = @(
        "--workspace",
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
            cargo llvm-cov @baseArgs --no-report --quiet
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