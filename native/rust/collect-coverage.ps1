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


    if (-not $NoClean) {
        Write-Host "Cleaning cargo-llvm-cov artifacts..." -ForegroundColor Yellow
        Invoke-Checked -Command "cargo llvm-cov clean" -Run {
            cargo llvm-cov clean --workspace
        }
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

    try {
        if (-not $NoHtml) {
            Invoke-Checked -Command "cargo llvm-cov (html report)" -Run {
                cargo llvm-cov @baseArgs --html --output-dir $OutputDir
            }
        }

        Invoke-Checked -Command "cargo llvm-cov (lcov report)" -Run {
            cargo llvm-cov @baseArgs --lcov --output-path (Join-Path $OutputDir "lcov.info")
        }
    } catch {
        Write-Host "Coverage gate failed; current production-code summary:" -ForegroundColor Yellow
        & cargo llvm-cov @summaryArgs | Out-Host
        throw
    }

    Write-Host "OK: Rust production line coverage >= $FailUnderLines%" -ForegroundColor Green
    Write-Host "Artifacts: $(Join-Path $here $OutputDir)" -ForegroundColor Green
} finally {
    Pop-Location
}