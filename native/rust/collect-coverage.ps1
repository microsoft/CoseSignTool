param(
    [int]$FailUnderLines = 95,
    [string]$OutputDir = "coverage",
    [switch]$NoHtml,
    [switch]$NoClean
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

# Exclude non-production code from coverage accounting:
# - tests/ and examples/ directories
# - build artifacts
# - the demo executable crate (not production)
# Note: cargo-llvm-cov expects a Rust-style regex over file paths. Use `\\` to match a single
# Windows path separator in the regex, and keep the PowerShell string itself single-quoted.
$ignoreFilenameRegex = '(^|\\|/)(tests|examples)(\\|/)|(^|\\|/)target(\\|/)|(^|\\|/)cose_sign1_validation_demo(\\|/)'

Push-Location $here
try {
    Assert-NoTestsInSrc -Root $here

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