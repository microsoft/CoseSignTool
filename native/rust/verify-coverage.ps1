# verify-coverage.ps1 — Standalone coverage gate script
# Usage: powershell -File verify-coverage.ps1 [-MinLines 95]
# Exit 0 if coverage >= MinLines%, exit 1 otherwise.
# This script CANNOT be fooled by cfg'd-out tests or stale profraw data.
param([int]$MinLines = 95)

$ErrorActionPreference = 'Stop'
$env:OPENSSL_DIR = 'c:\vcpkg\installed\x64-windows'
$env:PATH = 'c:\vcpkg\installed\x64-windows\bin;' + $env:PATH

# Anti-cheat: check for .disabled test files
Write-Host "Checking for disabled test files..."
$disabled = Get-ChildItem -Recurse -Filter "*.disabled" -Path $PSScriptRoot -ErrorAction SilentlyContinue
if ($disabled.Count -gt 0) {
    Write-Host "FAIL: Found $($disabled.Count) .disabled test files. Agents must not disable tests."
    $disabled | ForEach-Object { Write-Host "  - $($_.FullName -replace '.*native\\rust\\','')" }
    exit 1
}

# Anti-cheat: check for cfg(feature) guards referencing nonexistent features in test files
Write-Host "Checking for bogus cfg(feature) guards in test files..."
$testFiles = Get-ChildItem -Recurse -Filter "*.rs" -Path $PSScriptRoot | Where-Object { $_.DirectoryName -match '\\tests$' }
foreach ($tf in $testFiles) {
    $head = Get-Content $tf.FullName -TotalCount 15
    if ($head -match '#!\[cfg\(feature\s*=\s*"([^"]+)"\)') {
        $feat = $Matches[1]
        $cargoToml = Join-Path (Split-Path (Split-Path $tf.DirectoryName)) "Cargo.toml"
        if (Test-Path $cargoToml) {
            $tomlContent = Get-Content $cargoToml -Raw
            if ($tomlContent -notmatch "\b$feat\b") {
                Write-Host "FAIL: $($tf.Name) has #![cfg(feature = `"$feat`")] but $cargoToml does not define feature '$feat'"
                exit 1
            }
        }
    }
}

Write-Host "=== Coverage Gate: requiring >= $MinLines% line coverage ==="

# Clean any stale profraw data to ensure a fresh measurement
Write-Host "Cleaning stale coverage data..."
$targetDir = Join-Path $PSScriptRoot "target\llvm-cov-target"
if (Test-Path $targetDir) {
    Get-ChildItem -Path $targetDir -Filter "*.profraw" -Recurse -ErrorAction SilentlyContinue | Remove-Item -Force
}

# Run the coverage measurement with JSON output
Write-Host "Running instrumented test suite (this may take 15-30 minutes)..."
$jsonFile = [System.IO.Path]::GetTempFileName()
$errFile  = [System.IO.Path]::GetTempFileName()

$proc = Start-Process -FilePath "cargo" `
    -ArgumentList "+nightly","llvm-cov","test","--workspace","--exclude","cose_openssl","--exclude","cose_openssl_ffi","--ignore-run-fail","--json" `
    -WorkingDirectory $PSScriptRoot `
    -NoNewWindow -Wait -PassThru `
    -RedirectStandardOutput $jsonFile `
    -RedirectStandardError $errFile

if ($proc.ExitCode -ne 0) {
    Write-Host "ERROR: cargo llvm-cov test failed with exit code $($proc.ExitCode)"
    Get-Content $errFile | Select-Object -Last 30
    Remove-Item $jsonFile, $errFile -ErrorAction SilentlyContinue
    exit 1
}

# Parse the JSON output to get TOTAL line coverage
$rawJson = Get-Content $jsonFile -Raw
Remove-Item $jsonFile, $errFile -ErrorAction SilentlyContinue

$coverage = $rawJson | ConvertFrom-Json
$totals = $coverage.data[0].totals
$linesCovered = $totals.lines.covered
$linesTotal   = $totals.lines.count
$linesPct     = [math]::Round($totals.lines.percent, 2)

Write-Host ""
Write-Host "=== Coverage Results ==="
Write-Host "Lines covered: $linesCovered / $linesTotal = $linesPct%"
Write-Host "Threshold:     $MinLines%"
Write-Host ""

if ($linesPct -ge $MinLines) {
    Write-Host "PASS: Coverage $linesPct% >= $MinLines% threshold"
    exit 0
} else {
    $needed = [math]::Ceiling($linesTotal * $MinLines / 100) - $linesCovered
    Write-Host "FAIL: Coverage $linesPct% < $MinLines% threshold"
    Write-Host "      Need $needed more covered lines to pass"
    
    # Show top uncovered files
    Write-Host ""
    Write-Host "Top 10 files by uncovered lines:"
    $coverage.data[0].files |
        Where-Object { $_.filename -notmatch '\\tests\\' -and $_.filename -notmatch 'test_utils' -and $_.summary.lines.count -gt 0 } |
        ForEach-Object {
            $uncov = $_.summary.lines.count - $_.summary.lines.covered
            [PSCustomObject]@{
                File = ($_.filename -replace '.*native\\rust\\','')
                Uncovered = $uncov
                Total = $_.summary.lines.count
                Pct = "$([math]::Round($_.summary.lines.percent, 1))%"
            }
        } |
        Sort-Object Uncovered -Descending |
        Select-Object -First 10 |
        Format-Table -AutoSize |
        Out-String |
        Write-Host
    
    exit 1
}
