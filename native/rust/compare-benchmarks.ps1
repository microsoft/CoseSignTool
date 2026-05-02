# Compare current benchmark results against a baseline
# Usage: ./compare-benchmarks.ps1 [-Threshold 10] [-FailOnRegression]
param(
    [int]$Threshold = 10,     # Percentage threshold for regression warning
    [switch]$FailOnRegression # Exit with error if regression detected
)

$env:OPENSSL_DIR = if ($env:VCPKG_ROOT) { "$env:VCPKG_ROOT\installed\x64-windows" } else { "c:\vcpkg\installed\x64-windows" }
$env:PATH = "$env:OPENSSL_DIR\bin;$env:PATH"

Write-Host "Running benchmarks..." -ForegroundColor Cyan
$output = cargo bench -p cose_benchmarks --bench cose_benchmarks 2>&1
$output | Out-File -FilePath benchmark-results.txt -Encoding utf8

# Check for regressions
$regressions = $output | Select-String "regressed"
$improvements = $output | Select-String "improved"

Write-Host "`n=== Benchmark Summary ===" -ForegroundColor Cyan

if ($improvements) {
    Write-Host "`nImprovements:" -ForegroundColor Green
    $improvements | ForEach-Object { Write-Host "  $($_.Line.Trim())" -ForegroundColor Green }
}

if ($regressions) {
    Write-Host "`nRegressions:" -ForegroundColor Yellow
    $regressions | ForEach-Object { Write-Host "  $($_.Line.Trim())" -ForegroundColor Yellow }

    if ($FailOnRegression) {
        Write-Host "`nFAILED: Performance regressions detected." -ForegroundColor Red
        exit 1
    } else {
        Write-Host "`nWARNING: Regressions detected but -FailOnRegression not set." -ForegroundColor Yellow
    }
} else {
    Write-Host "`nNo regressions detected." -ForegroundColor Green
}

# Count benchmarks
$benchCount = ($output | Select-String "time:.*\[").Count
Write-Host "`nTotal benchmarks: $benchCount" -ForegroundColor Cyan