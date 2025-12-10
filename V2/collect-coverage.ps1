# Code Coverage Collection Script for V2 Projects
# Target: 95% line coverage across all source files

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  V2 Code Coverage Collection" -ForegroundColor Cyan
Write-Host "  Target: 95% Line Coverage" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

# Clean previous results
Write-Host "Cleaning previous coverage results..." -ForegroundColor Yellow
Remove-Item coverage.cobertura.xml -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force coverage-report -ErrorAction SilentlyContinue

# Build all projects
Write-Host "Building all V2 projects..." -ForegroundColor Yellow
dotnet build --no-incremental
if ($LASTEXITCODE -ne 0) {
    Write-Host "Build failed!" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "Running tests with coverage collection..." -ForegroundColor Yellow
# Collect coverage using dotnet-coverage
dotnet-coverage collect --output coverage.cobertura.xml --output-format cobertura "dotnet test --no-build"

if ($LASTEXITCODE -ne 0) {
    Write-Host "Test execution failed!" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "Generating coverage report..." -ForegroundColor Yellow
# Generate HTML and text summary reports
reportgenerator `
    -reports:coverage.cobertura.xml `
    -targetdir:coverage-report `
    -reporttypes:"Html;TextSummary;Badges" `
    -assemblyfilters:"-*.Tests;-*.Tests.Common" `
    -classfilters:"-System.*;-Microsoft.*" `
    -verbosity:Info

Write-Host ""
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  Coverage Summary" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Get-Content coverage-report\Summary.txt

Write-Host ""
Write-Host "Full coverage report: coverage-report\index.html" -ForegroundColor Green
Write-Host ""

# Extract line coverage percentage
$summary = Get-Content coverage-report\Summary.txt
$lineCoverage = ($summary | Select-String "Line coverage:").ToString() -replace '.*Line coverage:\s*(\d+\.?\d*)%.*', '$1'
$lineCoverageNum = [double]$lineCoverage

Write-Host "Current Line Coverage: $lineCoverageNum%" -ForegroundColor $(if ($lineCoverageNum -ge 95) { "Green" } elseif ($lineCoverageNum -ge 80) { "Yellow" } else { "Red" })
Write-Host "Target Line Coverage: 95%" -ForegroundColor Cyan
Write-Host "Gap: $([math]::Round(95 - $lineCoverageNum, 1))%" -ForegroundColor $(if ($lineCoverageNum -ge 95) { "Green" } else { "Red" })

if ($lineCoverageNum -lt 95) {
    Write-Host ""
    Write-Host "Coverage is below target. Review coverage-report\index.html for details." -ForegroundColor Yellow
    exit 1
} else {
    Write-Host ""
    Write-Host "Coverage target achieved!" -ForegroundColor Green
    exit 0
}
