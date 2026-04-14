# Run BenchmarkDotNet suite and generate reports
param(
    [string]$Filter = "*",
    [switch]$ExportJson
)

$exportArgs = if ($ExportJson) { "--exporters", "json" } else { @() }

dotnet run -c Release --project CoseSign1.Benchmarks -- --filter $Filter @exportArgs

if ($LASTEXITCODE -eq 0) {
    Write-Host "`nResults saved to: BenchmarkDotNet.Artifacts/" -ForegroundColor Green
    if (Test-Path "BenchmarkDotNet.Artifacts/results") {
        Get-ChildItem "BenchmarkDotNet.Artifacts/results" -Filter "*.md" | ForEach-Object {
            Write-Host "`n=== $($_.Name) ===" -ForegroundColor Cyan
            Get-Content $_.FullName
        }
    }
}
