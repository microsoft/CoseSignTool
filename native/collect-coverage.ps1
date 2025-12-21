# Native C++ Code Coverage Collection Script
# Target: 95% line coverage across native libraries

param(
  # Which native projects to run coverage for. Default is all.
  # Example: .\native\collect-coverage.ps1 -Projects cosesign1-x509
  [Parameter(Mandatory=$false)]
  [ValidateSet('cosesign1-common', 'cosesign1-validation','cosesign1-x509','cosesign1-mst')]
  [string[]]$Projects = @('cosesign1-common','cosesign1-validation','cosesign1-x509','cosesign1-mst')
)

Set-Location $PSScriptRoot

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  Native Code Coverage Collection" -ForegroundColor Cyan
Write-Host "  Target: 95% Line Coverage" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

$openCppCoverage = "C:\Program Files\OpenCppCoverage\OpenCppCoverage.exe"
if (-not (Test-Path $openCppCoverage)) {
  Write-Host "OpenCppCoverage not found at: $openCppCoverage" -ForegroundColor Red
  Write-Host "Install it with: winget install --id OpenCppCoverage.OpenCppCoverage -e" -ForegroundColor Yellow
  exit 1
}

# Clean previous results
Write-Host "Cleaning previous coverage results..." -ForegroundColor Yellow
Remove-Item -Force "coverage.cobertura.xml" -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force "coverage-report" -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force "coverage-report" | Out-Null

$cmakeDir = "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin"
$cmake = Join-Path $cmakeDir "cmake.exe"
$ctest = Join-Path $cmakeDir "ctest.exe"

if (-not (Test-Path $cmake)) {
  Write-Host "CMake not found at: $cmake" -ForegroundColor Red
  exit 1
}

$env:VCPKG_ROOT = "C:\vcpkg"
$env:VCPKG_OVERLAY_PORTS = (Join-Path $PSScriptRoot "vcpkg-ports")
$env:VCPKG_VISUAL_STUDIO_PATH = "C:\Program Files\Microsoft Visual Studio\2022\Enterprise"
$env:VCPKG_PLATFORM_TOOLSET = "v143"

function Get-CoberturaFileCoverage {
  param(
    [Parameter(Mandatory=$true)][string]$CoberturaPath
  )

  if (-not (Test-Path $CoberturaPath)) {
    throw "Cobertura file not found: $CoberturaPath"
  }

  [xml]$xml = Get-Content -Path $CoberturaPath
  $files = @()

  $packages = @()
  if ($xml.coverage.packages -and $xml.coverage.packages.package) {
    $packages = @($xml.coverage.packages.package)
  }

  foreach ($pkg in $packages) {
    $pkgName = [string]$pkg.name
    $classes = @()
    if ($pkg.classes -and $pkg.classes.class) {
      $classes = @($pkg.classes.class)
    }

    foreach ($cls in $classes) {
      $filename = [string]$cls.filename
      if ([string]::IsNullOrWhiteSpace($filename)) {
        continue
      }

      $total = 0
      $covered = 0

      $lines = @()
      if ($cls.lines -and $cls.lines.line) {
        $lines = @($cls.lines.line)
      }

      foreach ($ln in $lines) {
        $total++
        $hits = 0
        try { $hits = [int]$ln.hits } catch { $hits = 0 }
        if ($hits -gt 0) { $covered++ }
      }

      if ($total -eq 0) {
        continue
      }

      $pct = [math]::Round(($covered * 100.0) / $total, 2)
      $files += [pscustomobject]@{
        Package = $pkgName
        File = $filename
        Covered = $covered
        Total = $total
        Percent = $pct
      }
    }
  }

  return $files
}

function Write-CoverageDetails {
  param(
    [Parameter(Mandatory=$true)][string]$ProjectName,
    [Parameter(Mandatory=$true)][string]$CoberturaPath
  )

  $files = Get-CoberturaFileCoverage -CoberturaPath $CoberturaPath
  if (-not $files -or $files.Count -eq 0) {
    Write-Host "No per-file coverage entries found in: $CoberturaPath" -ForegroundColor Yellow
    return [pscustomobject]@{ Covered = 0; Total = 0; Percent = 0.0 }
  }

  $totCovered = ($files | Measure-Object -Property Covered -Sum).Sum
  $totTotal = ($files | Measure-Object -Property Total -Sum).Sum
  $totPct = if ($totTotal -gt 0) { [math]::Round(($totCovered * 100.0) / $totTotal, 2) } else { 0.0 }

  Write-Host "" 
  Write-Host "================================================" -ForegroundColor Cyan
  Write-Host "  $ProjectName Coverage Details" -ForegroundColor Cyan
  Write-Host "================================================" -ForegroundColor Cyan
  Write-Host "Cobertura: $CoberturaPath" -ForegroundColor DarkGray

  $pkgGroups = $files | Group-Object Package | Sort-Object Name
  foreach ($g in $pkgGroups) {
    $pkgCovered = ($g.Group | Measure-Object -Property Covered -Sum).Sum
    $pkgTotal = ($g.Group | Measure-Object -Property Total -Sum).Sum
    $pkgPct = if ($pkgTotal -gt 0) { [math]::Round(($pkgCovered * 100.0) / $pkgTotal, 2) } else { 0.0 }
    Write-Host ("Package: {0}  {1}/{2}  {3}%" -f $g.Name, $pkgCovered, $pkgTotal, $pkgPct) -ForegroundColor Cyan

    $g.Group | Sort-Object Percent, File | ForEach-Object {
      $color = if ($_.Percent -ge 95) { "Green" } elseif ($_.Percent -ge 80) { "Yellow" } else { "Red" }
      Write-Host ("  {0}%  ({1}/{2})  {3}" -f $_.Percent, $_.Covered, $_.Total, $_.File) -ForegroundColor $color
    }
  }

  Write-Host "" 
  Write-Host ("Project Total: {0}/{1}  {2}%" -f $totCovered, $totTotal, $totPct) -ForegroundColor Cyan
  return [pscustomobject]@{ Covered = $totCovered; Total = $totTotal; Percent = $totPct }
}

function Invoke-CoveredCtest {
  param(
    [Parameter(Mandatory=$true)][string]$ProjectDir,
    [Parameter(Mandatory=$true)][string]$BuildDir,
    [Parameter(Mandatory=$true)][string]$ProjectName
  )

  $config = "RelWithDebInfo"

  Write-Host "" 
  Write-Host "==> Configuring $ProjectName" -ForegroundColor Yellow
  & $cmake -S $ProjectDir -B $BuildDir -G "Visual Studio 17 2022" -A x64 `
    -DCMAKE_TOOLCHAIN_FILE="$env:VCPKG_ROOT\scripts\buildsystems\vcpkg.cmake" `
    -DVCPKG_TARGET_TRIPLET=x64-windows `
    -DVCPKG_MANIFEST_MODE=ON | Out-Host
  if ($LASTEXITCODE -ne 0) { throw "Configure failed for $ProjectName" }

  Write-Host "==> Building $ProjectName ($config)" -ForegroundColor Yellow
  & $cmake --build $BuildDir --config $config -- /m | Out-Host
  if ($LASTEXITCODE -ne 0) { throw "Build failed for $ProjectName" }

  Write-Host "==> Running $ProjectName tests with coverage" -ForegroundColor Yellow

  $projectLeaf = Split-Path -Path $ProjectDir -Leaf
  $projectSources = "*CoseSignTool*native*$projectLeaf*"

  $outCobertura = Join-Path $PSScriptRoot "coverage-report\$ProjectName.cobertura.xml"

  # Use OpenCppCoverage to run ctest. Export Cobertura for later aggregation.
  & $openCppCoverage `
    --quiet `
    --cover_children `
    --optimized_build `
    --export_type cobertura:"$outCobertura" `
    --working_dir "$BuildDir" `
    --sources "$projectSources" `
    --modules "*out*build*coverage*" `
    --excluded_sources "*out*build*" `
    --excluded_sources "*vcpkg_installed*" `
    --excluded_sources "*tests*" `
    -- `
    $ctest --test-dir "$BuildDir" -C $config --output-on-failure | Out-Host

  $testExitCode = $LASTEXITCODE
  if ($testExitCode -ne 0) {
    throw "$ProjectName tests failed (exit $testExitCode)"
  }

  if (-not (Test-Path $outCobertura)) {
    throw "Coverage output missing: $outCobertura"
  }

  return [string]$outCobertura
}

try {
  if (-not $Projects -or $Projects.Count -eq 0) {
    throw "No projects specified. Valid values: cosesign1-common cosesign1-validation, cosesign1-x509, cosesign1-mst."
  }

  $results = @()
  foreach ($p in $Projects) {
    $cobertura = Invoke-CoveredCtest -ProjectDir (Join-Path $PSScriptRoot $p) -BuildDir (Join-Path $PSScriptRoot "$p\out\build\coverage") -ProjectName $p
    $summary = Write-CoverageDetails -ProjectName $p -CoberturaPath $cobertura
    $results += $summary
  }

  $minPct = ($results.Percent | Measure-Object -Minimum).Minimum

  Write-Host "" 
  Write-Host "================================================" -ForegroundColor Cyan
  Write-Host "  Coverage Summary (min across projects)" -ForegroundColor Cyan
  Write-Host "================================================" -ForegroundColor Cyan
  Write-Host "Min Line Coverage (computed): $minPct%" -ForegroundColor $(if ($minPct -ge 95) { "Green" } elseif ($minPct -ge 80) { "Yellow" } else { "Red" })
  Write-Host "Target Line Coverage: 95%" -ForegroundColor Cyan

  if ($minPct -lt 95) {
    Write-Host "Coverage is below target. See coverage-report/*.cobertura.xml" -ForegroundColor Yellow
    exit 1
  }

  Write-Host "Coverage target achieved!" -ForegroundColor Green
  exit 0
}
catch {
  Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
  exit 1
}
