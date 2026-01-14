# Code Coverage Collection Script for V2 Projects
# Target: 95% line coverage across all source files
#
# Usage:
#   .\collect-coverage.ps1                    # Run all tests
#   .\collect-coverage.ps1 -ProjectFilter "CoseSign1.Certificates"  # Run tests for specific project
#   .\collect-coverage.ps1 -ProjectFilter "CoseSign1.Validation"    # Run tests for specific project
#   .\collect-coverage.ps1 -SkipBuild         # Skip build step (use with -ProjectFilter for parallel runs)

param(
    [string]$ProjectFilter = "",
    [switch]$SkipBuild = $false,
    [switch]$SkipClean = $false,
    [switch]$IncludeSubAssemblies = $false
)

# Ensure relative paths resolve from the V2 directory (script location)
Set-Location $PSScriptRoot

function Get-ScopeName {
    param([string]$Filter)

    if ([string]::IsNullOrWhiteSpace($Filter)) {
        return "All Projects"
    }

    # Prefer leaf name if a relative/absolute path is provided.
    $leaf = Split-Path -Path $Filter -Leaf
    if (-not [string]::IsNullOrWhiteSpace($leaf)) {
        return $leaf
    }

    return $Filter
}

function Resolve-AssemblyNameForFilter {
    param([string]$Filter)

    if ([string]::IsNullOrWhiteSpace($Filter)) {
        return ""
    }

    $name = $Filter

    # If a csproj was specified, derive from file name.
    if ($name -like "*.csproj") {
        $name = [System.IO.Path]::GetFileNameWithoutExtension($name)
    }

    # If a test project is specified, derive the product assembly name.
    if ($name -like "*.Tests") {
        $name = $name.Substring(0, $name.Length - ".Tests".Length)
    }

    return $name
}

function Resolve-TestProjects {
    param([string]$Filter)

    # Exact csproj path or file name.
    if ($Filter -like "*.csproj") {
        if (Test-Path $Filter) {
            return @(Get-Item -Path $Filter)
        }

        # Try relative to repo root (script folder) if a relative path was provided.
        $candidate = Join-Path $PSScriptRoot $Filter
        if (Test-Path $candidate) {
            return @(Get-Item -Path $candidate)
        }

        # Try exact file name match anywhere under V2.
        $byName = @(Get-ChildItem -Path . -Recurse -File -Filter ([System.IO.Path]::GetFileName($Filter)))
        return $byName
    }

    $allTests = @(Get-ChildItem -Path . -Recurse -File -Filter "*.Tests.csproj")

    # Prefer an exact match: <Filter>.Tests or <Filter> (if user passed the full test project name).
    $candidates = @($Filter)
    if ($Filter -notlike "*.Tests") {
        $candidates += "$Filter.Tests"
    }

    $exact = @($allTests | Where-Object { $candidates -contains $_.BaseName })
    if ($exact.Count -gt 0) {
        return $exact
    }

    # Back-compat fallback: directory-name contains filter.
    return @($allTests | Where-Object { $_.Directory.Name -like "*$Filter*" })
}

$projectDisplay = Get-ScopeName $ProjectFilter

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  V2 Code Coverage Collection" -ForegroundColor Cyan
Write-Host "  Target: 95% Line Coverage" -ForegroundColor Cyan
Write-Host "  Scope: $projectDisplay" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

# Determine results directory - use subfolder when filtering by project
if ($ProjectFilter) {
    $scopeFolder = Get-ScopeName $ProjectFilter
    $resultsDir = "TestResults\$scopeFolder"
    $reportDir = "coverage-report\$scopeFolder"
} else {
    $resultsDir = "TestResults"
    $reportDir = "coverage-report"
}

# File-based lock for serializing clean/build phase across parallel runs
$lockFile = Join-Path $PSScriptRoot ".build.lock"
$lockAcquired = $false
$lockStream = $null

function Acquire-BuildLock {
    param([int]$TimeoutSeconds = 300)
    
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $waitLogged = $false
    
    while ($stopwatch.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
        try {
            $script:lockStream = [System.IO.File]::Open($lockFile, [System.IO.FileMode]::OpenOrCreate, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
            $script:lockAcquired = $true
            if ($waitLogged) {
                Write-Host "  Lock acquired after $([math]::Round($stopwatch.Elapsed.TotalSeconds, 1))s" -ForegroundColor Gray
            }
            return $true
        }
        catch {
            if (-not $waitLogged) {
                Write-Host "  Waiting for build lock (another build in progress)..." -ForegroundColor Yellow
                $waitLogged = $true
            }
            Start-Sleep -Milliseconds 500
        }
    }
    
    Write-Host "Failed to acquire build lock after $TimeoutSeconds seconds" -ForegroundColor Red
    return $false
}

function Release-BuildLock {
    if ($script:lockStream) {
        $script:lockStream.Close()
        $script:lockStream = $null
        $script:lockAcquired = $false
    }
}

# Register cleanup to release lock on script exit/termination
$null = Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action { Release-BuildLock }
trap { Release-BuildLock; break }

# Acquire lock before clean/build phase (only when using ProjectFilter for parallel safety)
$needsLock = $ProjectFilter -and (-not $SkipBuild -or -not $SkipClean)
if ($needsLock) {
    Write-Host "Acquiring build lock for parallel safety..." -ForegroundColor Gray
    if (-not (Acquire-BuildLock)) {
        exit 1
    }
}

try {
    # Clean previous results (only for this project's scope)
    if (-not $SkipClean) {
        Write-Host "Cleaning previous coverage results for $projectDisplay..." -ForegroundColor Yellow
        if ($ProjectFilter) {
            Remove-Item -Recurse -Force $resultsDir -ErrorAction SilentlyContinue
            Remove-Item -Recurse -Force $reportDir -ErrorAction SilentlyContinue
        } else {
            Remove-Item coverage.cobertura.xml -ErrorAction SilentlyContinue
            Remove-Item -Recurse -Force coverage-report -ErrorAction SilentlyContinue
            Remove-Item -Recurse -Force TestResults -ErrorAction SilentlyContinue
        }
    }

    # Build projects (skip if already built for parallel runs)
    if (-not $SkipBuild) {
        if ($ProjectFilter) {
            # Find and build only the test project(s) for this filter (builds dependencies automatically)
            $testProjects = Resolve-TestProjects $ProjectFilter
            
            if ($testProjects.Count -eq 0) {
                Write-Host "No test projects found matching filter: $ProjectFilter" -ForegroundColor Red
                exit 1
            }
            
            Write-Host "Building test project(s) for $ProjectFilter..." -ForegroundColor Yellow
            foreach ($proj in $testProjects) {
                Write-Host "  Building $($proj.BaseName)..." -ForegroundColor Gray
                dotnet build $proj.FullName --no-incremental
                if ($LASTEXITCODE -ne 0) {
                    Write-Host "Build failed for $($proj.Name)!" -ForegroundColor Red
                    exit 1
                }
            }
        } else {
            Write-Host "Building all V2 projects..." -ForegroundColor Yellow
            dotnet build --no-incremental
            if ($LASTEXITCODE -ne 0) {
                Write-Host "Build failed!" -ForegroundColor Red
                exit 1
            }
        }
    } else {
        Write-Host "Skipping build (using existing build)..." -ForegroundColor Yellow
    }
}
finally {
    # Release lock after build phase - tests can run in parallel
    if ($needsLock) {
        Write-Host "Releasing build lock (tests can run in parallel)..." -ForegroundColor Gray
        Release-BuildLock
    }
}

Write-Host ""
Write-Host "Running tests with coverage collection..." -ForegroundColor Yellow
# Collect coverage using XPlat Code Coverage (coverlet collector).

# Ensure results directory exists
New-Item -ItemType Directory -Path $resultsDir -Force | Out-Null

if ($ProjectFilter) {
    # Find test projects matching the filter (may already be found during build)
    $testProjects = Resolve-TestProjects $ProjectFilter
    
    if ($testProjects.Count -eq 0) {
        Write-Host "No test projects found matching filter: $ProjectFilter" -ForegroundColor Red
        exit 1
    }
    
    Write-Host "Running tests for: $($testProjects.BaseName -join ', ')" -ForegroundColor Yellow
    foreach ($proj in $testProjects) {
        Write-Host "  Testing $($proj.BaseName)..." -ForegroundColor Gray
        dotnet test $proj.FullName --no-build --settings coverage.runsettings --collect:"XPlat Code Coverage" --results-directory $resultsDir
    }
} else {
    dotnet test CoseSignToolV2.sln --no-build --settings coverage.runsettings --collect:"XPlat Code Coverage" --results-directory $resultsDir
}

# Continue even if tests fail to generate coverage report
$testExitCode = $LASTEXITCODE

Write-Host ""
Write-Host "Generating coverage report..." -ForegroundColor Yellow

# Ensure reportgenerator is available (prefer a repo-local tool install).
$reportGeneratorCmd = Get-Command reportgenerator -ErrorAction SilentlyContinue
if (-not $reportGeneratorCmd) {
    $toolPath = Join-Path $PSScriptRoot ".tools"
    $reportGeneratorExe = Join-Path $toolPath "reportgenerator.exe"
    if (-not (Test-Path $reportGeneratorExe)) {
        Write-Host "reportgenerator not found; installing to $toolPath..." -ForegroundColor Yellow
        New-Item -ItemType Directory -Path $toolPath -Force | Out-Null
        dotnet tool install dotnet-reportgenerator-globaltool --tool-path $toolPath
        if ($LASTEXITCODE -ne 0) {
            Write-Host "Failed to install reportgenerator tool." -ForegroundColor Red
            exit 1
        }
    }
    $reportGeneratorCmd = Get-Command $reportGeneratorExe -ErrorAction SilentlyContinue
    if (-not $reportGeneratorCmd) {
        Write-Host "reportgenerator is still not available after install." -ForegroundColor Red
        exit 1
    }
}

# Ensure report directory exists
New-Item -ItemType Directory -Path $reportDir -Force | Out-Null

# Generate HTML and text summary reports
# Classes requiring external services/dependencies use [ExcludeFromCodeCoverage] attribute
# When filtering by project, include only that project's assembly by default.
# Use -IncludeSubAssemblies to include sibling assemblies with the same prefix.
$assemblyName = Resolve-AssemblyNameForFilter $ProjectFilter
$assemblyFilter = ""
if ($assemblyName) {
    $assemblyFilter = "+$assemblyName"
    if ($IncludeSubAssemblies) {
        $assemblyFilter += ";+$assemblyName.*"
    }
}

$reportGenArgs = @(
    "-reports:$resultsDir/**/coverage.cobertura.xml",
    "-targetdir:$reportDir",
    "-reporttypes:Html;TextSummary;Badges;Cobertura",
    "-verbosity:Info"
)

if ($assemblyFilter) {
    $reportGenArgs += "-assemblyfilters:$assemblyFilter"
}

& $reportGeneratorCmd.Path @reportGenArgs

# Copy merged Cobertura output to the expected location (only for full runs)
if (-not $ProjectFilter) {
    if (Test-Path "$reportDir\Cobertura.xml") {
        Copy-Item "$reportDir\Cobertura.xml" "coverage.cobertura.xml" -Force
    }
}

Write-Host ""
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  Coverage Summary - $projectDisplay" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan

if (Test-Path "$reportDir\Summary.txt") {
    Get-Content "$reportDir\Summary.txt"
} else {
    Write-Host "No coverage data found in $reportDir" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "Full coverage report: $reportDir\index.html" -ForegroundColor Green
Write-Host ""

# Extract line coverage percentage
$summary = Get-Content "$reportDir\Summary.txt"
$lineCoverage = ($summary | Select-String "Line coverage:").ToString() -replace '.*Line coverage:\s*(\d+\.?\d*)%.*', '$1'
$lineCoverageNum = [double]$lineCoverage

Write-Host "Current Line Coverage: $lineCoverageNum%" -ForegroundColor $(if ($lineCoverageNum -ge 95) { "Green" } elseif ($lineCoverageNum -ge 80) { "Yellow" } else { "Red" })
Write-Host "Target Line Coverage: 95%" -ForegroundColor Cyan
Write-Host "Gap: $([math]::Round(95 - $lineCoverageNum, 1))%" -ForegroundColor $(if ($lineCoverageNum -ge 95) { "Green" } else { "Red" })

if ($lineCoverageNum -lt 95) {
    Write-Host ""
    Write-Host "Coverage is below target. Review coverage-report\index.html for details." -ForegroundColor Yellow
    if ($testExitCode -ne 0) {
        Write-Host "Note: Some tests failed during execution." -ForegroundColor Yellow
    }
    exit 1
} else {
    Write-Host ""
    Write-Host "Coverage target achieved!" -ForegroundColor Green
    if ($testExitCode -ne 0) {
        Write-Host "Warning: Coverage target met but some tests failed." -ForegroundColor Yellow
        exit 1
    }
    exit 0
}
