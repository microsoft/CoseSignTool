[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release', 'RelWithDebInfo')]
    [string]$Configuration = 'RelWithDebInfo',

    [string]$BuildDir = (Join-Path $PSScriptRoot 'build'),
    [string]$ReportDir = (Join-Path $PSScriptRoot 'coverage'),

    # Compile and run tests under AddressSanitizer (ASAN) to catch memory errors.
    # On MSVC this enables /fsanitize=address.
    [switch]$EnableAsan = $true,

    # Optional: use vcpkg toolchain so GoogleTest can be found and the CTest
    # suite runs gtest-discovered tests.
    [string]$VcpkgRoot = 'C:\vcpkg',
    [string]$VcpkgTriplet = 'x64-windows',
    [switch]$UseVcpkg = $true,
    [switch]$EnsureGTest = $true,

    # If set, fail fast when OpenCppCoverage isn't available.
    # Otherwise, run tests via CTest and skip coverage generation.
    [switch]$RequireCoverageTool,

    # Minimum overall line coverage percentage required for production/header code.
    # Set to 0 to disable coverage gating (tests will still run).
    [ValidateRange(0, 100)]
    [int]$MinimumLineCoveragePercent = 95,

    [switch]$NoBuild
)

$ErrorActionPreference = 'Stop'

function Find-VsCMakeBin {
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (-not (Test-Path $vswhere)) {
        return $null
    }

    $vsPath = & $vswhere -latest -products * -property installationPath
    if (-not $vsPath) {
        return $null
    }

    $cmakeBin = Join-Path $vsPath 'Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin'
    if (Test-Path (Join-Path $cmakeBin 'cmake.exe')) {
        return $cmakeBin
    }

    return $null
}

function Get-NormalizedPath([string]$Path) {
    return [System.IO.Path]::GetFullPath($Path)
}

function Get-CoberturaLineCoverage([string]$CoberturaPath) {
    if (-not (Test-Path $CoberturaPath)) {
        throw "Cobertura report not found: $CoberturaPath"
    }

    [xml]$xml = Get-Content -LiteralPath $CoberturaPath
    $root = $xml.SelectSingleNode('/coverage')
    if (-not $root) {
        throw "Invalid Cobertura report (missing <coverage> root): $CoberturaPath"
    }

    # OpenCppCoverage's Cobertura export can include the same source file multiple
    # times (e.g., once per module/test executable). The <coverage> root totals may
    # therefore double-count "lines-valid" and under-report the union coverage.
    # Aggregate coverage by (filename, line number) and take the max hits.
    $fileToLineHits = @{}
    $classNodes = $xml.SelectNodes('//class[@filename]')
    foreach ($classNode in $classNodes) {
        $filename = $classNode.GetAttribute('filename')
        if (-not $filename) {
            continue
        }

        if (-not $fileToLineHits.ContainsKey($filename)) {
            $fileToLineHits[$filename] = @{}
        }

        $lineNodes = $classNode.SelectNodes('lines/line[@number and @hits]')
        foreach ($lineNode in $lineNodes) {
            $lineNumber = [int]$lineNode.GetAttribute('number')
            $hits = [int]$lineNode.GetAttribute('hits')
            $lineHitsForFile = $fileToLineHits[$filename]

            if ($lineHitsForFile.ContainsKey($lineNumber)) {
                if ($hits -gt $lineHitsForFile[$lineNumber]) {
                    $lineHitsForFile[$lineNumber] = $hits
                }
            } else {
                $lineHitsForFile[$lineNumber] = $hits
            }
        }
    }

    $dedupedValid = 0
    $dedupedCovered = 0
    foreach ($filename in $fileToLineHits.Keys) {
        foreach ($lineNumber in $fileToLineHits[$filename].Keys) {
            $dedupedValid += 1
            if ($fileToLineHits[$filename][$lineNumber] -gt 0) {
                $dedupedCovered += 1
            }
        }
    }

    $dedupedPercent = 0.0
    if ($dedupedValid -gt 0) {
        $dedupedPercent = ($dedupedCovered / [double]$dedupedValid) * 100.0
    }

    # Keep root totals for diagnostics/fallback.
    $rootLinesValid = [int]$root.GetAttribute('lines-valid')
    $rootLinesCovered = [int]$root.GetAttribute('lines-covered')
    $rootLineRateAttr = $root.GetAttribute('line-rate')
    $rootPercent = 0.0
    if ($rootLinesValid -gt 0) {
        $rootPercent = ($rootLinesCovered / [double]$rootLinesValid) * 100.0
    } elseif ($rootLineRateAttr) {
        $rootPercent = ([double]$rootLineRateAttr) * 100.0
    }

    # If the deduped aggregation produced no data (e.g., missing <lines> entries),
    # fall back to root totals so we still surface something useful.
    if ($dedupedValid -le 0 -and $rootLinesValid -gt 0) {
        $dedupedValid = $rootLinesValid
        $dedupedCovered = $rootLinesCovered
        $dedupedPercent = $rootPercent
    }

    return [pscustomobject]@{
        LinesValid = $dedupedValid
        LinesCovered = $dedupedCovered
        Percent = $dedupedPercent

        RootLinesValid = $rootLinesValid
        RootLinesCovered = $rootLinesCovered
        RootPercent = $rootPercent
        FileCount = $fileToLineHits.Count
    }
}

function Assert-Tooling {
    $openCpp = Get-Command 'OpenCppCoverage.exe' -ErrorAction SilentlyContinue
    if (-not $openCpp) {
        $candidates = @(
            $env:OPENCPPCOVERAGE_PATH,
            'C:\\Program Files\\OpenCppCoverage\\OpenCppCoverage.exe',
            'C:\\Program Files (x86)\\OpenCppCoverage\\OpenCppCoverage.exe'
        )
        foreach ($candidate in $candidates) {
            if ($candidate -and (Test-Path $candidate)) {
                $openCpp = [pscustomobject]@{ Source = $candidate }
                break
            }
        }
    }
    if (-not $openCpp -and $RequireCoverageTool) {
        throw "OpenCppCoverage.exe not found on PATH. Install OpenCppCoverage and ensure it's available in PATH, or omit -RequireCoverageTool to run tests without coverage. See: https://github.com/OpenCppCoverage/OpenCppCoverage"
    }

    $cmakeExe = (Get-Command 'cmake.exe' -ErrorAction SilentlyContinue).Source
    $ctestExe = (Get-Command 'ctest.exe' -ErrorAction SilentlyContinue).Source

    if ((-not $cmakeExe) -or (-not $ctestExe)) {
        if ($IsWindows) {
            $vsCmakeBin = Find-VsCMakeBin
            if ($vsCmakeBin) {
                if (-not $cmakeExe) { $cmakeExe = (Join-Path $vsCmakeBin 'cmake.exe') }
                if (-not $ctestExe) { $ctestExe = (Join-Path $vsCmakeBin 'ctest.exe') }
            }
        }
    }

    if (-not $cmakeExe) {
        throw 'cmake.exe not found on PATH (and no Visual Studio-bundled CMake was found).'
    }
    if (-not $ctestExe) {
        throw 'ctest.exe not found on PATH (and no Visual Studio-bundled CTest was found).'
    }

    $vcpkgExe = Join-Path $VcpkgRoot 'vcpkg.exe'
    if ($UseVcpkg -or $EnsureGTest) {
        if (-not (Test-Path $vcpkgExe)) {
            throw "vcpkg.exe not found at $vcpkgExe"
        }

        $toolchain = Join-Path $VcpkgRoot 'scripts\buildsystems\vcpkg.cmake'
        if (-not (Test-Path $toolchain)) {
            throw "vcpkg toolchain not found at $toolchain"
        }
    }

    return @{
        OpenCppCoverage = if ($openCpp) { $openCpp.Source } else { $null }
        CMake = $cmakeExe
        CTest = $ctestExe
    }
}

$tools = Assert-Tooling
$openCppCoverageExe = $tools.OpenCppCoverage
$cmakeExe = $tools.CMake
$ctestExe = $tools.CTest

if ($MinimumLineCoveragePercent -gt 0) {
    $RequireCoverageTool = $true
}

# If the caller didn't explicitly override BuildDir/ReportDir, use ASAN-specific defaults.
if ($EnableAsan) {
    if (-not $PSBoundParameters.ContainsKey('BuildDir')) {
        $BuildDir = (Join-Path $PSScriptRoot 'build-asan')
    }
    if (-not $PSBoundParameters.ContainsKey('ReportDir')) {
        $ReportDir = (Join-Path $PSScriptRoot 'coverage-asan')
    }

    # Leak detection is generally not supported/usable on Windows; keep it off to reduce noise.
    $env:ASAN_OPTIONS = 'detect_leaks=0,halt_on_error=1'
}

if (-not $NoBuild) {
    if ($EnsureGTest) {
        $vcpkgExe = Join-Path $VcpkgRoot 'vcpkg.exe'
        & $vcpkgExe install "gtest:$VcpkgTriplet"
        if ($LASTEXITCODE -ne 0) {
            throw "vcpkg failed to install gtest:$VcpkgTriplet"
        }
        $UseVcpkg = $true
    }

    $cmakeArgs = @('-S', $PSScriptRoot, '-B', $BuildDir, '-DBUILD_TESTING=ON')
    if ($EnableAsan) {
        $cmakeArgs += '-DCOSE_ENABLE_ASAN=ON'
    }
    if ($UseVcpkg) {
        $toolchain = Join-Path $VcpkgRoot 'scripts\buildsystems\vcpkg.cmake'
        $cmakeArgs += "-DCMAKE_TOOLCHAIN_FILE=$toolchain"
        $cmakeArgs += "-DVCPKG_TARGET_TRIPLET=$VcpkgTriplet"
        $cmakeArgs += "-DVCPKG_APPLOCAL_DEPS=OFF"
    }

    & $cmakeExe @cmakeArgs
    & $cmakeExe --build $BuildDir --config $Configuration
}

if (-not (Test-Path $BuildDir)) {
    throw "Build directory not found: $BuildDir. Build first (or pass -BuildDir pointing to an existing build)."
}

New-Item -ItemType Directory -Force -Path $ReportDir | Out-Null

$sourcesList = @(
    # Production/header code is primarily in include/
    (Get-NormalizedPath (Join-Path $PSScriptRoot 'include'))
)

$excludeList = @(
    (Get-NormalizedPath $BuildDir),
    (Get-NormalizedPath (Join-Path $PSScriptRoot '..\\rust\\target'))
)

if ($openCppCoverageExe) {
    $coberturaPath = (Join-Path $ReportDir 'cobertura.xml')

    $openCppArgs = @()
    foreach($s in $sourcesList) { $openCppArgs += '--sources'; $openCppArgs += $s }
    foreach($e in $excludeList) { $openCppArgs += '--excluded_sources'; $openCppArgs += $e }
    $openCppArgs += '--export_type'
    $openCppArgs += ("html:" + $ReportDir)
    $openCppArgs += '--export_type'
    $openCppArgs += ("cobertura:" + $coberturaPath)

    # CTest spawns test executables; we must enable child-process coverage.
    $openCppArgs += '--cover_children'

    $openCppArgs += '--quiet'
    $openCppArgs += '--'

    & $openCppCoverageExe @openCppArgs $ctestExe --test-dir $BuildDir -C $Configuration --output-on-failure

    if ($LASTEXITCODE -ne 0) {
        throw "OpenCppCoverage failed with exit code $LASTEXITCODE"
    }

    $coverage = Get-CoberturaLineCoverage $coberturaPath
    $pct = [Math]::Round([double]$coverage.Percent, 2)
    Write-Host "Line coverage (production/header): ${pct}% ($($coverage.LinesCovered)/$($coverage.LinesValid))"

    if (($null -ne $coverage.RootLinesValid) -and ($coverage.RootLinesValid -gt 0)) {
        $rootPct = [Math]::Round([double]$coverage.RootPercent, 2)
        Write-Host "(Cobertura root totals: ${rootPct}% ($($coverage.RootLinesCovered)/$($coverage.RootLinesValid)))"
    }

    if ($MinimumLineCoveragePercent -gt 0) {
        if ($coverage.LinesValid -le 0) {
            throw "No coverable production/header lines were detected by OpenCppCoverage (lines-valid=0); cannot enforce $MinimumLineCoveragePercent% gate."
        }

        if ($coverage.Percent -lt $MinimumLineCoveragePercent) {
            throw "Line coverage ${pct}% is below required ${MinimumLineCoveragePercent}%."
        }
    }
} else {
    Write-Warning "OpenCppCoverage.exe not found; running tests without coverage."
    & $ctestExe --test-dir $BuildDir -C $Configuration --output-on-failure
    if ($LASTEXITCODE -ne 0) {
        throw "CTest failed with exit code $LASTEXITCODE"
    }
}

Write-Host "Coverage report: $(Join-Path $ReportDir 'index.html')"
