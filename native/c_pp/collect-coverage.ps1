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

function Resolve-ExePath {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [string[]]$FallbackPaths
    )

    $cmd = Get-Command $Name -ErrorAction SilentlyContinue
    if ($cmd -and $cmd.Source -and (Test-Path $cmd.Source)) {
        return $cmd.Source
    }

    foreach ($p in ($FallbackPaths | Where-Object { $_ })) {
        if (Test-Path $p) {
            return $p
        }
    }

    return $null
}

function Get-VsInstallationPath {
    $vswhere = Resolve-ExePath -Name 'vswhere' -FallbackPaths @(
        "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe",
        "${env:ProgramFiles}\Microsoft Visual Studio\Installer\vswhere.exe"
    )

    if (-not $vswhere) {
        return $null
    }

    $vsPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if ($LASTEXITCODE -ne 0 -or -not $vsPath) {
        $vsPath = & $vswhere -latest -products * -property installationPath
    }

    if (-not $vsPath) {
        return $null
    }

    $vsPath = ($vsPath | Select-Object -First 1).Trim()
    if (-not $vsPath) {
        return $null
    }

    if (-not (Test-Path $vsPath)) {
        return $null
    }

    return $vsPath
}

function Add-VsAsanRuntimeToPath {
    if (-not ($env:OS -eq 'Windows_NT')) {
        return
    }

    $vsPath = Get-VsInstallationPath
    if (-not $vsPath) {
        return
    }

    # On MSVC, /fsanitize=address depends on clang ASAN runtime DLLs that ship with VS.
    # If they're not on PATH, Windows shows modal popup dialogs and tests fail with 0xc0000135.
    $candidateDirs = @()

    $msvcToolsRoot = Join-Path $vsPath 'VC\Tools\MSVC'
    if (Test-Path $msvcToolsRoot) {
        $latestMsvc = Get-ChildItem -Path $msvcToolsRoot -Directory -ErrorAction SilentlyContinue |
            Sort-Object Name -Descending |
            Select-Object -First 1
        if ($latestMsvc) {
            $candidateDirs += (Join-Path $latestMsvc.FullName 'bin\Hostx64\x64')
            $candidateDirs += (Join-Path $latestMsvc.FullName 'bin\Hostx64\x86')
        }
    }

    $llvmRoot = Join-Path $vsPath 'VC\Tools\Llvm'
    if (Test-Path $llvmRoot) {
        $candidateDirs += (Join-Path $llvmRoot 'x64\bin')
        $clangLibRoot = Join-Path $llvmRoot 'x64\lib\clang'
        if (Test-Path $clangLibRoot) {
            $latestClang = Get-ChildItem -Path $clangLibRoot -Directory -ErrorAction SilentlyContinue |
                Sort-Object Name -Descending |
                Select-Object -First 1
            if ($latestClang) {
                $candidateDirs += (Join-Path $latestClang.FullName 'lib\windows')
            }
        }
    }

    $asanDllName = 'clang_rt.asan_dynamic-x86_64.dll'
    foreach ($dir in ($candidateDirs | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique)) {
        if (Test-Path (Join-Path $dir $asanDllName)) {
            if ($env:PATH -notlike "${dir}*") {
                $env:PATH = "${dir};$env:PATH"
                Write-Host "Using ASAN runtime from: $dir" -ForegroundColor Yellow
            }
            return
        }
    }
}

function Find-VsCMakeBin {
    function Probe-VsRootForCMakeBin([string]$vsRoot) {
        if (-not $vsRoot -or -not (Test-Path $vsRoot)) {
            return $null
        }

        $years = Get-ChildItem -Path $vsRoot -Directory -ErrorAction SilentlyContinue
        foreach ($year in $years) {
            $editions = Get-ChildItem -Path $year.FullName -Directory -ErrorAction SilentlyContinue
            foreach ($edition in $editions) {
                $cmakeBin = Join-Path $edition.FullName 'Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin'
                if (Test-Path (Join-Path $cmakeBin 'cmake.exe')) {
                    return $cmakeBin
                }

                $cmakeExtensionRoot = Join-Path $edition.FullName 'Common7\IDE\CommonExtensions\Microsoft\CMake'
                if (Test-Path $cmakeExtensionRoot) {
                    $found = Get-ChildItem -Path $cmakeExtensionRoot -Recurse -File -Filter 'cmake.exe' -ErrorAction SilentlyContinue |
                        Select-Object -First 1
                    if ($found) {
                        return (Split-Path -Parent $found.FullName)
                    }
                }
            }
        }

        return $null
    }

    $vswhere = Resolve-ExePath -Name 'vswhere' -FallbackPaths @(
        "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe",
        "${env:ProgramFiles}\Microsoft Visual Studio\Installer\vswhere.exe"
    )

    if ($vswhere) {
        $vsPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
        if ($LASTEXITCODE -ne 0 -or -not $vsPath) {
            $vsPath = & $vswhere -latest -products * -property installationPath
        }

        if ($vsPath) {
            $vsPath = ($vsPath | Select-Object -First 1).Trim()
            if ($vsPath) {
                $cmakeBin = Join-Path $vsPath 'Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin'
                if (Test-Path (Join-Path $cmakeBin 'cmake.exe')) {
                    return $cmakeBin
                }

                $cmakeExtensionRoot = Join-Path $vsPath 'Common7\IDE\CommonExtensions\Microsoft\CMake'
                if (Test-Path $cmakeExtensionRoot) {
                    $found = Get-ChildItem -Path $cmakeExtensionRoot -Recurse -File -Filter 'cmake.exe' -ErrorAction SilentlyContinue |
                        Select-Object -First 1
                    if ($found) {
                        return (Split-Path -Parent $found.FullName)
                    }
                }
            }
        }
    }

    $roots = @(
        (Join-Path $env:ProgramFiles 'Microsoft Visual Studio'),
        (Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio')
    )
    foreach ($r in ($roots | Where-Object { $_ })) {
        $bin = Probe-VsRootForCMakeBin -vsRoot $r
        if ($bin) {
            return $bin
        }
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
        if ($env:OS -eq 'Windows_NT') {
            $vsCmakeBin = Find-VsCMakeBin
            if ($vsCmakeBin) {
                if ($env:PATH -notlike "${vsCmakeBin}*") {
                    $env:PATH = "${vsCmakeBin};$env:PATH"
                }

                if (-not $cmakeExe) {
                    $candidate = (Join-Path $vsCmakeBin 'cmake.exe')
                    if (Test-Path $candidate) { $cmakeExe = $candidate }
                }
                if (-not $ctestExe) {
                    $candidate = (Join-Path $vsCmakeBin 'ctest.exe')
                    if (Test-Path $candidate) { $ctestExe = $candidate }
                }
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

    Add-VsAsanRuntimeToPath
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
