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

function Assert-Tooling {
    $openCpp = Get-Command 'OpenCppCoverage.exe' -ErrorAction SilentlyContinue
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

$sources = @(
    (Join-Path $PSScriptRoot 'include'),
    (Join-Path $PSScriptRoot 'tests')
) -join ';'

$exclude = @(
    (Get-NormalizedPath $BuildDir),
    (Get-NormalizedPath (Join-Path $PSScriptRoot '..\rust\target'))
) -join ';'

if ($openCppCoverageExe) {
    & $openCppCoverageExe `
        --sources $sources `
        --excluded_sources $exclude `
        --export_type ("html:" + $ReportDir) `
        --quiet `
        -- `
        $ctestExe --test-dir $BuildDir -C $Configuration --output-on-failure
} else {
    Write-Warning "OpenCppCoverage.exe not found; running tests without coverage."
    & $ctestExe --test-dir $BuildDir -C $Configuration --output-on-failure
    if ($LASTEXITCODE -ne 0) {
        throw "CTest failed with exit code $LASTEXITCODE"
    }
}

Write-Host "Coverage report: $(Join-Path $ReportDir 'index.html')"
