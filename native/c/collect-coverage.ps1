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

function Assert-Tooling {
    $openCpp = Get-Command 'OpenCppCoverage.exe' -ErrorAction SilentlyContinue
    if (-not $openCpp -and $RequireCoverageTool) {
        throw "OpenCppCoverage.exe not found on PATH. Install OpenCppCoverage and ensure it's available in PATH, or omit -RequireCoverageTool to run tests without coverage. See: https://github.com/OpenCppCoverage/OpenCppCoverage"
    }

    $cmake = Get-Command 'cmake.exe' -ErrorAction SilentlyContinue
    if (-not $cmake) {
        throw 'cmake.exe not found on PATH.'
    }

    $ctest = Get-Command 'ctest.exe' -ErrorAction SilentlyContinue
    if (-not $ctest) {
        throw 'ctest.exe not found on PATH.'
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
        CTest = $ctest.Source
    }
}

$tools = Assert-Tooling
$openCppCoverageExe = $tools.OpenCppCoverage
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

    cmake @cmakeArgs
    cmake --build $BuildDir --config $Configuration
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
    $BuildDir,
    (Join-Path $PSScriptRoot '..\rust\target')
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
