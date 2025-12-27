param(
    [string]$BuildDir = "out-vs18",
    [string]$Configuration = "Release",
    [string]$VcpkgRoot = $env:VCPKG_ROOT,
    [string]$OpenCppCoveragePath = $env:OPENCPPCOVERAGE_PATH,
    [switch]$AutoInstallTools
)

$ErrorActionPreference = "Stop"

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$buildPath = Join-Path $here $BuildDir

if (-not $VcpkgRoot) {
    throw "VCPKG_ROOT is not set. Set it to your vcpkg installation root (e.g. C:\\vcpkg)."
}

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

function Resolve-OpenCppCoverage {
    if ($OpenCppCoveragePath) {
        if (-not (Test-Path $OpenCppCoveragePath)) {
            throw "OpenCppCoveragePath was provided but does not exist: $OpenCppCoveragePath"
        }
        return $OpenCppCoveragePath
    }

    $occ = Resolve-ExePath -Name "OpenCppCoverage" -FallbackPaths @(
        "C:\\Program Files\\OpenCppCoverage\\OpenCppCoverage.exe",
        "C:\\Program Files (x86)\\OpenCppCoverage\\OpenCppCoverage.exe",
        (Join-Path $here "_tools\\OpenCppCoverage\\OpenCppCoverage.exe"),
        (Join-Path $here "..\\..\\..\\_tmp\\tools\\OpenCppCoverage\\OpenCppCoverage.exe")
    )

    if ($occ) {
        return $occ
    }

    if (-not $AutoInstallTools) {
        return $null
    }

    Write-Host "OpenCppCoverage not found. Attempting to install..." -ForegroundColor Yellow

    $winget = Resolve-ExePath -Name "winget" -FallbackPaths @()
    if ($winget) {
        try {
            & $winget install -e --id OpenCppCoverage.OpenCppCoverage --accept-source-agreements --accept-package-agreements --silent | Out-Host
        } catch {
            Write-Warning "winget install failed: $($_.Exception.Message)"
        }
    }

    $occ = Resolve-ExePath -Name "OpenCppCoverage" -FallbackPaths @(
        "C:\\Program Files\\OpenCppCoverage\\OpenCppCoverage.exe",
        "C:\\Program Files (x86)\\OpenCppCoverage\\OpenCppCoverage.exe"
    )
    if ($occ) {
        return $occ
    }

    $choco = Resolve-ExePath -Name "choco" -FallbackPaths @()
    if ($choco) {
        try {
            & $choco install opencppcoverage -y --no-progress | Out-Host
        } catch {
            Write-Warning "choco install failed: $($_.Exception.Message)"
        }
    }

    return (Resolve-ExePath -Name "OpenCppCoverage" -FallbackPaths @(
        "C:\\Program Files\\OpenCppCoverage\\OpenCppCoverage.exe",
        "C:\\Program Files (x86)\\OpenCppCoverage\\OpenCppCoverage.exe"
    ))
}

$cmake = Resolve-ExePath -Name "cmake" -FallbackPaths @(
    "C:\\Program Files\\Microsoft Visual Studio\\18\\Enterprise\\Common7\\IDE\\CommonExtensions\\Microsoft\\CMake\\CMake\\bin\\cmake.exe"
)
$ctest = Resolve-ExePath -Name "ctest" -FallbackPaths @(
    "C:\\Program Files\\Microsoft Visual Studio\\18\\Enterprise\\Common7\\IDE\\CommonExtensions\\Microsoft\\CMake\\CMake\\bin\\ctest.exe"
)

if (-not (Test-Path $cmake)) {
    throw "cmake.exe not found. Install CMake or the Visual Studio CMake tools."
}

if (-not (Test-Path $ctest)) {
    throw "ctest.exe not found. Install CMake or the Visual Studio CMake tools."
}

$occExe = Resolve-OpenCppCoverage
if (-not $occExe) {
    throw "OpenCppCoverage not found. Re-run with -AutoInstallTools, or install it manually (e.g. winget install OpenCppCoverage.OpenCppCoverage), or set OPENCPPCOVERAGE_PATH."
}

& $cmake -S $here -B $buildPath -G "Visual Studio 18 2026" -A x64 -DCMAKE_TOOLCHAIN_FILE="$VcpkgRoot\\scripts\\buildsystems\\vcpkg.cmake"
& $cmake --build $buildPath --config $Configuration -j
& $ctest --test-dir $buildPath -C $Configuration --output-on-failure

$exe = Join-Path $buildPath "$Configuration\\cosesign1_native_tests.exe"
if (-not (Test-Path $exe)) {
    throw "Test executable not found: $exe"
}

$headerSources = Join-Path $buildPath "vcpkg_installed\\x64-windows\\include\\cosesign1"
if (-not (Test-Path $headerSources)) {
    Write-Warning "Header include dir not found at expected location: $headerSources"
}

$coverageOut = Join-Path $buildPath "coverage"
New-Item -ItemType Directory -Force -Path $coverageOut | Out-Null

$occArgs = @(
    "--quiet",
    "--sources=$headerSources",
    "--export_type=html:$coverageOut",
    "--",
    $exe
)

& $occExe @occArgs

Write-Output "Coverage HTML written to: $coverageOut"
