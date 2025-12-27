param(
    [string]$BuildDir = "out-vs18",
    [string]$Configuration = "Release",
    [string]$VcpkgRoot = $env:VCPKG_ROOT,
    [string]$OpenCppCoveragePath = $env:OPENCPPCOVERAGE_PATH,
    [string]$Generator = "",
    [string]$Architecture = "x64",
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

function Resolve-VsCMakeBinDir {
    $vswhere = Resolve-ExePath -Name "vswhere" -FallbackPaths @(
        "${env:ProgramFiles(x86)}\\Microsoft Visual Studio\\Installer\\vswhere.exe",
        "${env:ProgramFiles}\\Microsoft Visual Studio\\Installer\\vswhere.exe"
    )

    if (-not $vswhere) {
        return $null
    }

    $installPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if ($LASTEXITCODE -ne 0 -or -not $installPath) {
        return $null
    }

    $installPath = $installPath.Trim()
    if (-not $installPath) {
        return $null
    }

    $cmakeBin = Join-Path $installPath "Common7\\IDE\\CommonExtensions\\Microsoft\\CMake\\CMake\\bin"
    if (Test-Path $cmakeBin) {
        return $cmakeBin
    }

    return $null
}

function Resolve-VsGenerator {
    param(
        [string]$Explicit
    )

    if ($Explicit) {
        return $Explicit
    }

    $vswhere = Resolve-ExePath -Name "vswhere" -FallbackPaths @(
        "${env:ProgramFiles(x86)}\\Microsoft Visual Studio\\Installer\\vswhere.exe",
        "${env:ProgramFiles}\\Microsoft Visual Studio\\Installer\\vswhere.exe"
    )

    if (-not $vswhere) {
        # Default to the most common currently-supported VS generator.
        return "Visual Studio 17 2022"
    }

    $ver = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationVersion
    if ($LASTEXITCODE -ne 0 -or -not $ver) {
        return "Visual Studio 17 2022"
    }

    $major = ($ver.Trim() -split '\.')[0]
    switch ($major) {
        "17" { return "Visual Studio 17 2022" }
        "18" { return "Visual Studio 18 2026" }
        default { return "Visual Studio 17 2022" }
    }
}

$cmake = Resolve-ExePath -Name "cmake" -FallbackPaths @()
$ctest = Resolve-ExePath -Name "ctest" -FallbackPaths @()

if (-not $cmake -or -not $ctest) {
    $vsCmakeBin = Resolve-VsCMakeBinDir
    if ($vsCmakeBin) {
        if (-not $cmake) {
            $candidate = Join-Path $vsCmakeBin "cmake.exe"
            if (Test-Path $candidate) { $cmake = $candidate }
        }
        if (-not $ctest) {
            $candidate = Join-Path $vsCmakeBin "ctest.exe"
            if (Test-Path $candidate) { $ctest = $candidate }
        }
    }
}

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

& $cmake -S $here -B $buildPath -G (Resolve-VsGenerator -Explicit $Generator) -A $Architecture -DCMAKE_TOOLCHAIN_FILE="$VcpkgRoot\\scripts\\buildsystems\\vcpkg.cmake"
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
