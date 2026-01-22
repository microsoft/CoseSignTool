[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release', 'RelWithDebInfo')]
    [string]$Configuration = 'Debug',

    [ValidateRange(0, 100)]
    [int]$MinimumLineCoveragePercent = 95,

    # Build the Rust FFI DLLs first (required for native C/C++ tests).
    [switch]$BuildRust = $true
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

$repoRoot = Split-Path -Parent $PSScriptRoot

# Ensure ASAN runtime is available for all phases, including Rust-dependency C code.
Add-VsAsanRuntimeToPath

# When running under the ASAN pipeline, also build any C/C++ code compiled by Rust crates
# (e.g., PQClean via pqcrypto-*) with AddressSanitizer enabled. This helps catch memory
# issues inside those vendored C implementations.
$prevCFlags = ${env:CFLAGS_x86_64-pc-windows-msvc}
$prevCxxFlags = ${env:CXXFLAGS_x86_64-pc-windows-msvc}
${env:CFLAGS_x86_64-pc-windows-msvc} = '/fsanitize=address'
${env:CXXFLAGS_x86_64-pc-windows-msvc} = '/fsanitize=address'

try {
    if ($BuildRust) {
        Push-Location (Join-Path $PSScriptRoot 'rust')
        try {
            cargo build --release -p cose_sign1_validation_ffi -p cose_sign1_validation_ffi_certificates -p cose_sign1_validation_ffi_mst -p cose_sign1_validation_ffi_akv -p cose_sign1_validation_ffi_trust

            # Explicitly compile the PQClean-backed PQC implementation under ASAN, even though it's
            # feature-gated and not built by default.
            # This keeps the default coverage gates unchanged while still ensuring PQClean C is
            # ASAN-instrumented in the ASAN pipeline.
            cargo build --release -p cose_sign1_validation_certificates --features pqc-mldsa
        } finally {
            Pop-Location
        }
    }

    & (Join-Path $PSScriptRoot 'rust\collect-coverage.ps1') -FailUnderLines $MinimumLineCoveragePercent
    & (Join-Path $PSScriptRoot 'c\collect-coverage.ps1') -Configuration $Configuration -MinimumLineCoveragePercent $MinimumLineCoveragePercent
    & (Join-Path $PSScriptRoot 'c_pp\collect-coverage.ps1') -Configuration $Configuration -MinimumLineCoveragePercent $MinimumLineCoveragePercent
} finally {
    ${env:CFLAGS_x86_64-pc-windows-msvc} = $prevCFlags
    ${env:CXXFLAGS_x86_64-pc-windows-msvc} = $prevCxxFlags
}

Write-Host "Native C + C++ coverage gates passed (Configuration=$Configuration, MinimumLineCoveragePercent=$MinimumLineCoveragePercent)."