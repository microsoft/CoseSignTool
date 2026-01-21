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

$repoRoot = Split-Path -Parent $PSScriptRoot

if ($BuildRust) {
    Push-Location (Join-Path $PSScriptRoot 'rust')
    try {
        cargo build --release -p cose_sign1_validation_ffi -p cose_sign1_validation_ffi_certificates -p cose_sign1_validation_ffi_mst -p cose_sign1_validation_ffi_akv -p cose_sign1_validation_ffi_trust
    } finally {
        Pop-Location
    }
}

& (Join-Path $PSScriptRoot 'c\collect-coverage.ps1') -Configuration $Configuration -MinimumLineCoveragePercent $MinimumLineCoveragePercent
& (Join-Path $PSScriptRoot 'c_pp\collect-coverage.ps1') -Configuration $Configuration -MinimumLineCoveragePercent $MinimumLineCoveragePercent

Write-Host "Native C + C++ coverage gates passed (Configuration=$Configuration, MinimumLineCoveragePercent=$MinimumLineCoveragePercent)."