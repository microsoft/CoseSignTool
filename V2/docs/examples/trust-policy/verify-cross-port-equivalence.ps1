# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# verify-cross-port-equivalence.ps1
#
# Demonstrates that an identical .coseTrustPolicy.json (or .rego) file produces
# equivalent verifier behaviour on the .NET V2 CLI (cosesigntool) AND the native
# Rust CLI. The contract is documented in V2/docs/guides/trust-policy.md under
# "Cross-port compatibility".
#
# Usage:
#   .\verify-cross-port-equivalence.ps1 [-PolicyFile <path>] [-Signature <path>] [-PayloadParams <json>]
#
# The defaults exercise V2/docs/examples/trust-policy/canonical-policy.coseTrustPolicy.json
# against a representative signed COSE Sign1 fixture from CoseSign1.Tests.Common.
#
# What this script asserts:
#  1. Both CLIs accept the SAME --trust-policy <path> + --trust-policy-param flags.
#  2. Both CLIs produce equivalent exit codes for the same (signature, policy, params) tuple.
#  3. Both CLIs surface the SAME TPX diagnostic code on translation errors.
#
# What this script does NOT assert (by design):
#  - Byte-identical stdout. Each CLI formats its output independently; only the
#    diagnostic-code-set and exit-code are part of the cross-port contract.
#  - Byte-identical decision under all runtime conditions. Pack fact producers
#    are independently implemented in .NET vs. Rust; edge cases in cert chain
#    validation, revocation handling, etc. may differ. The portable surface is
#    the POLICY DOCUMENT, not every fact-producer behaviour.

[CmdletBinding()]
param(
    [string]$PolicyFile = (Join-Path $PSScriptRoot 'canonical-policy.coseTrustPolicy.json'),
    [string]$Signature = '',
    [string]$PayloadParams = '{}',
    [string]$DotnetCli = (Join-Path $PSScriptRoot '..\..\..\artifacts\cosesigntool.exe'),
    [string]$RustCli = (Join-Path $PSScriptRoot '..\..\..\..\native\rust\target\release\cose-rs.exe')
)

$ErrorActionPreference = 'Stop'

function Format-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host "================================================================" -ForegroundColor Cyan
}

function Invoke-Cli {
    param([string]$ExePath, [string[]]$Args, [string]$Label)
    if (-not (Test-Path $ExePath)) {
        Write-Host "  [skipped] $Label binary not found at $ExePath" -ForegroundColor Yellow
        return $null
    }
    Write-Host "  $Label invocation:" -ForegroundColor Gray
    Write-Host "    $ExePath $($Args -join ' ')" -ForegroundColor Gray
    $output = & $ExePath @Args 2>&1
    [pscustomobject]@{
        Label    = $Label
        ExitCode = $LASTEXITCODE
        Output   = ($output -join [Environment]::NewLine)
        TpxCodes = ($output | Select-String -Pattern 'TPX\d{3,4}' -AllMatches `
                              | ForEach-Object { $_.Matches.Value } | Sort-Object -Unique)
    }
}

Format-Section 'Cross-port equivalence demonstration'
Write-Host "  Policy file: $PolicyFile"
Write-Host "  Signature:   $(if ($Signature) { $Signature } else { '<none — translation-only mode>' })"
Write-Host "  Parameters:  $PayloadParams"

# Build the argument lists. Both CLIs accept the same flag shape.
$args = @('verify', 'x509')
if ($Signature) { $args += $Signature }
$args += @('--trust-policy', $PolicyFile)
if ($PayloadParams -and $PayloadParams -ne '{}') {
    # Translate JSON params object into repeated --trust-policy-param key='value' invocations.
    $obj = $PayloadParams | ConvertFrom-Json
    foreach ($prop in $obj.PSObject.Properties) {
        $args += @('--trust-policy-param', "$($prop.Name)=$($prop.Value | ConvertTo-Json -Compress)")
    }
}

Format-Section '.NET V2 CLI (cosesigntool)'
$dotnetResult = Invoke-Cli -ExePath $DotnetCli -Args $args -Label '.NET'

Format-Section 'Native Rust CLI (cose-rs)'
$rustResult = Invoke-Cli -ExePath $RustCli -Args $args -Label 'Rust'

Format-Section 'Equivalence verdict'
if (-not $dotnetResult -or -not $rustResult) {
    Write-Host "  Could not exercise both CLIs (one or both binaries missing). Build both before running." -ForegroundColor Yellow
    Write-Host "    .NET:  cd V2 && dotnet publish CoseSignTool/CoseSignTool.csproj" -ForegroundColor Gray
    Write-Host "    Rust:  cd native/rust && cargo build --release -p cli" -ForegroundColor Gray
    exit 2
}

$exitCodeMatch = $dotnetResult.ExitCode -eq $rustResult.ExitCode
$tpxSetMatch   = ((Compare-Object $dotnetResult.TpxCodes $rustResult.TpxCodes) -eq $null)

Write-Host ("  .NET exit code: {0}    TPX codes: {1}" -f $dotnetResult.ExitCode, ($dotnetResult.TpxCodes -join ', '))
Write-Host ("  Rust exit code: {0}    TPX codes: {1}" -f $rustResult.ExitCode, ($rustResult.TpxCodes -join ', '))
Write-Host ""

if ($exitCodeMatch -and $tpxSetMatch) {
    Write-Host "  ✅ EQUIVALENT — same exit code, same TPX diagnostic set." -ForegroundColor Green
    exit 0
}

if (-not $exitCodeMatch) {
    Write-Host "  ❌ EXIT CODE MISMATCH — .NET=$($dotnetResult.ExitCode), Rust=$($rustResult.ExitCode)" -ForegroundColor Red
}
if (-not $tpxSetMatch) {
    Write-Host "  ❌ TPX CODE SET MISMATCH" -ForegroundColor Red
    Write-Host ("     .NET: {0}" -f ($dotnetResult.TpxCodes -join ', '))
    Write-Host ("     Rust: {0}" -f ($rustResult.TpxCodes -join ', '))
}
exit 1
