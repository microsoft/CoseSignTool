<#
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
#>

$ErrorActionPreference = 'Stop'

Push-Location $PSScriptRoot
try {
  cargo build --release
  if ($LASTEXITCODE -ne 0) {
    throw "cargo build failed (exit $LASTEXITCODE)"
  }

  $exe = Join-Path $PSScriptRoot 'target/release/hello-world.exe'
  Write-Host "Built: $exe" -ForegroundColor Green
  Write-Host "Run:   $exe <cose_sign1_file> <public_key_file> [external_payload_file]" -ForegroundColor Cyan
} finally {
  Pop-Location
}
