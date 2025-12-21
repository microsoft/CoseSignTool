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

  $exe = Join-Path $PSScriptRoot 'target/release/cosesign1_hello_world.exe'
  Write-Host "Built: $exe" -ForegroundColor Green
  Write-Host "Run:   $exe <mode> [args...]" -ForegroundColor Cyan
} finally {
  Pop-Location
}
