param(
  [int]$FailUnderLines = 95
)

$ErrorActionPreference = 'Stop'

Push-Location $PSScriptRoot
try {
  & rustup component add llvm-tools-preview
  if ($LASTEXITCODE -ne 0) {
    throw "Failed to install rustup component llvm-tools-preview (exit $LASTEXITCODE)"
  }

  $llvmCov = Get-Command cargo-llvm-cov -ErrorAction SilentlyContinue
  if (-not $llvmCov) {
    Write-Host "Installing cargo-llvm-cov..." -ForegroundColor Cyan
    & cargo install cargo-llvm-cov
    if ($LASTEXITCODE -ne 0) {
      throw "Failed to install cargo-llvm-cov (exit $LASTEXITCODE)"
    }
  }

  & cargo llvm-cov --workspace --fail-under-lines $FailUnderLines
  if ($LASTEXITCODE -ne 0) {
    throw "Coverage gate failed: expected >= $FailUnderLines% line coverage (exit $LASTEXITCODE)"
  }
} finally {
  Pop-Location
}
