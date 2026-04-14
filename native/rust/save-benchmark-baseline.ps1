# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Saves current benchmark results as the baseline for CI comparison.
# Usage: .\save-benchmark-baseline.ps1 [-BaselineName "main"]

param([string]$BaselineName = "main")

$env:OPENSSL_DIR = "c:\vcpkg\installed\x64-windows"
$env:PATH = "$env:OPENSSL_DIR\bin;$env:PATH"

cargo bench -p cose_benchmarks -- --save-baseline $BaselineName

Write-Host "Baseline '$BaselineName' saved to target/criterion/"
