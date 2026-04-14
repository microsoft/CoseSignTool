#!/usr/bin/env pwsh
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Downloads and builds the OQS (Open Quantum Safe) provider for OpenSSL.
# Provides hybrid PQC algorithms (e.g., p256_mldsa44, p384_mldsa65).
#
# Prerequisites: CMake, Ninja, MSVC (cl.exe), Git
# Usage: ./setup-oqs-provider.ps1 [-OpenSslDir "c:\vcpkg\installed\x64-windows"]

param(
    [string]$OpenSslDir = $env:OPENSSL_DIR,
    [string]$InstallDir = "$PSScriptRoot\..\oqs-provider",
    [string]$LiboqsVersion = "0.15.0",
    [string]$OqsProviderVersion = "0.11.0"
)

$ErrorActionPreference = "Stop"

if (-not $OpenSslDir) {
    Write-Error "OPENSSL_DIR not set. Provide -OpenSslDir or set the environment variable."
    exit 1
}

$buildDir = Join-Path $InstallDir "build"
New-Item -ItemType Directory -Force -Path $buildDir | Out-Null

# Step 1: Clone and build liboqs
Write-Host "=== Building liboqs v$LiboqsVersion ===" -ForegroundColor Cyan
$liboqsDir = Join-Path $buildDir "liboqs"
if (-not (Test-Path $liboqsDir)) {
    git clone --depth 1 --branch "$LiboqsVersion" https://github.com/open-quantum-safe/liboqs.git $liboqsDir
}

$liboqsBuild = Join-Path $liboqsDir "build"
$liboqsInstall = Join-Path $InstallDir "liboqs"
cmake -G Ninja -S $liboqsDir -B $liboqsBuild `
    -DCMAKE_BUILD_TYPE=Release `
    -DCMAKE_INSTALL_PREFIX=$liboqsInstall `
    -DOQS_BUILD_ONLY_LIB=ON
cmake --build $liboqsBuild --config Release
cmake --install $liboqsBuild

# Step 2: Clone and build oqs-provider
Write-Host "=== Building oqs-provider v$OqsProviderVersion ===" -ForegroundColor Cyan
$providerDir = Join-Path $buildDir "oqs-provider"
if (-not (Test-Path $providerDir)) {
    git clone --depth 1 --branch "$OqsProviderVersion" https://github.com/open-quantum-safe/oqs-provider.git $providerDir
}

$providerBuild = Join-Path $providerDir "_build"
cmake -G Ninja -S $providerDir -B $providerBuild `
    -DCMAKE_BUILD_TYPE=Release `
    -DOPENSSL_ROOT_DIR=$OpenSslDir `
    -Dliboqs_DIR="$liboqsInstall\lib\cmake\liboqs"
cmake --build $providerBuild --config Release

# Step 3: Copy provider DLL to output directory
$providerDll = Get-ChildItem $providerBuild -Recurse -Filter "oqsprovider.dll" | Select-Object -First 1
if (-not $providerDll) {
    $providerDll = Get-ChildItem $providerBuild -Recurse -Filter "oqsprovider.so" | Select-Object -First 1
}

if ($providerDll) {
    $modulesDir = Join-Path $InstallDir "lib"
    New-Item -ItemType Directory -Force -Path $modulesDir | Out-Null
    Copy-Item $providerDll.FullName -Destination $modulesDir
    Write-Host "OQS provider installed to: $modulesDir\$($providerDll.Name)" -ForegroundColor Green

    # Set environment variable for this session
    $env:OPENSSL_MODULES = $modulesDir
    Write-Host "Set OPENSSL_MODULES=$modulesDir" -ForegroundColor Green

    # Verify
    Write-Host "`n=== Verifying OQS provider ===" -ForegroundColor Cyan
    $opensslExe = Get-ChildItem "$OpenSslDir" -Recurse -Filter "openssl.exe" | Select-Object -First 1
    if ($opensslExe) {
        & $opensslExe.FullName list -signature-algorithms -provider oqsprovider -provider default 2>&1 |
            Select-String "mldsa|dilithium|p256|p384" | Select-Object -First 10
    }
} else {
    Write-Error "Failed to find oqsprovider DLL after build"
    exit 1
}

Write-Host "`n=== OQS Provider Setup Complete ===" -ForegroundColor Green
Write-Host "To use: set OPENSSL_MODULES=$modulesDir" -ForegroundColor Yellow
