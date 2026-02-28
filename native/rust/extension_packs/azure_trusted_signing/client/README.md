# azure_trusted_signing_client

Rust client for the Azure Trusted Signing REST API, reverse-engineered from Azure.CodeSigning.Sdk NuGet v0.1.164.

## Overview

This crate provides a direct REST API client for Azure Trusted Signing (ATS), implementing the exact same endpoints as the official C# Azure.CodeSigning.Sdk. It enables code signing operations through Azure's managed certificate infrastructure.

## Features

- **Sign Operations**: Submit digest signing requests with Long-Running Operation (LRO) polling
- **Certificate Management**: Retrieve certificate chains, root certificates, and Extended Key Usage (EKU) information
- **Authentication**: Support for Azure Identity credentials (DefaultAzureCredential, etc.)
- **Error Handling**: Comprehensive error types matching the service's error responses

## API Endpoints

All endpoints are prefixed with: `{endpoint}/codesigningaccounts/{accountName}/certificateprofiles/{profileName}`

| Method | Path | Description |
|--------|------|-------------|
| POST | `/sign` | Submit digest for signing (returns 202, initiates LRO) |
| GET | `/sign/{operationId}` | Poll signing operation status |
| GET | `/sign/eku` | Get Extended Key Usage OIDs |
| GET | `/sign/rootcert` | Get root certificate (DER bytes) |
| GET | `/sign/certchain` | Get certificate chain (PKCS#7 bytes) |

## Usage Example

```rust
use azure_trusted_signing_client::{CertificateProfileClient, CertificateProfileClientOptions, SignatureAlgorithm};

// Configure client
let options = CertificateProfileClientOptions::new(
    "https://eus.codesigning.azure.net",
    "my-account",
    "my-profile"
);

// Create client with developer credentials
let client = CertificateProfileClient::new_dev(options)?;

// Sign a digest
let digest = &[0x12, 0x34, 0x56, 0x78]; // SHA-256 digest
let result = client.sign(SignatureAlgorithm::RS256, digest)?;

println!("Signature: {:?}", result.signature);
println!("Certificate: {:?}", result.signing_certificate);

// Get certificate chain
let chain = client.get_certificate_chain()?;
println!("Chain length: {} bytes", chain.len());
```

## Authentication

The client uses Azure Identity for authentication. The auth scope is automatically constructed as `{endpoint}/.default` (e.g., `https://eus.codesigning.azure.net/.default`).

Supported credential types:
- `DeveloperToolsCredential` (recommended for local development)
- `ManagedIdentityCredential`
- `ClientSecretCredential`
- Any type implementing `azure_core::credentials::TokenCredential`

## Supported Signature Algorithms

- RS256, RS384, RS512 (RSASSA-PKCS1-v1_5)
- PS256, PS384, PS512 (RSASSA-PSS)
- ES256, ES384, ES512 (ECDSA)
- ES256K (ECDSA with secp256k1)

## Error Handling

The client provides detailed error information through `AtsClientError`:

- `HttpError`: Network or HTTP protocol errors
- `AuthenticationFailed`: Azure authentication issues
- `ServiceError`: Azure Trusted Signing service errors (with service error codes)
- `OperationFailed`/`OperationTimeout`: Long-running operation failures
- `DeserializationError`: JSON parsing failures

## Architecture Notes

This is a **pure REST client** implementation using `reqwest` directly, as there is no official Rust SDK for Azure Trusted Signing. The implementation mirrors the C# SDK's behavior exactly, including:

- LRO polling with 5-minute timeout and 1-second intervals
- Base64 encoding for digests and certificates
- Proper HTTP headers and auth scopes
- Error response parsing

## Dependencies

- `azure_core` + `azure_identity`: Azure SDK authentication
- `reqwest`: HTTP client
- `serde` + `serde_json`: JSON serialization
- `base64`: Base64 encoding for binary data
- `tokio`: Async runtime

## Relationship to Other Crates

This client is designed to be consumed by higher-level COSE signing crates in the workspace, providing the low-level ATS REST API access needed for Azure-backed code signing operations.