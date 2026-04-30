# CoseSign1.Transparent.MST

Microsoft's Signing Transparency (MST) integration for CoseSignTool V2.

## Overview

CoseSign1.Transparent.MST provides integration with Microsoft's Signing Transparency service, enabling public auditability and non-repudiation for COSE signatures.

## Installation

```bash
dotnet add package CoseSign1.Transparent.MST --version 2.0.0-preview
```

## What is Microsoft's Signing Transparency (MST)?

Microsoft's Signing Transparency (MST) is a transparency service that:

- **Publishes cryptographic commitments** to an append-only log
- **Issues signed receipts** proving inclusion in the log
- **Enables public verification** that artifacts were signed and logged
- **Provides tamper evidence** for signed artifacts

## Quick Start

### Verifying MST Proofs

```csharp
using Azure.Security.CodeTransparency;
using CoseSign1.Transparent.MST;
using System.Security.Cryptography.Cose;

var client = new CodeTransparencyClient(new Uri("https://dataplane.codetransparency.azure.net"));
var provider = new MstTransparencyProvider(client);

// A CoseSign1Message that already contains an MST receipt in its unprotected headers
CoseSign1Message messageWithReceipt = /* ... */;

var result = await provider.VerifyTransparencyProofAsync(messageWithReceipt);
bool isValid = result.IsValid;
```

### CLI Usage

With the MST plugin installed, additional options are available on the `verify` command:

```bash
# Enable MST receipt trust with an explicit ledger allow-list (online verification)
CoseSignTool verify signed.cose \
    --mst-trust \
    --issuer esrp-cts-cp.confidential-ledger.azure.com

# Offline-only verification using pinned keys (no network fallback)
CoseSignTool verify signed.cose \
    --mst-trust \
    --issuer-offline-keys esrp-cts-cp.confidential-ledger.azure.com=esrp-cts-cp.confidential-ledger.azure.com.jwks.json
```

## Verification Options

Advanced verification behavior can be configured via `CodeTransparencyVerificationOptions`.

## MST Receipts

## Trust facts and policy scoping

In V2, MST receipts are modeled as **counter-signature subjects** for the purpose of trust evaluation.
This enables per-receipt trust decisions (a message can contain multiple receipts).

As a result:

- `MstReceiptPresentFact` and `MstReceiptTrustedFact` are **counter-signature-scoped** facts.
- Policies that require receipts should use `TrustPlanPolicy.AnyCounterSignature(...)`.
- The default `AnyCounterSignature` behavior is **deny on empty**, which is a natural way to express “a receipt is required”.

### Receipt Structure

MST receipts contain:

- **Inclusion Proof** - Cryptographic proof the signature is in the log
- **Log Timestamp** - When the entry was added to the log
- **Service Signature** - MST's signature over the receipt

### Embedding Receipts

Receipts can be embedded in COSE signature unprotected headers:

```csharp
// Get receipt from MST
var receipt = await provider.GetReceiptAsync(signature);

// Receipt bytes can be added to unprotected headers
// during signature creation (typically by a transparency provider)
```

## Verification Process

When verifying with MST:

1. **Extract Receipt** - Get MST receipt from signature headers
2. **Verify Receipt Signature** - Confirm MST signed the receipt
3. **Verify Inclusion** - Confirm the signature is in the log
4. **Check Timestamp** - Validate receipt timestamp is acceptable

```
┌─────────────────────────────────────────────────────────┐
│                 MST Verification Flow                    │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  COSE Signature ─┬─► Extract Receipt                     │
│                  │                                       │
│                  ▼                                       │
│           Verify Receipt ─► Check MST Signature          │
│                  │                                       │
│                  ▼                                       │
│           Verify Inclusion ─► Validate Merkle Proof      │
│                  │                                       │
│                  ▼                                       │
│           Check Timestamp ─► Within Acceptable Range     │
│                  │                                       │
│                  ▼                                       │
│             ✓ Valid                                      │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

## Integration with Validators

Add MST validation to the V2 validation pipeline:

```csharp
using CoseSign1.Certificates.Trust.Facts;
using CoseSign1.Transparent.MST.Trust;
using CoseSign1.Validation;
using CoseSign1.Validation.DependencyInjection;
using CoseSign1.Validation.Trust;
using Microsoft.Extensions.DependencyInjection;
using System.Security.Cryptography.Cose;

var mstEndpoint = new Uri("https://dataplane.codetransparency.azure.net");

var services = new ServiceCollection();
var validation = services.ConfigureCoseValidation();

// MST receipts are typically attached to X.509-backed signatures.
validation.EnableCertificateSupport(certTrust => certTrust
    .UseSystemTrust()
    );

// Enable MST receipt verification (online).
validation.EnableMstSupport(mst => mst.VerifyReceipts(mstEndpoint));

// Require an MST receipt (and require that at least one receipt verifies).
var trustPolicy = TrustPlanPolicy.AnyCounterSignature(cs => cs
        .RequireFact<MstReceiptPresentFact>(f => f.IsPresent, "MST receipt is required")
        .RequireFact<MstReceiptTrustedFact>(f => f.IsTrusted, "MST receipt must be trusted"))
    .And(
        TrustPlanPolicy.PrimarySigningKey(k => k
            .RequireFact<X509ChainTrustedFact>(f => f.IsTrusted, "Signing certificate chain must be trusted")));

services.AddSingleton<CompiledTrustPlan>(sp => trustPolicy.Compile(sp));

using var sp = services.BuildServiceProvider();
using var scope = sp.CreateScope();

var validator = scope.ServiceProvider
    .GetRequiredService<ICoseSign1ValidatorFactory>()
    .Create();

CoseSign1Message message = /* ... */;
var result = message.Validate(validator);

if (result.Overall.IsValid)
{
    Console.WriteLine("MST receipt verified!");
}
```

### Online Receipt Verification

For online verification that fetches current signing keys from the service:

```csharp
var services = new ServiceCollection();
var validation = services.ConfigureCoseValidation();

validation.EnableCertificateSupport(certTrust => certTrust
    .UseSystemTrust()
    );

validation.EnableMstSupport(mst => mst.VerifyReceipts(new Uri("https://dataplane.codetransparency.azure.net")));

var trustPolicy = TrustPlanPolicy.AnyCounterSignature(cs => cs
    .RequireFact<MstReceiptPresentFact>(f => f.IsPresent, "MST receipt is required")
    .RequireFact<MstReceiptTrustedFact>(f => f.IsTrusted, "MST receipt must be trusted"));

services.AddSingleton<CompiledTrustPlan>(sp => trustPolicy.Compile(sp));

using var sp = services.BuildServiceProvider();
using var scope = sp.CreateScope();

var validator = scope.ServiceProvider
    .GetRequiredService<ICoseSign1ValidatorFactory>()
    .Create();
```

## Performance Optimization

### TransactionNotCached Fast Retry

The Azure Code Transparency Service returns HTTP 503 with a `Retry-After: 1` header when a newly
registered entry has not yet propagated to the serving node. The Azure SDK respects this header,
causing unnecessary 1-second delays per retry. The `MstPerformanceOptimizationPolicy` solves this
by performing fast retries (default: 250 ms × 8 attempts ≈ 2 seconds) and stripping all
`Retry-After` headers from `/entries/` and `/operations/` responses.

#### Quick Setup

```csharp
using Azure.Security.CodeTransparency;

var options = new CodeTransparencyClientOptions();
options.ConfigureMstPerformanceOptimizations();  // default: 250 ms delay, 8 retries
var client = new CodeTransparencyClient(endpoint, credential, options);
```

#### Custom Timing

```csharp
options.ConfigureMstPerformanceOptimizations(
    retryDelay: TimeSpan.FromMilliseconds(100),  // faster retries
    maxRetries: 16);                              // longer window
```

#### Manual Registration

```csharp
var policy = new MstPerformanceOptimizationPolicy(
    TimeSpan.FromMilliseconds(100), maxRetries: 8);
options.AddPolicy(policy, HttpPipelinePosition.PerRetry);
```

#### Observability

The policy emits `System.Diagnostics.Activity` spans under the source name
`CoseSign1.Transparent.MST.PerformanceOptimizationPolicy`. Activities include:

| Activity | Emitted when |
|---|---|
| `MstPerformanceOptimization.Evaluate` | Every response (tags: action, status, url) |
| `MstPerformanceOptimization.AcceleratedRetry` | 503 on `/entries/` triggers fast retry |
| `MstPerformanceOptimization.RetryAttempt` | Each individual retry attempt |

### LRO Polling Optimization

For long-running operations (CreateEntry), configure aggressive polling via `MstPollingOptions`:

```csharp
var pollingOptions = new MstPollingOptions
{
    DelayStrategy = DelayStrategy.CreateFixedDelayStrategy(TimeSpan.FromMilliseconds(100))
};
```

Combining both optimizations typically reduces end-to-end transparency registration
from ~3 seconds to ~600 ms.

## Security Considerations

- **Trust** - Ensure you trust the MST service endpoint
- **Timestamp Validation** - Consider acceptable timestamp ranges
- **Network Security** - Use HTTPS and validate certificates
- **Caching** - Be cautious about caching receipt verifications

## Error Handling

```csharp
try
{
    var result = await provider.VerifyTransparencyProofAsync(messageWithReceipt);
}
catch (Azure.RequestFailedException ex)
{
    Console.WriteLine($"MST service error: {ex.Message}");
}
```

## See Also

- [Transparency Overview](transparent.md)
- [SCITT Compliance](../guides/scitt-compliance.md)
- [MST Plugin](../plugins/mst-plugin.md)
- [Validation Framework](../architecture/validation-framework.md)
