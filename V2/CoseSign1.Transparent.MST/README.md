# CoseSign1.Transparent.MST

Microsoft's Signing Transparency (MST) receipt support for COSE Sign1 message verification.

## Overview

This package enables verification of MST receipts embedded in COSE Sign1 messages (SCITT receipts).

In V2, MST receipts are modeled as **counter-signatures** for trust evaluation purposes. This enables:

- Trust decisions expressed as `TrustPlanPolicy` rules (facts + rules).
- Receipt verification scoped to an individual receipt (counter-signature subject).
- Optional **ToBeSigned attestation**: when a receipt is verified and attests it validated the same COSE `Sig_structure`, staged validation can skip primary signing-key resolution and primary signature verification.

## Installation

```bash
dotnet add package CoseSign1.Transparent.MST --version 2.0.0-preview
```

## What this package does (and doesn’t)

- ✅ Verifies MST receipts embedded in COSE Sign1 messages.
- ✅ Contributes a trust pack (`ITrustPack`) with MST receipt facts.
- ✅ Contributes a counter-signature resolver (to discover receipts from the message).
- ✅ Contributes a ToBeSigned attestor (optional staged-validation optimization).
- ❌ Does not submit messages to an MST service or “generate receipts”. (Receipt acquisition happens elsewhere.)

## Quick Start

### Verify a COSE Sign1 message that includes MST receipts (online)

This example opts into MST support (`EnableMstSupport`) and then expresses trust decisions via a `TrustPlanPolicy`.

```csharp
using System.Security.Cryptography.Cose;
using CoseSign1.Transparent.MST.Trust;
using CoseSign1.Validation;
using CoseSign1.Validation.DependencyInjection;
using CoseSign1.Validation.Interfaces;
using CoseSign1.Validation.Trust.Plan;
using Microsoft.Extensions.DependencyInjection;

// Decode a COSE_Sign1 / SCITT statement (bytes include MST receipt header label 394).
var message = CoseMessage.DecodeSign1(File.ReadAllBytes("statement.scitt"));

var services = new ServiceCollection();
var builder = services.ConfigureCoseValidation();

// Enable MST receipt support and configure online verification.
builder.EnableMstSupport(mst => mst.VerifyReceipts(new Uri("https://dataplane.codetransparency.azure.net")));

using var sp = services.BuildServiceProvider();

// Trust decisions live in policy (not in module configuration).
const string expectedIssuerHost = "esrp-cts-cp.confidential-ledger.azure.com";
var policy = TrustPlanPolicy.AnyCounterSignature(cs => cs
    .RequireFact<MstReceiptPresentFact>(f => f.IsPresent, "MST receipt must be present")
    .RequireFact<MstReceiptTrustedFact>(f => f.IsTrusted, "MST receipt must be verified")
    .RequireFact<MstReceiptIssuerHostFact>(
        f => f.Hosts.Any(h => string.Equals(h, expectedIssuerHost, StringComparison.OrdinalIgnoreCase)),
        $"MST receipt issuer host must be {expectedIssuerHost}"));

var trustPlan = policy.Compile(sp);

var validator = new CoseSign1Validator(
    signingKeyResolvers: sp.GetServices<ISigningKeyResolver>(),
    postSignatureValidators: sp.GetServices<IPostSignatureValidator>(),
    toBeSignedAttestors: sp.GetServices<IToBeSignedAttestor>(),
    trustPlan: trustPlan,
    options: new CoseSign1ValidationOptions
    {
        // When the MST receipt validates the same Sig_structure, staged validation can skip
        // primary key resolution + primary signature verification.
        AllowToBeSignedAttestationToSkipPrimarySignature = true,
    });

var result = await validator.ValidateAsync(message);

if (!result.Overall.IsSuccess)
{
    throw new InvalidOperationException("Validation failed: " + result.Overall.Failures[0].Message);
}

// Optional: assert the attestation shortcut happened.
Console.WriteLine($"Resolution stage: {result.Resolution.Kind}");
Console.WriteLine($"Signature stage:  {result.Signature.Kind}");
```

### Verify with pinned offline keys (no network)

If you have a pinned JWKS for the expected MST issuer, you can run in offline-only mode.

```csharp
using CoseSign1.Transparent.MST.Trust;
using CoseSign1.Validation.DependencyInjection;
using Microsoft.Extensions.DependencyInjection;

var jwksJson = File.ReadAllText("esrp-cts-cp.confidential-ledger.azure.com.jwks.json");

var services = new ServiceCollection();
var builder = services.ConfigureCoseValidation();

builder.EnableMstSupport(mst => mst.UseOfflineTrustedJwksJson(jwksJson));
```

Pair offline verification with an issuer-host requirement in policy (as shown above) to avoid trusting arbitrary receipts.

## Notes on trust and policy

- `EnableMstSupport(...)` enables the *capability* (receipt discovery + verification + fact production).
- `TrustPlanPolicy` expresses *trust decisions* (which receipts/issuers are acceptable).
- For “real-world” safety, combine:
  - `MstReceiptTrustedFact` (receipt must verify), and
  - `MstReceiptIssuerHostFact` (issuer identity constraint).

## When to Use

- ✅ SCITT compliance and transparency
- ✅ Verifiable transparency logs
- ✅ Supply chain auditability
- ✅ Immutable record keeping
- ✅ Provenance tracking
- ✅ Compliance requirements

## Related Packages

- **CoseSign1.Factories** - Message creation
- **CoseSign1.Validation** - Validation framework
- **CoseSign1.Certificates** - Certificate-based signing

## Documentation

- 📖 V2 docs overview: https://github.com/microsoft/CoseSignTool/blob/main/V2/docs/README.md
- 📖 MST component guide: https://github.com/microsoft/CoseSignTool/blob/main/V2/docs/components/mst.md
- 📖 Trust plan deep dive: https://github.com/microsoft/CoseSignTool/blob/main/V2/docs/guides/trust-policy.md
- 📖 SCITT guide: https://github.com/microsoft/CoseSignTool/blob/main/V2/docs/guides/scitt-compliance.md

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
