# CoseSign1.Tests.Common

Shared test utilities for the V2 test projects.

## What’s Included

- `LocalCertificateFactory`: Create in-memory RSA/ECDSA/ML-DSA certificates and chains.
- `TestCertificateUtils`: Create certificates/chains with more knobs (SAN/EKU/issuer, ordering, etc.).
- `PlatformHelper`: Platform detection and test skipping helpers.

## Certificate Generation

### Single Certificates

```csharp
using CoseSign1.Tests.Common;

using var rsaCert = LocalCertificateFactory.CreateRsaCertificate();
using var ecdsaCert = LocalCertificateFactory.CreateEcdsaCertificate();
```

### Certificate Chains

```csharp
using CoseSign1.Tests.Common;
using System.Security.Cryptography.X509Certificates;

X509Certificate2Collection chain = LocalCertificateFactory.CreateEcdsaChain(leafFirst: true);
X509Certificate2 leaf = chain[0];
```

## Platform-Specific Tests

The repository uses NUnit for V2 tests.

```csharp
using CoseSign1.Tests.Common;

// Skip current test if ML-DSA isn't supported on this OS/runtime.
PlatformHelper.SkipIfMLDsaNotSupported();
```

## Example: Sign and Validate

```csharp
using System.Security.Cryptography.Cose;
using System.Text;
using CoseSign1.Certificates;
using CoseSign1.Certificates.Local;
using CoseSign1.Direct;
using CoseSign1.Tests.Common;
using CoseSign1.Validation;
using NUnit.Framework;

[TestFixture]
public class SigningTests
{
    [Test]
    public async Task SignAndValidate_Succeeds()
    {
        using var cert = LocalCertificateFactory.CreateEcdsaCertificate();
        var signingService = CertificateSigningService.Create(cert, new X509ChainBuilder());
        using var factory = new DirectSignatureFactory(signingService);

        var payload = Encoding.UTF8.GetBytes("hello");
        var coseBytes = factory.CreateCoseSign1MessageBytes(payload, "text/plain");
        var message = CoseMessage.DecodeSign1(coseBytes);

        var validator = Cose.Sign1Message()
            .AddCertificateValidator(b => b.ValidateSignature())
            .Build();

        var result = await validator.ValidateAsync(message);
        Assert.That(result.IsValid, Is.True);
    }
}
```

## See Also

- [Testing Guide](../guides/testing.md)
- [Development Testing](../development/testing.md)
- [Code Coverage](../development/coverage.md)
