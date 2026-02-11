---
applyTo: '.worktrees/ab1b6320/**'
---

# Current Task

# Update Test Mock Implementations

## Context
Adding VerifySignature to ISigningService requires updating all mock/test implementations.

## Task
Search for and update all test implementations of ISigningService.

## Steps
1. Search for: `: ISigningService<` in V2/**/*.cs
2. For each test/mock implementation found, add:
```csharp
public bool VerifySignature(CoseSign1Message message, SigningContext context)
{
    return true; // Default: verification passes for tests
}
```

## Known locations (verify and update):
- V2/CoseSignTool.Tests/Commands/Builders/SigningCommandBuilderTests.cs
- V2/CoseSign1.Certificates.Tests/Local/DirectCertificateSourceTests.cs
- V2/CoseSign1.Certificates.Tests/Trust/X509CertificateTrustPackDispatchTests.cs
- V2/CoseSign1.Certificates.Tests/Trust/X509CertificateTrustPackProducerTests.cs
- V2/CoseSign1.Certificates.Tests/Remote/RemoteSigningTests.cs
- V2/CoseSign1.Integration.Tests/ (any test signing services)

## Also update any overrides:
Search for `override.*GetSigningKey` and ensure access modifiers match if the base changed.

## Verification
Run: dotnet build V2/CoseSignToolV2.sln



## Guidelines

- Focus only on the task described above
- Make minimal, targeted changes
- Follow existing code patterns and conventions in this repository
- Commit your changes when complete
