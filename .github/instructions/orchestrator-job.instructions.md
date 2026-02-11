---
applyTo: '.worktrees/3b3aaaab/**'
---

# Current Task

# Implement Post-Sign Verification in DirectSignatureFactory

## Context
DirectSignatureFactory creates COSE Sign1 messages. After signing, we must verify the signature before returning to ensure cryptographic validity.

## Task
Modify V2/CoseSign1.Factories/Direct/DirectSignatureFactory.cs to verify signatures after creation.

## Implementation Steps

1. After calling CoseSign1Message.SignEmbedded or SignDetached, call SigningService.VerifySignature
2. If verification fails, throw SignatureVerificationException with the operation ID
3. Add logging for post-sign verification (Debug level for start/success, Error for failure)

## Code Pattern
```csharp
// After signing:
var message = options.EmbedPayload
    ? CoseSign1Message.SignEmbedded(payload, signer, additionalDataSpan)
    : CoseSign1Message.SignDetached(payload, signer, additionalDataSpan);

// Add verification:
Logger.LogDebug(LogEvents.PostSignVerificationStarted, "Verifying created signature");
if (!SigningService.VerifySignature(CoseSign1Message.DecodeSign1(message), context))
{
    Logger.LogError(LogEvents.PostSignVerificationFailed, "Post-sign verification failed");
    throw new SignatureVerificationException(
        "The created signature failed post-sign verification.",
        operationId);
}
Logger.LogDebug(LogEvents.PostSignVerificationSucceeded, "Post-sign verification succeeded");
```

4. Add log event IDs to LogEvents in CoseSign1.Factories/Logging/LogEvents.cs:
   - PostSignVerificationStarted = new EventId(1010, ...)
   - PostSignVerificationSucceeded = new EventId(1011, ...)
   - PostSignVerificationFailed = new EventId(1012, ...)

5. Apply to ALL signing methods (sync and async)

## Files to modify
- V2/CoseSign1.Factories/Direct/DirectSignatureFactory.cs
- V2/CoseSign1.Factories/Logging/LogEvents.cs (add event IDs)

## Verification
Run: dotnet test V2/CoseSign1.Factories.Tests/CoseSign1.Factories.Tests.csproj --filter "FullyQualifiedName~DirectSignatureFactory"



## Guidelines

- Focus only on the task described above
- Make minimal, targeted changes
- Follow existing code patterns and conventions in this repository
- Commit your changes when complete
