// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Tests;

using CoseSign1.Abstractions;
using CoseSign1.Validation.Interfaces;
using System.Security.Cryptography.Cose;

public sealed class CounterSignatureResolutionResultTests
{
    private sealed class StubSigningKey : ISigningKey
    {
        public CoseKey GetCoseKey() => throw new NotSupportedException("Test stub.");

        public void Dispose()
        {
            // No-op.
        }
    }

    private sealed class TestCounterSignature : ICounterSignature
    {
        public TestCounterSignature(byte[] rawCounterSignatureBytes, bool isProtectedHeader, ISigningKey signingKey)
        {
            RawCounterSignatureBytes = rawCounterSignatureBytes;
            IsProtectedHeader = isProtectedHeader;
            SigningKey = signingKey;
        }

        public byte[] RawCounterSignatureBytes { get; }

        public bool IsProtectedHeader { get; }

        public ISigningKey SigningKey { get; }
    }

    [Test]
    public void Success_WhenNullCounterSignature_ThrowsArgumentNullException()
    {
        Assert.That(() => CounterSignatureResolutionResult.Success(null!), Throws.ArgumentNullException);
    }

    [Test]
    public void Success_SetsIsSuccessAndCounterSignature()
    {
        var counterSignature = new TestCounterSignature([1, 2, 3], isProtectedHeader: true, new StubSigningKey());

        var result = CounterSignatureResolutionResult.Success(counterSignature);

        Assert.That(result.IsSuccess, Is.True);
        Assert.That(result.CounterSignature, Is.SameAs(counterSignature));
        Assert.That(result.ErrorCode, Is.Null);
        Assert.That(result.ErrorMessage, Is.Null);
    }

    [Test]
    public void Failure_SetsProperties_AndDefaultsDiagnosticsToEmpty()
    {
        var result = CounterSignatureResolutionResult.Failure("oops", errorCode: "E123");

        Assert.That(result.IsSuccess, Is.False);
        Assert.That(result.CounterSignature, Is.Null);
        Assert.That(result.ErrorMessage, Is.EqualTo("oops"));
        Assert.That(result.ErrorCode, Is.EqualTo("E123"));
        Assert.That(result.Diagnostics, Is.Empty);
    }

    [Test]
    public void Failure_PreservesDiagnosticsInstance()
    {
        IReadOnlyList<string> diagnostics = new[] { "d1", "d2" };

        var result = CounterSignatureResolutionResult.Failure("oops", diagnostics: diagnostics);

        Assert.That(result.IsSuccess, Is.False);
        Assert.That(result.Diagnostics, Is.SameAs(diagnostics));
    }
}
