// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Tests.Extensions;

using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using CoseSign1.Validation.Interfaces;
using CoseSign1.Validation.Results;
using CoseSign1.Validation.Trust.Engine;
using CoseSign1.Validation.Trust.Plan;
using CoseSign1.Validation.Trust.Rules;

[TestFixture]
public sealed class CoseSign1MessageValidationExtensionsTests
{
    private static readonly byte[] Payload = "validation extensions"u8.ToArray();

    private sealed class TestValidator : ICoseSign1Validator
    {
        private readonly CoseSign1ValidationResult Result;

        public TestValidator(CoseSign1ValidationResult result)
        {
            Result = result;
        }

        public bool ValidateCalled { get; private set; }

        public bool ValidateAsyncCalled { get; private set; }

        public CompiledTrustPlan TrustPlan { get; } = new(TrustRules.AllowAll(), Array.Empty<IMultiTrustFactProducer>());

        public CoseSign1ValidationResult Validate(CoseSign1Message message)
        {
            ValidateCalled = true;
            return Result;
        }

        public Task<CoseSign1ValidationResult> ValidateAsync(CoseSign1Message message, CancellationToken cancellationToken = default)
        {
            ValidateAsyncCalled = true;
            return Task.FromResult(Result);
        }
    }

    private static CoseSign1Message CreateMessage()
    {
        using var key = ECDsa.Create();
        var signer = new CoseSigner(key, HashAlgorithmName.SHA256);
        byte[] signedBytes = CoseSign1Message.SignDetached(Payload, signer, ReadOnlySpan<byte>.Empty);
        return CoseMessage.DecodeSign1(signedBytes);
    }

    private static CoseSign1ValidationResult CreateResult(string name)
    {
        var ok = ValidationResult.Success(name);
        return new CoseSign1ValidationResult(ok, ok, ok, ok, ok);
    }

    [Test]
    public void Validate_WithValidator_DelegatesToValidator()
    {
        var message = CreateMessage();
        var expected = CreateResult("sync");
        var validator = new TestValidator(expected);

        var result = message.Validate(validator);

        Assert.That(validator.ValidateCalled, Is.True);
        Assert.That(result, Is.SameAs(expected));
    }

    [Test]
    public async Task ValidateAsync_WithValidator_DelegatesToValidator()
    {
        var message = CreateMessage();
        var expected = CreateResult("async");
        var validator = new TestValidator(expected);

        var result = await message.ValidateAsync(validator, CancellationToken.None);

        Assert.That(validator.ValidateAsyncCalled, Is.True);
        Assert.That(result, Is.SameAs(expected));
    }

    [Test]
    public void Validate_WithNullValidator_ThrowsArgumentNullException()
    {
        var message = CreateMessage();

        Assert.Throws<ArgumentNullException>(() => message.Validate((ICoseSign1Validator)null!));
    }

    [Test]
    public void Validate_WithNullMessage_ThrowsArgumentNullException()
    {
        var validator = new TestValidator(CreateResult("x"));

        Assert.Throws<ArgumentNullException>(() => ((CoseSign1Message)null!).Validate(validator));
    }
}
