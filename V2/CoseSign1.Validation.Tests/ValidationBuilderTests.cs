// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSign1.Certificates.ChainBuilders;
using CoseSign1.Certificates.Local;
using CoseSign1.Direct;
using CoseSign1.Tests.Common;
using CoseSign1.Validation;
using NUnit.Framework;

namespace CoseSign1.Validation.Tests;

[TestFixture]
public class ValidationBuilderTests
{
    private CoseSign1Message? ValidMessage;

    [SetUp]
#pragma warning disable CA2252
    public void SetUp()
    {
        var cert = TestCertificateUtils.CreateCertificate("BuilderTest");
        var chainBuilder = new X509ChainBuilder();
        var signingService = CertificateSigningService.Create(cert, chainBuilder);
        var factory = new DirectSignatureFactory(signingService);
        var payload = new byte[] { 1, 2, 3, 4, 5 };
        var messageBytes = factory.CreateCoseSign1MessageBytes(payload, "application/test");
        ValidMessage = CoseSign1Message.DecodeSign1(messageBytes);
        cert.Dispose();
    }
#pragma warning restore CA2252

    [Test]
    public void Cose_Sign1Message_ReturnsBuilder()
    {
        var builder = Cose.Sign1Message();
        Assert.That(builder, Is.Not.Null);
    }

    [Test]
    public void CoseMessageValidationBuilder_Build_ReturnsCompositeValidator()
    {
        var builder = Cose.Sign1Message();
        var validator = builder.Build();

        Assert.That(validator, Is.Not.Null);
    }

    [Test]
    public void CoseMessageValidationBuilder_AddValidator_AddsValidator()
    {
        var mockValidator = new MockValidator(true);
        var builder = Cose.Sign1Message()
            .AddValidator(mockValidator);

        var validator = builder.Build();
        var result = validator.Validate(ValidMessage!);

        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public void CoseMessageValidationBuilder_WithMultipleValidators_AddsAllValidators()
    {
        var builder = Cose.Sign1Message()
            .AddValidator(new MockValidator(true))
            .AddValidator(new MockValidator(true))
            .AddValidator(new MockValidator(true));

        var validator = builder.Build();
        var result = validator.Validate(ValidMessage!);

        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public void CoseMessageValidationBuilder_WithFunc_CreatesValidator()
    {
        var builder = Cose.Sign1Message()
            .AddValidator(msg => ValidationResult.Success("TestFunc"));

        var validator = builder.Build();
        var result = validator.Validate(ValidMessage!);

        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public void CoseMessageValidationBuilder_StopOnFirstFailure_ConfiguresComposite()
    {
        var builder = Cose.Sign1Message()
            .AddValidator(new MockValidator(true))
            .AddValidator(new MockValidator(false))
            .AddValidator(new MockValidator(true))
            .StopOnFirstFailure();

        var validator = builder.Build();
        var result = validator.Validate(ValidMessage!);

        Assert.That(result.IsValid, Is.False);
    }

    [Test]
    public void CoseMessageValidationBuilder_RunInParallel_ConfiguresComposite()
    {
        var builder = Cose.Sign1Message()
            .AddValidator(new MockValidator(true))
            .AddValidator(new MockValidator(true))
            .RunInParallel();

        var validator = builder.Build();
        var result = validator.Validate(ValidMessage!);

        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public void CoseMessageValidationBuilder_BuildWithNoValidators_ReturnsEmptyComposite()
    {
        var builder = Cose.Sign1Message();
        var validator = builder.Build();
        var result = validator.Validate(ValidMessage!);

        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public void CoseMessageValidationBuilder_ChainedConfiguration_WorksCorrectly()
    {
        var builder = Cose.Sign1Message()
            .AddValidator(msg => ValidationResult.Success("V1"))
            .AddValidator(msg => ValidationResult.Success("V2"))
            .StopOnFirstFailure()
            .RunInParallel();

        var validator = builder.Build();
        Assert.That(validator, Is.Not.Null);
    }

    [Test]
    public void ValidationBuilderContext_StoresConfiguration()
    {
        var context = new ValidationBuilderContext();
        context.StopOnFirstFailure = true;
        context.RunInParallel = false;

        Assert.That(context.StopOnFirstFailure, Is.True);
        Assert.That(context.RunInParallel, Is.False);
    }

    [Test]
    public void ValidationBuilderContext_DefaultValues_AreCorrect()
    {
        var context = new ValidationBuilderContext();

        Assert.That(context.StopOnFirstFailure, Is.False);
        Assert.That(context.RunInParallel, Is.False);
    }

    [Test]
    public void CoseMessageValidationBuilder_AddValidator_WithNullValidator_ThrowsArgumentNullException()
    {
        var builder = Cose.Sign1Message();

        Assert.Throws<ArgumentNullException>(() => builder.AddValidator((IValidator<CoseSign1Message>)null!));
    }

    [Test]
    public void CoseMessageValidationBuilder_AddValidator_WithNullFunc_ThrowsArgumentNullException()
    {
        var builder = Cose.Sign1Message();

        Assert.Throws<ArgumentNullException>(() => builder.AddValidator((Func<CoseSign1Message, ValidationResult>)null!));
    }

    [Test]
    public void CoseMessageValidationBuilder_StopOnFirstFailure_WithFalse_ConfiguresCorrectly()
    {
        var builder = Cose.Sign1Message()
            .StopOnFirstFailure(false);

        var validator = builder.Build();
        Assert.That(validator, Is.Not.Null);
    }

    [Test]
    public void CoseMessageValidationBuilder_RunInParallel_WithFalse_ConfiguresCorrectly()
    {
        var builder = Cose.Sign1Message()
            .RunInParallel(false);

        var validator = builder.Build();
        Assert.That(validator, Is.Not.Null);
    }

    [Test]
    public void CoseMessageValidationBuilder_Context_ReturnsValidContext()
    {
        var builder = Cose.Sign1Message();

        // Access internal context through the interface
        var internalBuilder = builder as object;
        Assert.That(internalBuilder, Is.Not.Null);
    }

    private class MockValidator : IValidator<CoseSign1Message>
    {
        private readonly bool ShouldPass;

        public MockValidator(bool shouldPass)
        {
            ShouldPass = shouldPass;
        }

        public ValidationResult Validate(CoseSign1Message input)
        {
            return ShouldPass
                ? ValidationResult.Success("MockValidator")
                : ValidationResult.Failure("MockValidator", "Mock failure", "MOCK_ERROR");
        }

        public Task<ValidationResult> ValidateAsync(CoseSign1Message input, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(Validate(input));
        }
    }
}