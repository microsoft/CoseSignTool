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
public class CompositeValidatorTests
{
    private CoseSign1Message? ValidMessage;

    [SetUp]
#pragma warning disable CA2252
    public void SetUp()
    {
        var cert = TestCertificateUtils.CreateCertificate("CompositeTest");
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
    public void Constructor_WithValidValidators_CreatesInstance()
    {
        var validators = new List<IValidator<CoseSign1Message>>
        {
            new MockValidator(true),
            new MockValidator(true)
        };

        var composite = new CompositeValidator(validators);
        Assert.That(composite, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithNullValidators_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => new CompositeValidator(null!));
    }

    [Test]
    public void Validate_WithNullInput_ReturnsFailure()
    {
        var validators = new List<IValidator<CoseSign1Message>> { new MockValidator(true) };
        var composite = new CompositeValidator(validators);

        var result = composite.Validate(null!);

        Assert.That(result.IsValid, Is.False);
        Assert.That(result.ValidatorName, Is.EqualTo("CompositeValidator"));
        Assert.That(result.Failures.Any(f => f.ErrorCode == "NULL_INPUT"), Is.True);
    }

    [Test]
    public void Validate_WithEmptyValidators_ReturnsSuccess()
    {
        var composite = new CompositeValidator(new List<IValidator<CoseSign1Message>>());

        var result = composite.Validate(ValidMessage!);

        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public void Validate_WithAllPassingValidators_ReturnsSuccess()
    {
        var validators = new List<IValidator<CoseSign1Message>>
        {
            new MockValidator(true),
            new MockValidator(true),
            new MockValidator(true)
        };
        var composite = new CompositeValidator(validators);

        var result = composite.Validate(ValidMessage!);

        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public void Validate_WithOneFailingValidator_ReturnsFailure()
    {
        var validators = new List<IValidator<CoseSign1Message>>
        {
            new MockValidator(true),
            new MockValidator(false),
            new MockValidator(true)
        };
        var composite = new CompositeValidator(validators);

        var result = composite.Validate(ValidMessage!);

        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures.Count, Is.GreaterThan(0));
    }

    [Test]
    public void Validate_WithStopOnFirstFailure_StopsAtFirstFailure()
    {
        var validator1 = new MockValidator(true);
        var validator2 = new MockValidator(false);
        var validator3 = new MockValidator(true);

        var validators = new List<IValidator<CoseSign1Message>> { validator1, validator2, validator3 };
        var composite = new CompositeValidator(validators, stopOnFirstFailure: true);

        var result = composite.Validate(ValidMessage!);

        Assert.That(result.IsValid, Is.False);
        Assert.That(validator1.WasCalled, Is.True);
        Assert.That(validator2.WasCalled, Is.True);
        Assert.That(validator3.WasCalled, Is.False); // Should not be called
    }

    [Test]
    public void Validate_WithoutStopOnFirstFailure_RunsAllValidators()
    {
        var validator1 = new MockValidator(false);
        var validator2 = new MockValidator(false);
        var validator3 = new MockValidator(true);

        var validators = new List<IValidator<CoseSign1Message>> { validator1, validator2, validator3 };
        var composite = new CompositeValidator(validators, stopOnFirstFailure: false);

        var result = composite.Validate(ValidMessage!);

        Assert.That(result.IsValid, Is.False);
        Assert.That(validator1.WasCalled, Is.True);
        Assert.That(validator2.WasCalled, Is.True);
        Assert.That(validator3.WasCalled, Is.True); // Should be called
    }

    [Test]
    public void Validate_AggregatesFailuresFromMultipleValidators()
    {
        var validators = new List<IValidator<CoseSign1Message>>
        {
            new MockValidator(false, "Error1"),
            new MockValidator(false, "Error2"),
            new MockValidator(false, "Error3")
        };
        var composite = new CompositeValidator(validators);

        var result = composite.Validate(ValidMessage!);

        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures.Count, Is.EqualTo(3));
    }

    [Test]
    public async Task ValidateAsync_WithValidInput_ReturnsSuccess()
    {
        var validators = new List<IValidator<CoseSign1Message>>
        {
            new MockValidator(true),
            new MockValidator(true)
        };
        var composite = new CompositeValidator(validators);

        var result = await composite.ValidateAsync(ValidMessage!);

        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public async Task ValidateAsync_WithCancellationToken_CompletesSuccessfully()
    {
        var validators = new List<IValidator<CoseSign1Message>> { new MockValidator(true) };
        var composite = new CompositeValidator(validators);
        using var cts = new CancellationTokenSource();

        var result = await composite.ValidateAsync(ValidMessage!, cts.Token);

        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public void Validate_MergesMetadataFromSuccessfulValidators()
    {
        var validator1 = new MockValidator(true, metadata: new Dictionary<string, object> { ["Key1"] = "Value1" });
        var validator2 = new MockValidator(true, metadata: new Dictionary<string, object> { ["Key2"] = "Value2" });

        var validators = new List<IValidator<CoseSign1Message>> { validator1, validator2 };
        var composite = new CompositeValidator(validators);

        var result = composite.Validate(ValidMessage!);

        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Metadata.Count, Is.GreaterThan(0));
    }

    // Mock validator for testing
    private class MockValidator : IValidator<CoseSign1Message>
    {
        private readonly bool ShouldPass;
        private readonly string ErrorMessage;
        private readonly Dictionary<string, object>? Metadata;
        public bool WasCalled { get; private set; }

        public MockValidator(bool shouldPass, string errorMessage = "Mock error", Dictionary<string, object>? metadata = null)
        {
            ShouldPass = shouldPass;
            ErrorMessage = errorMessage;
            Metadata = metadata;
        }

        public ValidationResult Validate(CoseSign1Message input)
        {
            WasCalled = true;

            if (ShouldPass)
            {
                return ValidationResult.Success("MockValidator", Metadata);
            }

            return ValidationResult.Failure("MockValidator", ErrorMessage, "MOCK_ERROR");
        }

        public Task<ValidationResult> ValidateAsync(CoseSign1Message input, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(Validate(input));
        }
    }
}