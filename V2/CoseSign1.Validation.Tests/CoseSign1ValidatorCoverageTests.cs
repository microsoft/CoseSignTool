// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Tests;

using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using CoseSign1.Validation.Interfaces;
using CoseSign1.Validation.Results;

[TestFixture]
public class CoseSign1VerifierCoverageTests
{
    [Test]
    public void Verify_WhenMessageNull_Throws()
    {
        Assert.That(
                () => CoseSign1Validator.Validate(
                message: null!,
                validators: Array.Empty<IValidator>(),
                trustPolicy: TrustPolicy.AllowAll()),
            Throws.ArgumentNullException);
    }

    [Test]
    public void Verify_WhenValidatorsNull_Throws()
    {
        Assert.That(
                () => CoseSign1Validator.Validate(
                message: CreateMessage(),
                validators: null!,
                trustPolicy: TrustPolicy.AllowAll()),
            Throws.ArgumentNullException);
    }

    [Test]
    public void Verify_WhenTrustPolicyNull_Throws()
    {
        Assert.That(
                () => CoseSign1Validator.Validate(
                message: CreateMessage(),
                validators: new[] { new FixedValidator("Sig", ValidationStage.Signature, FixedResultKind.Success) },
                trustPolicy: null!),
            Throws.ArgumentNullException);
    }

    [Test]
    public void Verify_WhenNoSignatureValidatorsConfigured_Throws()
    {
        Assert.That(
                () => CoseSign1Validator.Validate(
                message: CreateMessage(),
                validators: Array.Empty<IValidator>(),
                trustPolicy: TrustPolicy.AllowAll()),
            Throws.TypeOf<InvalidOperationException>());
    }

    [Test]
    public void Verify_WhenResolutionFails_ShortCircuitsLaterStages()
    {
        var result = CoseSign1Validator.Validate(
                message: CreateMessage(),
            validators: new IValidator[]
            {
                new FixedValidator("Res", ValidationStage.KeyMaterialResolution, FixedResultKind.Failure),
                new FixedValidator("Sig", ValidationStage.Signature, FixedResultKind.Success)
            },
            trustPolicy: TrustPolicy.AllowAll());

        Assert.That(result.Resolution.IsFailure, Is.True);
        Assert.That(result.Trust.IsNotApplicable, Is.True);
        Assert.That(result.Signature.IsNotApplicable, Is.True);
        Assert.That(result.PostSignaturePolicy.IsNotApplicable, Is.True);
        Assert.That(result.Overall, Is.SameAs(result.Resolution));
    }

    [Test]
    public void Verify_WhenTrustValidatorHardFails_ShortCircuitsLaterStages()
    {
        var result = CoseSign1Validator.Validate(
                message: CreateMessage(),
            validators: new IValidator[]
            {
                new FixedValidator("TrustV", ValidationStage.KeyMaterialTrust, FixedResultKind.Failure),
                new FixedValidator("Sig", ValidationStage.Signature, FixedResultKind.Success)
            },
            trustPolicy: TrustPolicy.AllowAll());

        Assert.That(result.Resolution.IsValid, Is.True);
        Assert.That(result.Trust.IsFailure, Is.True);
        Assert.That(result.Signature.IsNotApplicable, Is.True);
        Assert.That(result.PostSignaturePolicy.IsNotApplicable, Is.True);
        Assert.That(result.Overall, Is.SameAs(result.Trust));
    }

    [Test]
    public void Verify_WhenTrustPolicyNotSatisfied_AndExplainIsSilent_UsesGenericFailureMessage()
    {
        var trustValidator = new FixedValidator(
            "TrustV",
            ValidationStage.KeyMaterialTrust,
            FixedResultKind.Success,
            new Dictionary<string, object>
            {
                [TrustAssertionMetadata.AssertionsKey] = new[]
                {
                    new TrustAssertion("a", satisfied: false)
                }
            });

        var result = CoseSign1Validator.Validate(
                message: CreateMessage(),
            validators: new IValidator[]
            {
                trustValidator,
                new FixedValidator("Sig", ValidationStage.Signature, FixedResultKind.Success)
            },
            trustPolicy: new SilentDenyTrustPolicy());

        Assert.That(result.Trust.IsFailure, Is.True);
        Assert.That(result.Trust.Failures, Has.Count.EqualTo(1));
        Assert.That(result.Trust.Failures[0].ErrorCode, Is.EqualTo("TRUST_POLICY_NOT_SATISFIED"));
        Assert.That(result.Trust.Failures[0].Message, Is.EqualTo("Trust policy was not satisfied"));
    }

    [Test]
    public void Verify_WhenTrustPolicyNotSatisfied_AndExplainProvidesReasons_UsesThoseReasons()
    {
        var trustValidator = new FixedValidator(
            "TrustV",
            ValidationStage.KeyMaterialTrust,
            FixedResultKind.Success,
            new Dictionary<string, object>
            {
                [TrustAssertionMetadata.AssertionsKey] = new[]
                {
                    new TrustAssertion("required", satisfied: false)
                }
            });

        var result = CoseSign1Validator.Validate(
                message: CreateMessage(),
            validators: new IValidator[]
            {
                trustValidator,
                new FixedValidator("Sig", ValidationStage.Signature, FixedResultKind.Success)
            },
            trustPolicy: TrustPolicy.Claim("required"));

        Assert.That(result.Trust.IsFailure, Is.True);
        Assert.That(result.Trust.Failures, Has.Count.GreaterThanOrEqualTo(1));
        Assert.That(result.Trust.Failures.Select(f => f.ErrorCode), Does.Contain("TRUST_POLICY_NOT_SATISFIED"));
        Assert.That(result.Trust.Failures.Select(f => f.Message), Has.Some.Contains("required"));
    }

    [Test]
    public void Verify_WhenAllStagesSucceed_MergesStageMetadata()
    {
        var resolutionValidator = new FixedValidator(
            "ResV",
            ValidationStage.KeyMaterialResolution,
            FixedResultKind.Success,
            new Dictionary<string, object> { ["k"] = "v" });

        var trustValidator = new FixedValidator(
            "TrustV",
            ValidationStage.KeyMaterialTrust,
            FixedResultKind.Success,
            new Dictionary<string, object>
            {
                [TrustAssertionMetadata.AssertionsKey] = new[]
                {
                    new TrustAssertion("trusted", satisfied: true)
                },
                ["extra"] = 123
            });

        var signatureValidator = new FixedValidator(
            "SigV",
            ValidationStage.Signature,
            FixedResultKind.Success,
            new Dictionary<string, object> { ["sig"] = true });

        var postValidator = new FixedValidator(
            "PostV",
            ValidationStage.PostSignature,
            FixedResultKind.Success,
            new Dictionary<string, object> { ["post"] = 1 });

        var result = CoseSign1Validator.Validate(
                message: CreateMessage(),
            validators: new IValidator[] { resolutionValidator, trustValidator, signatureValidator, postValidator },
            trustPolicy: TrustPolicy.Claim("trusted"));

        Assert.That(result.Overall.IsValid, Is.True);
        Assert.That(result.Overall.Metadata.Keys, Has.Some.EqualTo("Resolution.ResV.k"));
        Assert.That(result.Overall.Metadata.Keys, Has.Some.EqualTo("Signature.sig"));
        Assert.That(result.Overall.Metadata.Keys, Has.Some.EqualTo("Post.PostV.post"));
        Assert.That(result.Overall.Metadata.Keys, Has.Some.EndsWith("TrustV." + TrustAssertionMetadata.AssertionsKey));
    }

    private static CoseSign1Message CreateMessage()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signer = new CoseSigner(key, HashAlgorithmName.SHA256);
        var payload = System.Text.Encoding.UTF8.GetBytes("payload");
        var encoded = CoseSign1Message.SignEmbedded(payload, signer);
        return CoseSign1Message.DecodeSign1(encoded);
    }

    private enum FixedResultKind
    {
        Success,
        Failure
    }

    private sealed class FixedValidator : IValidator
    {
        private readonly string Name;
        private readonly ValidationStage Stage;
        private readonly FixedResultKind Kind;
        private readonly IDictionary<string, object>? Metadata;

        public FixedValidator(string name, ValidationStage stage, FixedResultKind kind, IDictionary<string, object>? metadata = null)
        {
            Name = name;
            Stage = stage;
            Kind = kind;
            Metadata = metadata;
        }

        public IReadOnlyCollection<ValidationStage> Stages => new[] { Stage };

        public ValidationResult Validate(CoseSign1Message input, ValidationStage stage)
        {
            if (stage != Stage)
            {
                return ValidationResult.NotApplicable(Name, stage);
            }

            return Kind switch
            {
                FixedResultKind.Success => ValidationResult.Success(Name, stage, Metadata),
                FixedResultKind.Failure => ValidationResult.Failure(Name, stage, "failure", "FAIL"),
                _ => throw new InvalidOperationException("Unknown kind")
            };
        }

        public Task<ValidationResult> ValidateAsync(CoseSign1Message input, ValidationStage stage, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(Validate(input, stage));
        }
    }

    private sealed class SilentDenyTrustPolicy : TrustPolicy
    {
        public override bool IsSatisfied(IReadOnlyDictionary<string, bool> claims) => false;

        public override void Explain(IReadOnlyDictionary<string, bool> claims, IList<string> reasons)
        {
            // Intentionally produce no reasons to cover the verifier fallback.
        }
    }
}
