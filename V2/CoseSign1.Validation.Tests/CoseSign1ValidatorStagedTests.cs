// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Tests;

using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using CoseSign1.Abstractions;
using CoseSign1.Validation.Interfaces;
using CoseSign1.Validation.Trust.Plan;
using CoseSign1.Validation.Trust.Rules;

/// <summary>
/// Tests for staged <see cref="CoseSign1Validator"/> behavior.
/// </summary>
[TestFixture]
[Category("Validation")]
public sealed class CoseSign1ValidatorStagedTests
{
    private static readonly byte[] Payload = "payload"u8.ToArray();

    private sealed class FixedSigningKeyResolver : ISigningKeyResolver
    {
        private readonly ISigningKey SigningKey;

        public FixedSigningKeyResolver(ISigningKey signingKey)
        {
            SigningKey = signingKey ?? throw new ArgumentNullException(nameof(signingKey));
        }

        public SigningKeyResolutionResult Resolve(CoseSign1Message message)
        {
            return SigningKeyResolutionResult.Success(SigningKey);
        }

        public Task<SigningKeyResolutionResult> ResolveAsync(CoseSign1Message message, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(SigningKeyResolutionResult.Success(SigningKey));
        }
    }

    private sealed class EcdsaSigningKey : ISigningKey
    {
        private readonly ECDsa Key;

        public EcdsaSigningKey(ECDsa key)
        {
            Key = key ?? throw new ArgumentNullException(nameof(key));
        }

        public CoseKey GetCoseKey()
        {
            return new CoseKey(Key, HashAlgorithmName.SHA256);
        }

        public void Dispose()
        {
            // The test owns the ECDsa instance.
        }
    }

    private static CoseSign1Message CreateSignedMessage(ECDsa signingKey)
    {
        var signer = new CoseSigner(signingKey, HashAlgorithmName.SHA256);
        byte[] messageBytes = CoseSign1Message.SignEmbedded(Payload, signer);
        return CoseMessage.DecodeSign1(messageBytes);
    }

    private static CompiledTrustPlan CreateAllowAllTrustPlan()
    {
        return new CompiledTrustPlan(TrustRules.AllowAll(), Array.Empty<IMultiTrustFactProducer>());
    }

    [Test]
    public void Validate_WhenNoResolvers_ReturnsResolutionFailure()
    {
        using var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var message = CreateSignedMessage(signingKey);

        var validator = new CoseSign1Validator(
            signingKeyResolvers: Array.Empty<ISigningKeyResolver>(),
            postSignatureValidators: null,
            toBeSignedAttestors: null,
            trustPlan: CreateAllowAllTrustPlan());

        var result = validator.Validate(message);

        Assert.That(result.Resolution.IsFailure, Is.True);
        Assert.That(result.Resolution.Failures, Is.Not.Empty);
        Assert.That(result.Resolution.Failures[0].ErrorCode, Is.EqualTo("NO_SIGNING_KEY_RESOLVED"));
    }

    [Test]
    public void Validate_WhenSigningKeyResolvedAndSignatureValid_ReturnsSuccess()
    {
        using var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var message = CreateSignedMessage(signingKey);

        var key = new EcdsaSigningKey(signingKey);
        var resolver = new FixedSigningKeyResolver(key);

        var validator = new CoseSign1Validator(
            signingKeyResolvers: new[] { resolver },
            postSignatureValidators: null,
            toBeSignedAttestors: null,
            trustPlan: CreateAllowAllTrustPlan());

        var result = validator.Validate(message);

        Assert.Multiple(() =>
        {
            Assert.That(result.Resolution.IsValid, Is.True);
            Assert.That(result.Signature.IsValid, Is.True);
            Assert.That(result.Trust.IsValid, Is.True);
            Assert.That(result.PostSignaturePolicy.IsValid, Is.True);
            Assert.That(result.Overall.IsValid, Is.True);
        });
    }

    [Test]
    public void Validate_WhenSigningKeyResolvedButWrongKey_ReturnsSignatureFailure()
    {
        using var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var wrongKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var message = CreateSignedMessage(signingKey);

        var key = new EcdsaSigningKey(wrongKey);
        var resolver = new FixedSigningKeyResolver(key);

        var validator = new CoseSign1Validator(
            signingKeyResolvers: new[] { resolver },
            postSignatureValidators: null,
            toBeSignedAttestors: null,
            trustPlan: CreateAllowAllTrustPlan());

        var result = validator.Validate(message);

        Assert.That(result.Signature.IsFailure, Is.True);
        Assert.That(result.Signature.Failures, Is.Not.Empty);
        Assert.That(result.Signature.Failures[0].ErrorCode, Is.EqualTo("SIGNATURE_VERIFICATION_FAILED"));
    }
}
