// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Tests;

using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using CoseSign1.Abstractions;
using CoseSign1.Validation.DependencyInjection;
using CoseSign1.Validation.Interfaces;
using CoseSign1.Validation.Trust.Plan;
using CoseSign1.Validation.Trust.Rules;
using Microsoft.Extensions.DependencyInjection;

[TestFixture]
[Category("Validation")]
public sealed class CoseSign1ValidatorFactoryTests
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

        public CoseKey GetCoseKey() => new CoseKey(Key, HashAlgorithmName.SHA256);

        public void Dispose()
        {
            // The test owns the ECDsa instance.
        }
    }

    private static CoseSign1Message CreateSignedEmbeddedMessage(ECDsa signingKey)
    {
        var signer = new CoseSigner(signingKey, HashAlgorithmName.SHA256);
        byte[] messageBytes = CoseSign1Message.SignEmbedded(Payload, signer);
        return CoseMessage.DecodeSign1(messageBytes);
    }

    [Test]
    public void Create_ResolvesComponentsFromServices_AndCanValidate()
    {
        var services = new ServiceCollection();

        _ = services.ConfigureCoseValidation();

        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        services.AddSingleton<ISigningKeyResolver>(new FixedSigningKeyResolver(new EcdsaSigningKey(ecdsa)));

        using var sp = services.BuildServiceProvider();

        var factory = sp.GetRequiredService<ICoseSign1ValidatorFactory>();

        var validator = factory.Create(
            options: new CoseSign1ValidationOptions { SkipPostSignatureValidation = true },
            trustEvaluationOptions: new TrustEvaluationOptions { BypassTrust = true });

        var message = CreateSignedEmbeddedMessage(ecdsa);
        var result = validator.Validate(message);

        Assert.That(result.Overall.IsValid, Is.True);
    }

    [Test]
    public void Create_WhenTrustPlanKeyProvidedAndNotRegistered_ThrowsInvalidOperationException()
    {
        var services = new ServiceCollection();

        _ = services.ConfigureCoseValidation();

        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        services.AddSingleton<ISigningKeyResolver>(new FixedSigningKeyResolver(new EcdsaSigningKey(ecdsa)));

        using var sp = services.BuildServiceProvider();

        var factory = sp.GetRequiredService<ICoseSign1ValidatorFactory>();

        Assert.That(
            () => _ = factory.Create(
                options: new CoseSign1ValidationOptions { SkipPostSignatureValidation = true },
                trustEvaluationOptions: new TrustEvaluationOptions { BypassTrust = true },
                trustPlanKey: "missing"),
            Throws.InvalidOperationException);
    }

    [Test]
    public void Create_WhenKeyedTrustPlanRegistered_UsesThatTrustPlan()
    {
        var services = new ServiceCollection();

        _ = services.ConfigureCoseValidation();

        // Register a keyed plan that always denies trust.
        var denyPlan = new CompiledTrustPlan(
            TrustRules.Not(TrustRules.AllowAll()),
            Array.Empty<IMultiTrustFactProducer>());
        services.AddKeyedSingleton<CompiledTrustPlan>("deny", denyPlan);

        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        services.AddSingleton<ISigningKeyResolver>(new FixedSigningKeyResolver(new EcdsaSigningKey(ecdsa)));

        using var sp = services.BuildServiceProvider();

        var factory = sp.GetRequiredService<ICoseSign1ValidatorFactory>();
        var validator = factory.Create(
            options: new CoseSign1ValidationOptions { SkipPostSignatureValidation = true },
            trustEvaluationOptions: new TrustEvaluationOptions { BypassTrust = false },
            trustPlanKey: "deny");

        var message = CreateSignedEmbeddedMessage(ecdsa);
        var result = validator.Validate(message);

        Assert.Multiple(() =>
        {
            Assert.That(result.Trust.IsFailure, Is.True);
            Assert.That(result.Signature.IsNotApplicable, Is.True);
        });
    }

    [Test]
    public void Create_WhenUnkeyedTrustPlanRegistered_UsesThatTrustPlan()
    {
        var services = new ServiceCollection();

        _ = services.ConfigureCoseValidation();

        // Register an unkeyed plan that always denies trust.
        services.AddSingleton(
            new CompiledTrustPlan(TrustRules.Not(TrustRules.AllowAll()), Array.Empty<IMultiTrustFactProducer>()));

        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        services.AddSingleton<ISigningKeyResolver>(new FixedSigningKeyResolver(new EcdsaSigningKey(ecdsa)));

        using var sp = services.BuildServiceProvider();

        var factory = sp.GetRequiredService<ICoseSign1ValidatorFactory>();
        var validator = factory.Create(
            options: new CoseSign1ValidationOptions { SkipPostSignatureValidation = true },
            trustEvaluationOptions: new TrustEvaluationOptions { BypassTrust = false });

        var message = CreateSignedEmbeddedMessage(ecdsa);
        var result = validator.Validate(message);

        Assert.Multiple(() =>
        {
            Assert.That(result.Trust.IsFailure, Is.True);
            Assert.That(result.Signature.IsNotApplicable, Is.True);
        });
    }
}
