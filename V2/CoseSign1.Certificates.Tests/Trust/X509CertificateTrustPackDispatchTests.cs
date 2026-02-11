// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Tests.Trust;

using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using System.Security.Cryptography.X509Certificates;
using CoseSign1.Abstractions;
using CoseSign1.Certificates.Trust;
using CoseSign1.Certificates.Trust.Facts;
using CoseSign1.Certificates.Trust.Facts.Producers;
using CoseSign1.Factories.Direct;
using CoseSign1.Validation.Trust.Engine;
using CoseSign1.Validation.Trust.Ids;
using CoseSign1.Validation.Trust.Plan;
using CoseSign1.Validation.Trust.Rules;
using CoseSign1.Validation.Trust.Subjects;

[TestFixture]
public class X509CertificateTrustPackDispatchTests
{
    private static readonly byte[] Payload = "trust-pack dispatch"u8.ToArray();

    private sealed class TestSigningService : ISigningService<SigningOptions>
    {
        private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        public CoseSigner GetCoseSigner(SigningContext context)
        {
            return new CoseSigner(_key, HashAlgorithmName.SHA256);
        }

        public SigningOptions CreateSigningOptions() => new();

        public bool IsRemote => false;

        public SigningServiceMetadata ServiceMetadata { get; } = new("TestSigningService");

        public bool VerifySignature(CoseSign1Message message, SigningContext context)
        {
            return true; // Default: verification passes for tests
        }

        public void Dispose()
        {
            _key.Dispose();
        }
    }

    private static CoseSign1Message CreateMessageWithoutCertificateHeaders()
    {
        using var service = new TestSigningService();
        using var factory = new DirectSignatureFactory(service);

        byte[] messageBytes = factory.CreateCoseSign1MessageBytes(Payload, "application/octet-stream");
        return CoseMessage.DecodeSign1(messageBytes);
    }

    private static IEnumerable<Type> SupportedFactTypes()
    {
        return new X509CertificateTrustPack().FactTypes;
    }

    [TestCaseSource(nameof(SupportedFactTypes))]
    public async Task ProduceAsync_WhenSubjectNotApplicable_ReturnsAvailableEmpty_ForAllSupportedFactTypes(Type factType)
    {
        var trustPack = new X509CertificateTrustPack();
        TrustSubjectId messageId = TrustSubjectId.FromSha256OfBytes("msg"u8.ToArray());
        var context = new TrustFactContext(messageId, TrustSubject.Message(messageId), new TrustEvaluationOptions(), memoryCache: null, message: null);

        var set = await trustPack.ProduceAsync(context, factType, CancellationToken.None);

        Assert.That(set.IsMissing, Is.False);
        Assert.That(set.Count, Is.EqualTo(0));
    }

    [TestCaseSource(nameof(SupportedFactTypes))]
    public async Task ProduceAsync_WhenMessageNull_ReturnsMissing_ForAllSupportedFactTypes(Type factType)
    {
        var trustPack = new X509CertificateTrustPack();
        TrustSubjectId messageId = TrustIds.CreateMessageId(new byte[32]);
        var context = new TrustFactContext(messageId, TrustSubject.PrimarySigningKey(messageId), new TrustEvaluationOptions(), memoryCache: null, message: null);

        var set = await trustPack.ProduceAsync(context, factType, CancellationToken.None);

        Assert.That(set.IsMissing, Is.True);
    }

    [Test]
    public async Task ProduceAsync_WhenFactTypeUnsupported_ReturnsMissing()
    {
        var trustPack = new X509CertificateTrustPack();
        TrustSubjectId messageId = TrustIds.CreateMessageId(new byte[32]);
        var message = CreateMessageWithoutCertificateHeaders();
        var context = new TrustFactContext(messageId, TrustSubject.PrimarySigningKey(messageId), new TrustEvaluationOptions(), memoryCache: null, message: message);

        var set = await trustPack.ProduceAsync(context, typeof(string), CancellationToken.None);

        Assert.That(set.IsMissing, Is.True);
    }

    [Test]
    public void ProduceAsync_WhenContextNull_ThrowsArgumentNullException()
    {
        var trustPack = new X509CertificateTrustPack();
        Assert.That(() => trustPack.ProduceAsync(null!, typeof(object), CancellationToken.None), Throws.ArgumentNullException);
    }

    [Test]
    public void ProduceAsync_WhenFactTypeNull_ThrowsArgumentNullException()
    {
        var trustPack = new X509CertificateTrustPack();
        TrustSubjectId messageId = TrustSubjectId.FromSha256OfBytes("msg"u8.ToArray());
        var context = new TrustFactContext(messageId, TrustSubject.Message(messageId), new TrustEvaluationOptions(), memoryCache: null, message: null);

        Assert.That(() => trustPack.ProduceAsync(context, null!, CancellationToken.None), Throws.ArgumentNullException);
    }

    [Test]
    public async Task ProduceChainTrusted_WhenSigningCertificateNotFound_ReturnsMissing()
    {
        var message = CreateMessageWithoutCertificateHeaders();
        TrustSubjectId messageId = TrustIds.CreateMessageId(message);

        var options = new CertificateTrustBuilder()
            .UseEmbeddedChainOnly()
            .WithRevocationMode(X509RevocationMode.NoCheck)
            .Options;

        var trustPack = new X509CertificateTrustPack(options);
        var context = new TrustFactContext(messageId, TrustSubject.PrimarySigningKey(messageId), new TrustEvaluationOptions(), memoryCache: null, message: message);

        var set = await trustPack.ProduceAsync(context, typeof(X509ChainTrustedFact), CancellationToken.None);

        Assert.That(set.IsMissing, Is.True);
    }

    [Test]
    public void IsChainTrustedPerSource_WhenStatusesNullOrEmpty_ReturnsTrue()
    {
        var method = typeof(X509CertificateTrustPack).GetMethod(
            "IsChainTrustedPerSource",
            BindingFlags.NonPublic | BindingFlags.Static);

        Assert.That(method, Is.Not.Null);

        var trustedNull = (bool)method!.Invoke(null, new object?[] { CertificateTrustSourceKind.System, null })!;
        Assert.That(trustedNull, Is.True);

        var trustedEmpty = (bool)method.Invoke(null, new object?[] { CertificateTrustSourceKind.System, Array.Empty<X509ChainStatus>() })!;
        Assert.That(trustedEmpty, Is.True);
    }

    [Test]
    public void IsChainTrustedPerSource_WhenEmbeddedChainOnly_AllowsUntrustedRoot()
    {
        var method = typeof(X509CertificateTrustPack).GetMethod(
            "IsChainTrustedPerSource",
            BindingFlags.NonPublic | BindingFlags.Static);

        Assert.That(method, Is.Not.Null);

        var statuses = new[]
        {
            new X509ChainStatus { Status = X509ChainStatusFlags.UntrustedRoot, StatusInformation = string.Empty },
        };

        var embedded = (bool)method!.Invoke(null, new object?[] { CertificateTrustSourceKind.EmbeddedChainOnly, statuses })!;
        Assert.That(embedded, Is.True);

        var system = (bool)method.Invoke(null, new object?[] { CertificateTrustSourceKind.System, statuses })!;
        Assert.That(system, Is.False);
    }

    [Test]
    public void GetDefaults_WhenTrustSourceNotConfigured_ReturnsDenyAllTrustSource()
    {
        var trustPack = new X509CertificateTrustPack();

        var defaults = trustPack.GetDefaults();

        Assert.That(defaults.TrustSources, Has.Count.EqualTo(1));
        Assert.That(defaults.Vetoes, Is.Not.Null);

        var engine = new TrustFactEngine(TrustSubjectId.FromSha256OfBytes("msg"u8.ToArray()), producers: Array.Empty<IMultiTrustFactProducer>());
        var ctx = new TrustRuleContext(engine, TrustSubject.Message(engine.MessageId));

        var decision = defaults.TrustSources[0].Evaluate(ctx);
        Assert.That(decision.IsTrusted, Is.False);
    }

    [Test]
    public void GetDefaults_WhenIdentityPinningEnabledButNotConfigured_ReturnsDenyAllTrustSource()
    {
        var options = new CertificateTrustBuilder().UseEmbeddedChainOnly().WithRevocationMode(X509RevocationMode.NoCheck).Options;
        options.IdentityPinningEnabled = true;

        var trustPack = new X509CertificateTrustPack(options);

        var defaults = trustPack.GetDefaults();

        Assert.That(defaults.TrustSources, Has.Count.EqualTo(1));

        var engine = new TrustFactEngine(TrustSubjectId.FromSha256OfBytes("msg"u8.ToArray()), producers: Array.Empty<IMultiTrustFactProducer>());
        var ctx = new TrustRuleContext(engine, TrustSubject.Message(engine.MessageId));

        var decision = defaults.TrustSources[0].Evaluate(ctx);
        Assert.That(decision.IsTrusted, Is.False);
    }

    [Test]
    public void GetDefaults_WhenConfigured_ReturnsDerivedSubjectTrustSource()
    {
        var options = new CertificateTrustBuilder()
            .UseEmbeddedChainOnly()
            .WithRevocationMode(X509RevocationMode.NoCheck)
            .Options;

        var trustPack = new X509CertificateTrustPack(options);

        var defaults = trustPack.GetDefaults();

        Assert.That(defaults.TrustSources, Has.Count.EqualTo(1));
        Assert.That(defaults.TrustSources[0], Is.Not.Null);
    }
}
