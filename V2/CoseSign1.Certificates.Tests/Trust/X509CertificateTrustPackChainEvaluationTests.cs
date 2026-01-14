// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Tests.Trust;

using System.Security.Cryptography.X509Certificates;
using CoseSign1.Certificates.Trust;
using CoseSign1.Certificates.Trust.Facts;
using CoseSign1.Certificates.Trust.Facts.Producers;
using CoseSign1.Factories.Direct;
using CoseSign1.Tests.Common;
using CoseSign1.Validation.Trust.Engine;
using CoseSign1.Validation.Trust.Ids;
using CoseSign1.Validation.Trust.Plan;
using CoseSign1.Validation.Trust.Subjects;
using Microsoft.Extensions.Caching.Memory;

[TestFixture]
public class X509CertificateTrustPackChainEvaluationTests
{
    private static readonly byte[] Payload = "trust-pack evaluation"u8.ToArray();

    private static CoseSign1Message CreateMessageWithCertificates(X509Certificate2 signingCertificate, X509Certificate2[] chain)
    {
        using var signingService = CertificateSigningService.Create(signingCertificate, chain);
        using var factory = new DirectSignatureFactory(signingService);

        byte[] messageBytes = factory.CreateCoseSign1MessageBytes(Payload, "application/octet-stream");
        return CoseMessage.DecodeSign1(messageBytes);
    }

    private static TrustFactContext CreateContextForPrimarySigningKey(CoseSign1Message message, IMemoryCache? cache)
    {
        TrustSubjectId messageId = TrustIds.CreateMessageId(message);
        TrustSubject subject = TrustSubject.PrimarySigningKey(messageId);
        var options = new TrustEvaluationOptions();
        return new TrustFactContext(messageId, subject, options, memoryCache: cache, message: message);
    }

    [Test]
    public async Task ProduceChainTrusted_WhenTrustSourceMissing_ReturnsMissing()
    {
        var chain = TestCertificateUtils.CreateTestChain(leafFirst: true);
        using var signingCertificate = chain[0];

        var message = CreateMessageWithCertificates(signingCertificate, chain.Cast<X509Certificate2>().ToArray());
        TrustFactContext context = CreateContextForPrimarySigningKey(message, cache: null);

        var trustPack = new X509CertificateTrustPack(new CertificateTrustBuilder.CertificateTrustOptions());

        var result = await trustPack.ProduceAsync(context, typeof(X509ChainTrustedFact), CancellationToken.None);

        Assert.That(result.IsMissing, Is.True);
    }

    [Test]
    public async Task ProduceChainElementIdentities_UsesHeaderChain_WhenNoTrustSourceConfigured()
    {
        var chain = TestCertificateUtils.CreateTestChain(leafFirst: true);
        using var signingCertificate = chain[0];

        var message = CreateMessageWithCertificates(signingCertificate, chain.Cast<X509Certificate2>().ToArray());
        TrustFactContext context = CreateContextForPrimarySigningKey(message, cache: null);

        var trustPack = new X509CertificateTrustPack();

        var result = await trustPack.ProduceAsync(context, typeof(X509ChainElementIdentityFact), CancellationToken.None);

        Assert.That(result.IsMissing, Is.False);
        var typed = (ITrustFactSet<X509ChainElementIdentityFact>)result;
        Assert.That(typed.Count, Is.GreaterThanOrEqualTo(2));
        Assert.That(typed.Values[0].Depth, Is.EqualTo(0));
        Assert.That(typed.Values[0].ChainLength, Is.EqualTo(typed.Count));
        Assert.That(typed.Values[^1].IsRoot, Is.True);
    }

    [Test]
    public async Task ProduceCertificateSigningKeyTrust_IsCachedAcrossMultipleCalls()
    {
        var chain = TestCertificateUtils.CreateTestChain(leafFirst: true);
        using var signingCertificate = chain[0];

        var message = CreateMessageWithCertificates(signingCertificate, chain.Cast<X509Certificate2>().ToArray());

        var trustBuilder = new CertificateTrustBuilder()
            .UseEmbeddedChainOnly()
            .WithRevocationMode(X509RevocationMode.NoCheck);

        var trustPack = new X509CertificateTrustPack(trustBuilder.Options);

        using var cache = new MemoryCache(new MemoryCacheOptions());
        TrustFactContext context = CreateContextForPrimarySigningKey(message, cache);

        var first = await trustPack.ProduceAsync(context, typeof(CertificateSigningKeyTrustFact), CancellationToken.None);
        var second = await trustPack.ProduceAsync(context, typeof(CertificateSigningKeyTrustFact), CancellationToken.None);

        Assert.That(first.IsMissing, Is.False);
        Assert.That(ReferenceEquals(first, second), Is.True);

        var typed = (ITrustFactSet<CertificateSigningKeyTrustFact>)first;
        Assert.That(typed.Count, Is.EqualTo(1));
        Assert.That(typed.Values[0].Thumbprint, Is.Not.Empty);
    }
}
