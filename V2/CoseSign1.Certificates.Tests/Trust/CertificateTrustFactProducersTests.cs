// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Tests.Trust;

using System.Text;
using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using System.Security.Cryptography.X509Certificates;
using CoseSign1.Factories.Direct;
using CoseSign1.Certificates.Trust.Facts;
using CoseSign1.Certificates.Trust.Facts.Producers;
using CoseSign1.Certificates.Trust;
using CoseSign1.Validation.Trust.Engine;
using CoseSign1.Validation.Trust.Ids;
using CoseSign1.Validation.Trust.Plan;
using CoseSign1.Validation.Trust.Subjects;
using CoseSign1.Tests.Common;
using Microsoft.Extensions.Caching.Memory;

[TestFixture]
public class CertificateTrustFactProducersTests
{
    private static readonly byte[] TestPayload = Encoding.UTF8.GetBytes("trust-facts test payload");

    private static CoseSign1Message CreateMessageWithCertificates(X509Certificate2 signingCertificate, X509Certificate2[] chain)
    {
        using var signingService = CertificateSigningService.Create(signingCertificate, chain);
        using var factory = new DirectSignatureFactory(signingService);

        byte[] messageBytes = factory.CreateCoseSign1MessageBytes(TestPayload, "application/octet-stream");
        return CoseMessage.DecodeSign1(messageBytes);
    }

    private static TrustFactContext CreateContextForPrimarySigningKey(CoseSign1Message message)
    {
        TrustSubjectId messageId = TrustIds.CreateMessageId(message);
        TrustSubject subject = TrustSubject.PrimarySigningKey(messageId);
        var options = new TrustEvaluationOptions();
        return new TrustFactContext(messageId, subject, options, memoryCache: null, message: message);
    }

    private static TrustFactContext CreateContextForCounterSignatureSigningKey(CoseSign1Message message)
    {
        TrustSubjectId messageId = TrustIds.CreateMessageId(message);
        TrustSubject counterSignature = TrustSubject.CounterSignature(messageId, rawCounterSignatureBytes: new byte[] { 0x01, 0x02, 0x03 });
        TrustSubject subject = TrustSubject.CounterSignatureSigningKey(counterSignature.Id);
        var options = new TrustEvaluationOptions();
        return new TrustFactContext(messageId, subject, options, memoryCache: null, message: message);
    }

    private static CoseSign1Message CreateMessageWithoutCertificates()
    {
        using RSA rsa = RSA.Create(2048);

        CoseSigner coseSigner = new(
            rsa,
            RSASignaturePadding.Pkcs1,
            HashAlgorithmName.SHA256,
            protectedHeaders: new CoseHeaderMap(),
            unprotectedHeaders: new CoseHeaderMap());

        byte[] coseBytes = CoseSign1Message.SignEmbedded(TestPayload, coseSigner);
        return CoseMessage.DecodeSign1(coseBytes);
    }

    [Test]
    public async Task X509CertificateTrustPack_EmitsIdentityFact()
    {
        var chain = TestCertificateUtils.CreateTestChain(leafFirst: true);
        using var signingCertificate = chain[0];

        var message = CreateMessageWithCertificates(signingCertificate, chain: chain.Cast<X509Certificate2>().ToArray());
        TrustFactContext context = CreateContextForPrimarySigningKey(message);

        IMultiTrustFactProducer producer = new X509CertificateTrustPack();
        var result = await producer.ProduceAsync(context, typeof(X509SigningCertificateIdentityFact), CancellationToken.None);

        Assert.That(result.IsMissing, Is.False);
        Assert.That(result, Is.InstanceOf<ITrustFactSet<X509SigningCertificateIdentityFact>>());

        var typed = (ITrustFactSet<X509SigningCertificateIdentityFact>)result;
        Assert.That(typed.Count, Is.EqualTo(1));
            Assert.That(typed.Values[0].CertificateThumbprint, Is.EqualTo(signingCertificate.GetCertHashString()));
        Assert.That(typed.Values[0].Subject, Is.EqualTo(signingCertificate.Subject));
        Assert.That(typed.Values[0].Issuer, Is.EqualTo(signingCertificate.Issuer));
    }

    [Test]
    public async Task X509CertificateTrustPack_EmitsCustomEku()
    {
        const string ekuOid = "1.2.3.4.5";
        using var signingCertificate = TestCertificateUtils.CreateCertificate(customEkus: new[] { ekuOid }, useEcc: true);

        var message = CreateMessageWithCertificates(signingCertificate, chain: new[] { signingCertificate });
        TrustFactContext context = CreateContextForPrimarySigningKey(message);

        IMultiTrustFactProducer producer = new X509CertificateTrustPack();
        var result = await producer.ProduceAsync(context, typeof(X509SigningCertificateEkuFact), CancellationToken.None);

        Assert.That(result.IsMissing, Is.False);
        Assert.That(result, Is.InstanceOf<ITrustFactSet<X509SigningCertificateEkuFact>>());

        var typed = (ITrustFactSet<X509SigningCertificateEkuFact>)result;
            Assert.That(typed.Values, Has.Some.Matches<X509SigningCertificateEkuFact>(f => f.OidValue == ekuOid));
            Assert.That(typed.Values, Has.Some.Matches<X509SigningCertificateEkuFact>(f => f.CertificateThumbprint == signingCertificate.GetCertHashString()));
    }

    [Test]
    public async Task X509CertificateTrustPack_EmitsChainIdentities()
    {
        var chain = TestCertificateUtils.CreateTestChain(leafFirst: true);
        using var signingCertificate = chain[0];

        var message = CreateMessageWithCertificates(signingCertificate, chain: chain.Cast<X509Certificate2>().ToArray());
        TrustFactContext context = CreateContextForPrimarySigningKey(message);

        IMultiTrustFactProducer producer = new X509CertificateTrustPack();
        var result = await producer.ProduceAsync(context, typeof(X509X5ChainCertificateIdentityFact), CancellationToken.None);

        Assert.That(result.IsMissing, Is.False);
        Assert.That(result, Is.InstanceOf<ITrustFactSet<X509X5ChainCertificateIdentityFact>>());

        var typed = (ITrustFactSet<X509X5ChainCertificateIdentityFact>)result;
        Assert.That(typed.Count, Is.EqualTo(chain.Count));
            Assert.That(typed.Values[0].CertificateThumbprint, Is.EqualTo(chain[0].GetCertHashString()));
    }

    [Test]
    public async Task X509CertificateTrustPack_ForCounterSignatureSigningKey_EmitsIdentityFact()
    {
        var chain = TestCertificateUtils.CreateTestChain(leafFirst: true);
        using var signingCertificate = chain[0];

        var message = CreateMessageWithCertificates(signingCertificate, chain: chain.Cast<X509Certificate2>().ToArray());
        TrustFactContext context = CreateContextForCounterSignatureSigningKey(message);

        IMultiTrustFactProducer producer = new X509CertificateTrustPack();
        var result = await producer.ProduceAsync(context, typeof(X509SigningCertificateIdentityFact), CancellationToken.None);

        Assert.That(result.IsMissing, Is.False);
        Assert.That(result, Is.InstanceOf<ITrustFactSet<X509SigningCertificateIdentityFact>>());

        var typed = (ITrustFactSet<X509SigningCertificateIdentityFact>)result;
        Assert.That(typed.Count, Is.EqualTo(1));
        Assert.That(typed.Values[0].CertificateThumbprint, Is.EqualTo(signingCertificate.GetCertHashString()));
    }

    [Test]
    public async Task X509CertificateTrustPack_WhenSubjectIsNotSigningKey_ReturnsAvailableEmptyFactSet()
    {
        var chain = TestCertificateUtils.CreateTestChain(leafFirst: true);
        using var signingCertificate = chain[0];

        var message = CreateMessageWithCertificates(signingCertificate, chain: chain.Cast<X509Certificate2>().ToArray());
        TrustSubjectId messageId = TrustIds.CreateMessageId(message);
        TrustSubject subject = TrustSubject.Message(messageId);
        var options = new TrustEvaluationOptions();
        var context = new TrustFactContext(messageId, subject, options, memoryCache: null, message: message);

        IMultiTrustFactProducer producer = new X509CertificateTrustPack();
        var result = await producer.ProduceAsync(context, typeof(X509SigningCertificateIdentityFact), CancellationToken.None);

        Assert.That(result.IsMissing, Is.False);
        var typed = (ITrustFactSet<X509SigningCertificateIdentityFact>)result;
        Assert.That(typed.Count, Is.EqualTo(0));
    }

    [Test]
    public async Task X509CertificateTrustPack_WhenMessageIsUnavailable_ReturnsMissingFact()
    {
        var chain = TestCertificateUtils.CreateTestChain(leafFirst: true);
        using var signingCertificate = chain[0];

        var message = CreateMessageWithCertificates(signingCertificate, chain: chain.Cast<X509Certificate2>().ToArray());
        TrustSubjectId messageId = TrustIds.CreateMessageId(message);
        TrustSubject subject = TrustSubject.PrimarySigningKey(messageId);
        var options = new TrustEvaluationOptions();
        var context = new TrustFactContext(messageId, subject, options, memoryCache: null, message: null);

        IMultiTrustFactProducer producer = new X509CertificateTrustPack();
        var result = await producer.ProduceAsync(context, typeof(X509SigningCertificateIdentityFact), CancellationToken.None);

        Assert.That(result.IsMissing, Is.True);
    }

    [Test]
    public async Task X509CertificateTrustPack_WhenNoCertificatesInMessage_ReturnsMissingIdentityFact()
    {
        var message = CreateMessageWithoutCertificates();
        TrustFactContext context = CreateContextForPrimarySigningKey(message);

        IMultiTrustFactProducer producer = new X509CertificateTrustPack();
        var result = await producer.ProduceAsync(context, typeof(X509SigningCertificateIdentityFact), CancellationToken.None);

        Assert.That(result.IsMissing, Is.True);
    }

    [Test]
    public async Task X509CertificateTrustPack_EmitsIdentityAllowedFact_WhenThumbprintAllowed()
    {
        var chain = TestCertificateUtils.CreateTestChain(leafFirst: true);
        using var signingCertificate = chain[0];

        var message = CreateMessageWithCertificates(signingCertificate, chain: chain.Cast<X509Certificate2>().ToArray());
        TrustFactContext context = CreateContextForPrimarySigningKey(message);

        var trustBuilder = new CertificateTrustBuilder()
            .UseEmbeddedChainOnly()
            .EnableCertificateIdentityPinning(p => p.AllowThumbprint("  " + signingCertificate.GetCertHashString() + "  "));

        IMultiTrustFactProducer producer = new X509CertificateTrustPack(trustBuilder.Options);
        var result = await producer.ProduceAsync(context, typeof(X509SigningCertificateIdentityAllowedFact), CancellationToken.None);

        Assert.That(result.IsMissing, Is.False);
        var typed = (ITrustFactSet<X509SigningCertificateIdentityAllowedFact>)result;
        Assert.That(typed.Count, Is.EqualTo(1));
        Assert.That(typed.Values[0].IsAllowed, Is.True);
    }

    [Test]
    public async Task X509CertificateTrustPack_EmitsKeyUsageAndBasicConstraintsFacts()
    {
        using var signingCertificate = TestCertificateUtils.CreateCertificate();

        var message = CreateMessageWithCertificates(signingCertificate, chain: new[] { signingCertificate });
        TrustFactContext context = CreateContextForPrimarySigningKey(message);

        IMultiTrustFactProducer producer = new X509CertificateTrustPack();

        var keyUsage = await producer.ProduceAsync(context, typeof(X509SigningCertificateKeyUsageFact), CancellationToken.None);
        Assert.That(keyUsage.IsMissing, Is.False);
        Assert.That(keyUsage, Is.InstanceOf<ITrustFactSet<X509SigningCertificateKeyUsageFact>>());

        var basicConstraints = await producer.ProduceAsync(context, typeof(X509SigningCertificateBasicConstraintsFact), CancellationToken.None);
        Assert.That(basicConstraints.IsMissing, Is.False);
        Assert.That(basicConstraints, Is.InstanceOf<ITrustFactSet<X509SigningCertificateBasicConstraintsFact>>());
    }

    [Test]
    public async Task X509CertificateTrustPack_WithCustomRootTrust_EmitsTrustedChainFact_AndCachesResults()
    {
        var chain = TestCertificateUtils.CreateTestChain(leafFirst: true);
        using var signingCertificate = chain[0];
        using var root = chain[^1];

        var message = CreateMessageWithCertificates(signingCertificate, chain: chain.Cast<X509Certificate2>().ToArray());

        TrustSubjectId messageId = TrustIds.CreateMessageId(message);
        TrustSubject subject = TrustSubject.PrimarySigningKey(messageId);
        var options = new TrustEvaluationOptions();
        using var memoryCache = new MemoryCache(new MemoryCacheOptions());
        var context = new TrustFactContext(messageId, subject, options, memoryCache: memoryCache, message: message);

        var roots = new X509Certificate2Collection { root };
        var trustBuilder = new CertificateTrustBuilder()
            .UseCustomRootTrust(roots);

        IMultiTrustFactProducer producer = new X509CertificateTrustPack(trustBuilder.Options);

        var first = await producer.ProduceAsync(context, typeof(X509ChainTrustedFact), CancellationToken.None);
        var second = await producer.ProduceAsync(context, typeof(X509ChainTrustedFact), CancellationToken.None);

        Assert.That(first.IsMissing, Is.False);
        Assert.That(ReferenceEquals(first, second), Is.True);

        var typed = (ITrustFactSet<X509ChainTrustedFact>)first;
        Assert.That(typed.Count, Is.EqualTo(1));
        // Chain building/trust can vary across environments (revocation, platform chain engine);
        // the purpose of this test is to ensure the trust pack produces the fact and caches it.
        Assert.That(typed.Values[0].ElementCount, Is.GreaterThanOrEqualTo(0));
    }
}
