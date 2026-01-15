// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Tests.Trust;

using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using System.Security.Cryptography.X509Certificates;
using CoseSign1.Certificates.Trust;
using CoseSign1.Certificates.Trust.Facts;
using CoseSign1.Certificates.Trust.Facts.Producers;
using CoseSign1.Tests.Common;
using CoseSign1.Validation.Trust.Engine;
using CoseSign1.Validation.Trust.Ids;
using CoseSign1.Validation.Trust.Plan;
using CoseSign1.Validation.Trust.Subjects;
using Microsoft.Extensions.Caching.Memory;

[TestFixture]
public sealed class X509CertificateTrustPackChainModesTests
{
    private static readonly byte[] Payload = "trust-pack chain modes"u8.ToArray();

    private static CoseSign1Message CreateMessageWithX509Headers(
        X509Certificate2 signingCertificate,
        IReadOnlyList<X509Certificate2> chain,
        IReadOnlyList<X509Certificate2>? extraCertificates = null)
    {
        var headers = new CoseHeaderMap();

        // x5t
        var thumbprint = new CoseX509Thumbprint(signingCertificate, HashAlgorithmName.SHA256);
        var thumbprintWriter = new CborWriter();
        _ = thumbprint.Serialize(thumbprintWriter);
        headers.Add(
            CertificateHeaderContributor.HeaderLabels.X5T,
            CoseHeaderValue.FromEncodedValue(thumbprintWriter.Encode()));

        // x5chain (leaf-first order)
        var chainWriter = new CborWriter();
        chainWriter.WriteStartArray(chain.Count);
        foreach (var cert in chain)
        {
            chainWriter.WriteByteString(cert.RawData);
        }
        chainWriter.WriteEndArray();
        headers.Add(
            CertificateHeaderContributor.HeaderLabels.X5Chain,
            CoseHeaderValue.FromEncodedValue(chainWriter.Encode()));

        // x5bag (unordered extras)
        if (extraCertificates != null && extraCertificates.Count > 0)
        {
            var bagWriter = new CborWriter();
            bagWriter.WriteStartArray(extraCertificates.Count);
            foreach (var cert in extraCertificates)
            {
                bagWriter.WriteByteString(cert.RawData);
            }
            bagWriter.WriteEndArray();

            headers.Add(
                CertificateHeaderContributor.HeaderLabels.X5Bag,
                CoseHeaderValue.FromEncodedValue(bagWriter.Encode()));
        }

        using var key = ECDsa.Create();
        var signer = new CoseSigner(key, HashAlgorithmName.SHA256, headers);
        byte[] signedBytes = CoseSign1Message.SignDetached(Payload, signer, ReadOnlySpan<byte>.Empty);
        return CoseMessage.DecodeSign1(signedBytes);
    }

    private static TrustFactContext CreateContextForPrimarySigningKey(CoseSign1Message message, IMemoryCache? cache)
    {
        TrustSubjectId messageId = TrustIds.CreateMessageId(message);
        TrustSubject subject = TrustSubject.PrimarySigningKey(messageId);
        var options = new TrustEvaluationOptions();
        return new TrustFactContext(messageId, subject, options, memoryCache: cache, message: message);
    }

    [Test]
    public async Task ProduceChainTrusted_WithCustomRootTrust_BuildsTrustedChainAndCachesResults()
    {
        var chain = TestCertificateUtils.CreateTestChain(leafFirst: true);
        using var leaf = chain[0];
        using var intermediate = chain[1];
        using var root = chain[^1];

        var message = CreateMessageWithX509Headers(
            signingCertificate: leaf,
            chain: chain.Cast<X509Certificate2>().ToArray(),
            extraCertificates: new[] { root });

        var trustBuilder = new CertificateTrustBuilder()
            .UseCustomRootTrust(new X509Certificate2Collection { root })
            .WithRevocationMode(X509RevocationMode.NoCheck);

        var trustPack = new X509CertificateTrustPack(trustBuilder.Options);

        using var cache = new MemoryCache(new MemoryCacheOptions());
        TrustFactContext context = CreateContextForPrimarySigningKey(message, cache);

        var first = await trustPack.ProduceAsync(context, typeof(X509ChainTrustedFact), CancellationToken.None);
        var second = await trustPack.ProduceAsync(context, typeof(X509ChainTrustedFact), CancellationToken.None);

        Assert.That(first.IsMissing, Is.False);
        Assert.That(ReferenceEquals(first, second), Is.True);

        var typed = (ITrustFactSet<X509ChainTrustedFact>)first;
        Assert.That(typed.Count, Is.EqualTo(1));
        Assert.That(typed.Values[0].ChainBuilt, Is.True);
        Assert.That(typed.Values[0].IsTrusted, Is.True);
        Assert.That(typed.Values[0].ElementCount, Is.GreaterThanOrEqualTo(2));

        var elements = await trustPack.ProduceAsync(context, typeof(X509ChainElementIdentityFact), CancellationToken.None);
        Assert.That(elements.IsMissing, Is.False);

        var elementSet = (ITrustFactSet<X509ChainElementIdentityFact>)elements;
        Assert.That(elementSet.Count, Is.GreaterThanOrEqualTo(2));
        Assert.That(elementSet.Values[0].Depth, Is.EqualTo(0));
        Assert.That(elementSet.Values[^1].IsRoot, Is.True);
    }

    [Test]
    public async Task ProduceChainTrusted_WithSystemTrustAndSelfSignedRoot_IsNotTrustedAndHasStatusSummary()
    {
        var chain = TestCertificateUtils.CreateTestChain(leafFirst: true);
        using var leaf = chain[0];

        var message = CreateMessageWithX509Headers(leaf, chain.Cast<X509Certificate2>().ToArray());

        var trustBuilder = new CertificateTrustBuilder()
            .UseSystemTrust()
            .WithRevocationMode(X509RevocationMode.NoCheck);

        var trustPack = new X509CertificateTrustPack(trustBuilder.Options);
        TrustFactContext context = CreateContextForPrimarySigningKey(message, cache: null);

        var result = await trustPack.ProduceAsync(context, typeof(X509ChainTrustedFact), CancellationToken.None);

        Assert.That(result.IsMissing, Is.False);

        var typed = (ITrustFactSet<X509ChainTrustedFact>)result;
        Assert.That(typed.Count, Is.EqualTo(1));
        Assert.That(typed.Values[0].IsTrusted, Is.False);
        Assert.That(typed.Values[0].StatusSummary, Is.Not.Null);
        Assert.That(typed.Values[0].StatusSummary, Is.Not.Empty);
    }

    [Test]
    public async Task ProduceChainTrusted_WithEmbeddedChainOnly_AllowsUnknownRoot_WhenChainBuilds()
    {
        var chain = TestCertificateUtils.CreateTestChain(leafFirst: true);
        using var leaf = chain[0];

        var message = CreateMessageWithX509Headers(leaf, chain.Cast<X509Certificate2>().ToArray());

        var trustBuilder = new CertificateTrustBuilder()
            .UseEmbeddedChainOnly()
            .WithRevocationMode(X509RevocationMode.NoCheck);

        var trustPack = new X509CertificateTrustPack(trustBuilder.Options);
        TrustFactContext context = CreateContextForPrimarySigningKey(message, cache: null);

        var result = await trustPack.ProduceAsync(context, typeof(X509ChainTrustedFact), CancellationToken.None);

        Assert.That(result.IsMissing, Is.False);

        var typed = (ITrustFactSet<X509ChainTrustedFact>)result;
        Assert.That(typed.Count, Is.EqualTo(1));

        // Embedded-chain-only mode permits UntrustedRoot when the chain otherwise builds.
        Assert.That(typed.Values[0].ChainBuilt, Is.True);
        Assert.That(typed.Values[0].IsTrusted, Is.True);
    }

    [Test]
    public async Task ProduceSigningCertificateIdentityAllowed_WhenNotAllowed_ReturnsIsAllowedFalse()
    {
        var chain = TestCertificateUtils.CreateTestChain(leafFirst: true);
        using var leaf = chain[0];
        using var root = chain[^1];

        var message = CreateMessageWithX509Headers(leaf, chain.Cast<X509Certificate2>().ToArray());

        var trustBuilder = new CertificateTrustBuilder()
            .UseCustomRootTrust(new X509Certificate2Collection { root })
            .EnableCertificateIdentityPinning(p => p.AllowThumbprint("00"))
            .WithRevocationMode(X509RevocationMode.NoCheck);

        var trustPack = new X509CertificateTrustPack(trustBuilder.Options);
        TrustFactContext context = CreateContextForPrimarySigningKey(message, cache: null);

        var result = await trustPack.ProduceAsync(context, typeof(X509SigningCertificateIdentityAllowedFact), CancellationToken.None);

        Assert.That(result.IsMissing, Is.False);
        var typed = (ITrustFactSet<X509SigningCertificateIdentityAllowedFact>)result;
        Assert.That(typed.Count, Is.EqualTo(1));
        Assert.That(typed.Values[0].IsAllowed, Is.False);
    }
}
