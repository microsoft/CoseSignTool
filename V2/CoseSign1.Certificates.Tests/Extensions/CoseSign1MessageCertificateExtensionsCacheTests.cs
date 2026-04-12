// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Tests.Extensions;

using System.Formats.Cbor;
using System.Text;
using CoseSign1.Certificates.Caching;
using CoseSign1.Certificates.Extensions;

/// <summary>
/// Tests for CoseSign1MessageCertificateExtensions with CertificateCache integration.
/// Verifies that the cache-accepting overloads work correctly and return
/// cached certificate instances on repeated calls.
/// </summary>
[TestFixture]
public sealed class CoseSign1MessageCertificateExtensionsCacheTests
{
    private static readonly byte[] TestPayload = Encoding.UTF8.GetBytes("cache test payload");

    private static CoseSign1Message CreateMessageWithHeaders(CoseHeaderMap headers)
    {
        using ECDsa key = ECDsa.Create();
        CoseSigner signer = new CoseSigner(key, HashAlgorithmName.SHA256, headers);
        byte[] signedBytes = CoseSign1Message.SignDetached(TestPayload, signer, ReadOnlySpan<byte>.Empty);
        return CoseMessage.DecodeSign1(signedBytes);
    }

    [Test]
    public void TryGetCertificateChain_WithCache_ReturnsCachedInstances()
    {
        // Arrange
        using X509Certificate2 testCert = TestCertificateUtils.CreateCertificate();
        CoseHeaderMap headers = new CoseHeaderMap();

        CborWriter writer = new CborWriter();
        writer.WriteByteString(testCert.RawData);
        CoseHeaderValue x5chainValue = CoseHeaderValue.FromEncodedValue(writer.Encode());
        headers.Add(CertificateHeaderContributor.HeaderLabels.X5Chain, x5chainValue);

        CoseSign1Message message = CreateMessageWithHeaders(headers);
        using CertificateCache cache = new CertificateCache();

        // Act — call twice with same cache
        bool result1 = message.TryGetCertificateChain(out X509Certificate2Collection? chain1, CoseHeaderLocation.Protected, cache);
        bool result2 = message.TryGetCertificateChain(out X509Certificate2Collection? chain2, CoseHeaderLocation.Protected, cache);

        // Assert — both succeed, and the inner certificates are the same instance (cache hit)
        Assert.That(result1, Is.True);
        Assert.That(result2, Is.True);
        Assert.That(chain1, Is.Not.Null);
        Assert.That(chain2, Is.Not.Null);
        Assert.That(chain2![0], Is.SameAs(chain1![0]));
    }

    [Test]
    public void TryGetCertificateChain_WithNullCache_StillWorks()
    {
        // Arrange
        using X509Certificate2 testCert = TestCertificateUtils.CreateCertificate();
        CoseHeaderMap headers = new CoseHeaderMap();

        CborWriter writer = new CborWriter();
        writer.WriteByteString(testCert.RawData);
        CoseHeaderValue x5chainValue = CoseHeaderValue.FromEncodedValue(writer.Encode());
        headers.Add(CertificateHeaderContributor.HeaderLabels.X5Chain, x5chainValue);

        CoseSign1Message message = CreateMessageWithHeaders(headers);

        // Act
        bool result = message.TryGetCertificateChain(out X509Certificate2Collection? chain, CoseHeaderLocation.Protected, certificateCache: null);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(chain, Is.Not.Null);
        Assert.That(chain!.Count, Is.EqualTo(1));
        Assert.That(chain[0].RawData, Is.EqualTo(testCert.RawData));
    }

    [Test]
    public void TryGetExtraCertificates_WithCache_ReturnsCachedInstances()
    {
        // Arrange
        using X509Certificate2 testCert = TestCertificateUtils.CreateCertificate();
        CoseHeaderMap headers = new CoseHeaderMap();

        CborWriter writer = new CborWriter();
        writer.WriteStartArray(1);
        writer.WriteByteString(testCert.RawData);
        writer.WriteEndArray();
        CoseHeaderValue x5bagValue = CoseHeaderValue.FromEncodedValue(writer.Encode());
        headers.Add(CertificateHeaderContributor.HeaderLabels.X5Bag, x5bagValue);

        CoseSign1Message message = CreateMessageWithHeaders(headers);
        using CertificateCache cache = new CertificateCache();

        // Act
        bool result1 = message.TryGetExtraCertificates(out X509Certificate2Collection? certs1, CoseHeaderLocation.Protected, cache);
        bool result2 = message.TryGetExtraCertificates(out X509Certificate2Collection? certs2, CoseHeaderLocation.Protected, cache);

        // Assert
        Assert.That(result1, Is.True);
        Assert.That(result2, Is.True);
        Assert.That(certs1, Is.Not.Null);
        Assert.That(certs2, Is.Not.Null);
        Assert.That(certs2![0], Is.SameAs(certs1![0]));
    }

    [Test]
    public void TryGetSigningCertificate_WithCache_ReturnsCachedInstance()
    {
        // Arrange
        using X509Certificate2 testCert = TestCertificateUtils.CreateCertificate();
        CoseX509Thumbprint thumbprint = new CoseX509Thumbprint(testCert, HashAlgorithmName.SHA256);
        CoseHeaderMap headers = new CoseHeaderMap();

        // Add x5t header
        CborWriter thumbprintWriter = new CborWriter();
        thumbprint.Serialize(thumbprintWriter);
        headers.Add(CertificateHeaderContributor.HeaderLabels.X5T, CoseHeaderValue.FromEncodedValue(thumbprintWriter.Encode()));

        // Add x5chain header
        CborWriter chainWriter = new CborWriter();
        chainWriter.WriteStartArray(1);
        chainWriter.WriteByteString(testCert.RawData);
        chainWriter.WriteEndArray();
        headers.Add(CertificateHeaderContributor.HeaderLabels.X5Chain, CoseHeaderValue.FromEncodedValue(chainWriter.Encode()));

        CoseSign1Message message = CreateMessageWithHeaders(headers);
        using CertificateCache cache = new CertificateCache();

        // Act
        bool result1 = message.TryGetSigningCertificate(out X509Certificate2? cert1, CoseHeaderLocation.Protected, cache);
        bool result2 = message.TryGetSigningCertificate(out X509Certificate2? cert2, CoseHeaderLocation.Protected, cache);

        // Assert
        Assert.That(result1, Is.True);
        Assert.That(result2, Is.True);
        Assert.That(cert1, Is.Not.Null);
        Assert.That(cert2, Is.Not.Null);
        Assert.That(cert2, Is.SameAs(cert1));
    }

    [Test]
    public void TryGetCertificateChain_DefaultOverload_StillWorks()
    {
        // Arrange — verify backward compatibility of the default (no-cache) overload
        using X509Certificate2 testCert = TestCertificateUtils.CreateCertificate();
        CoseHeaderMap headers = new CoseHeaderMap();

        CborWriter writer = new CborWriter();
        writer.WriteByteString(testCert.RawData);
        CoseHeaderValue x5chainValue = CoseHeaderValue.FromEncodedValue(writer.Encode());
        headers.Add(CertificateHeaderContributor.HeaderLabels.X5Chain, x5chainValue);

        CoseSign1Message message = CreateMessageWithHeaders(headers);

        // Act — using the original overload with no cache parameter
        bool result = message.TryGetCertificateChain(out X509Certificate2Collection? chain);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(chain, Is.Not.Null);
        Assert.That(chain!.Count, Is.EqualTo(1));
    }
}