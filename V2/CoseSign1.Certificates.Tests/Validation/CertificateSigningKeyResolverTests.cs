// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Tests.Validation;

using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using System.Security.Cryptography.X509Certificates;
using CoseSign1.Certificates.Validation;
using CoseSign1.Tests.Common;

[TestFixture]
public sealed class CertificateSigningKeyResolverTests
{
    private static readonly byte[] Payload = "resolver tests"u8.ToArray();

    private static CoseSign1Message CreateMessageWithHeaders(CoseHeaderMap protectedHeaders)
    {
        using var key = ECDsa.Create();
        var signer = new CoseSigner(key, HashAlgorithmName.SHA256, protectedHeaders);
        byte[] signedBytes = CoseSign1Message.SignDetached(Payload, signer, ReadOnlySpan<byte>.Empty);
        return CoseMessage.DecodeSign1(signedBytes);
    }

    private static CoseHeaderMap CreateX5THeader(X509Certificate2 certificate)
    {
        var headers = new CoseHeaderMap();
        var thumbprint = new CoseX509Thumbprint(certificate, HashAlgorithmName.SHA256);
        var writer = new CborWriter();
        _ = thumbprint.Serialize(writer);
        headers.Add(CertificateHeaderContributor.HeaderLabels.X5T, CoseHeaderValue.FromEncodedValue(writer.Encode()));
        return headers;
    }

    private static void AddX5ChainHeader(CoseHeaderMap headers, IReadOnlyList<X509Certificate2> chain)
    {
        var writer = new CborWriter();
        writer.WriteStartArray(chain.Count);
        foreach (var cert in chain)
        {
            writer.WriteByteString(cert.RawData);
        }
        writer.WriteEndArray();
        headers.Add(CertificateHeaderContributor.HeaderLabels.X5Chain, CoseHeaderValue.FromEncodedValue(writer.Encode()));
    }

    [Test]
    public void Resolve_WithNullMessage_ReturnsFailure()
    {
        var resolver = new CertificateSigningKeyResolver();

        var result = resolver.Resolve(null!);

        Assert.That(result.IsSuccess, Is.False);
        Assert.That(result.ErrorCode, Is.EqualTo(CertificateSigningKeyResolver.ClassStrings.ErrorCodeNullInput));
    }

    [Test]
    public void Resolve_WithMissingX5Chain_ReturnsFailure()
    {
        using var cert = TestCertificateUtils.CreateCertificate();
        var headers = CreateX5THeader(cert);
        var message = CreateMessageWithHeaders(headers);

        var resolver = new CertificateSigningKeyResolver();
        var result = resolver.Resolve(message);

        Assert.That(result.IsSuccess, Is.False);
        Assert.That(result.ErrorCode, Is.EqualTo(CertificateSigningKeyResolver.ClassStrings.ErrorCodeMissingOrInvalidChain));
    }

    [Test]
    public void Resolve_WithMissingX5T_ReturnsFailure()
    {
        using var cert = TestCertificateUtils.CreateCertificate();
        var headers = new CoseHeaderMap();
        AddX5ChainHeader(headers, new[] { cert });

        var message = CreateMessageWithHeaders(headers);

        var resolver = new CertificateSigningKeyResolver();
        var result = resolver.Resolve(message);

        Assert.That(result.IsSuccess, Is.False);
        Assert.That(result.ErrorCode, Is.EqualTo(CertificateSigningKeyResolver.ClassStrings.ErrorCodeMissingOrInvalidThumbprint));
    }

    [Test]
    public void Resolve_WhenSigningCertificateNotFound_ReturnsFailure()
    {
        using var certA = TestCertificateUtils.CreateCertificate("A");
        using var certB = TestCertificateUtils.CreateCertificate("B");

        var headers = CreateX5THeader(certA);
        AddX5ChainHeader(headers, new[] { certB });

        var message = CreateMessageWithHeaders(headers);

        var resolver = new CertificateSigningKeyResolver();
        var result = resolver.Resolve(message);

        Assert.That(result.IsSuccess, Is.False);
        Assert.That(result.ErrorCode, Is.EqualTo(CertificateSigningKeyResolver.ClassStrings.ErrorCodeSigningCertNotFound));
    }

    [Test]
    public void Resolve_WithValidX5TAndX5Chain_ReturnsSigningKey()
    {
        using var cert = TestCertificateUtils.CreateCertificate();

        var headers = CreateX5THeader(cert);
        AddX5ChainHeader(headers, new[] { cert });

        var message = CreateMessageWithHeaders(headers);

        var resolver = new CertificateSigningKeyResolver();
        var result = resolver.Resolve(message);

        Assert.That(result.IsSuccess, Is.True);
        Assert.That(result.SigningKey, Is.Not.Null);
        Assert.That(result.Thumbprint, Is.Not.Null);
        Assert.That(result.ErrorCode, Is.Null);
    }

    [Test]
    public async Task ResolveAsync_ReturnsSameResultAsResolve()
    {
        using var cert = TestCertificateUtils.CreateCertificate();

        var headers = CreateX5THeader(cert);
        AddX5ChainHeader(headers, new[] { cert });

        var message = CreateMessageWithHeaders(headers);

        var resolver = new CertificateSigningKeyResolver();

        var sync = resolver.Resolve(message);
        var asyncResult = await resolver.ResolveAsync(message, CancellationToken.None);

        Assert.That(asyncResult.IsSuccess, Is.EqualTo(sync.IsSuccess));
        Assert.That(asyncResult.ErrorCode, Is.EqualTo(sync.ErrorCode));
    }
}
