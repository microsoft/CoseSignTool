// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Tests;

using CoseSign1;

/// <summary>
/// Tests that the RSA signature padding chosen by a signing key provider is honored when the
/// COSE_Sign1 message is built, since the padding selects the COSE algorithm family
/// (PS256/PS384/PS512 for PSS, RS256/RS384/RS512 for PKCS#1 v1.5).
/// </summary>
[TestFixture]
public class RsaSignaturePaddingTests
{
    /// <summary>
    /// The COSE header label for the signature algorithm.
    /// </summary>
    private const int AlgorithmHeaderLabel = 1;

    /// <summary>
    /// A signing key provider that exposes the RSA signature padding for testing.
    /// </summary>
    private sealed class PaddingAwareSigningKeyProvider : X509Certificate2CoseSigningKeyProvider
    {
        public PaddingAwareSigningKeyProvider(X509Certificate2 certificate, HashAlgorithmName? hashAlgorithm, RSASignaturePadding padding)
            : base(certificate, hashAlgorithm)
        {
            RSASignaturePadding = padding;
        }
    }

    /// <summary>
    /// Verifies that each hash algorithm and padding combination produces the expected COSE algorithm.
    /// </summary>
    /// <param name="hashAlgorithmName">The hash algorithm to sign with.</param>
    /// <param name="usePkcs1">Whether to use PKCS#1 v1.5 padding instead of PSS.</param>
    /// <param name="expectedAlgorithm">The expected COSE algorithm identifier.</param>
    [TestCase("SHA256", false, -37)]
    [TestCase("SHA384", false, -38)]
    [TestCase("SHA512", false, -39)]
    [TestCase("SHA256", true, -257)]
    [TestCase("SHA384", true, -258)]
    [TestCase("SHA512", true, -259)]
    public void SignedMessage_UsesExpectedCoseAlgorithm(string hashAlgorithmName, bool usePkcs1, int expectedAlgorithm)
    {
        X509Certificate2 certificate = TestCertificateUtils.CreateCertificate(nameof(RsaSignaturePaddingTests));
        PaddingAwareSigningKeyProvider provider = new(
            certificate,
            new HashAlgorithmName(hashAlgorithmName),
            usePkcs1 ? RSASignaturePadding.Pkcs1 : RSASignaturePadding.Pss);

        CoseSign1Message message = new CoseSign1MessageFactory().CreateCoseSign1Message(
            Encoding.ASCII.GetBytes("payload"),
            provider,
            embedPayload: true);

        Assert.That(
            message.ProtectedHeaders[new CoseHeaderLabel(AlgorithmHeaderLabel)].GetValueAsInt32(),
            Is.EqualTo(expectedAlgorithm));
    }

    /// <summary>
    /// Verifies that a provider which does not choose a padding keeps the historical PSS behavior,
    /// so existing signatures are unaffected by the padding becoming selectable.
    /// </summary>
    [Test]
    public void SignedMessage_DefaultProvider_StillUsesPss()
    {
        X509Certificate2 certificate = TestCertificateUtils.CreateCertificate(nameof(RsaSignaturePaddingTests));
        X509Certificate2CoseSigningKeyProvider provider = new(certificate);

        CoseSign1Message message = new CoseSign1MessageFactory().CreateCoseSign1Message(
            Encoding.ASCII.GetBytes("payload"),
            provider,
            embedPayload: true);

        // -37 is PS256.
        Assert.That(
            message.ProtectedHeaders[new CoseHeaderLabel(AlgorithmHeaderLabel)].GetValueAsInt32(),
            Is.EqualTo(-37));
    }
}