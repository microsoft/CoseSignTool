// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Tests;

/// <summary>
/// Integration Tests for CreateCoseSign1 Message Using <see cref="CoseSign1MessageBuilder"/>
/// </summary>
[NUnit.Framework.Category("Integration")]
public class CoseSign1IntegrationTestsWithBuilder
{
    /// <summary>
    /// Tests Build() with Custom CertificateChainBuilder
    /// </summary>
    [Test]
    public void TestBuildSuccess()
    {
        // Genreate test cert and test testPayload
        X509Certificate2 testSigningCert = TestCertificateUtils.CreateCertificate();
        ReadOnlyMemory<byte> testPayload = Encoding.ASCII.GetBytes("Payload1!");

        // Custom Test Class for implementing ICertificateChainBuilder
        ICertificateChainBuilder testChainBuilder = new TestChainBuilder();

        // Create coseSignKeyProvider with local cert
        ICoseSigningKeyProvider testSigningKeyProvider = new X509Certificate2CoseSigningKeyProvider(testChainBuilder, testSigningCert);

        // Create the builder class object
        CoseSign1MessageBuilder testBuilder = new(testSigningKeyProvider);

        // Call build method which calls CreateCoseSign1Message method of CoseSign1MessageFactory
        CoseSign1Message response = testBuilder.SetPayloadBytes(testPayload)
                                                .SetContentType(ContentTypeConstants.Cose)
                                                .SetEmbedPayload(false).Build();

        // Verify response
        response.Should().NotBeNull();
        response.Should().BeOfType<CoseSign1Message>();
        response.ProtectedHeaders.Should().NotBeNull();

        // Verify all expected headers are present:
        // 1. Algorithm header (from CoseSigner)
        // 2-3. Default headers from CertificateCoseSigningKeyProvider (X5Chain, X5T)
        // 4. CWT Claims header (automatically added for SCITT compliance)
        // 5. Content Type header
        response.ProtectedHeaders.Should().HaveCount(c => c == 5);
        response.ProtectedHeaders.Should().ContainKey(CoseHeaderLabel.Algorithm);
        response.ProtectedHeaders.Should().ContainKey(CertificateCoseHeaderLabels.X5Chain);
        response.ProtectedHeaders.Should().ContainKey(CertificateCoseHeaderLabels.X5T);
        response.ProtectedHeaders.Should().ContainKey(CWTClaimsHeaderLabels.CWTClaims);
        response.ProtectedHeaders.Should().ContainKey(CoseHeaderLabel.ContentType);

        response.UnprotectedHeaders.Should().BeEmpty();
    }

    /// <summary>
    /// Tests Build() with Custom HeaderExtender
    /// </summary>
    [Test]
    public void TestBuildSuccessWithCustomHeaderExtender()
    {
        // Provide the test cert and test testPayload
        X509Certificate2 testSigningCert = TestCertificateUtils.CreateCertificate();
        ReadOnlyMemory<byte> testPayload = Encoding.ASCII.GetBytes("Payload1!");

        // Custom Test Class for implementing ICertificateChainBuilder
        ICertificateChainBuilder testChainBuilder = new TestChainBuilder();

        // Create coseSignKeyProvider with local cert
        ICoseSigningKeyProvider testSigningKeyProvider = new X509Certificate2CoseSigningKeyProvider(testChainBuilder, testSigningCert);

        // Create ICoseHeaderExtender instance to extend the CoseHeaders with the custom headers
        ICoseHeaderExtender testHeaderExtender = new TestHeaderExtender();

        // Create the builder class object
        CoseSign1MessageBuilder testBuilder = new(testSigningKeyProvider);

        // Call the Build method which calls CreateCoseSign1Message method of CoseSign1MessageFactory
        CoseSign1Message response = testBuilder.SetPayloadBytes(testPayload)
                                    .SetContentType(ContentTypeConstants.Cose)
                                    .SetEmbedPayload(false)
                                    .ExtendCoseHeader(testHeaderExtender).Build();

        // Verify response
        response.Should().NotBeNull();
        response.Should().BeOfType<CoseSign1Message>();
        response.ProtectedHeaders.Should().NotBeNull();

        // Verify all expected headers are present:
        // 1. Algorithm header (from CoseSigner)
        // 2-3. Default headers from provider (X5Chain, X5T)
        // 4. CWT Claims header (automatically added for SCITT compliance)
        // 5. Content Type header
        // 6. Custom header from TestHeaderExtender
        response.ProtectedHeaders.Should().HaveCount(c => c == 6);
        response.ProtectedHeaders.First().Key.Should().Be(CoseHeaderLabel.Algorithm);
        response.ProtectedHeaders.Should().ContainKey(CoseHeaderLabel.Algorithm);
        response.ProtectedHeaders.Should().ContainKey(CertificateCoseHeaderLabels.X5Chain);
        response.ProtectedHeaders.Should().ContainKey(CertificateCoseHeaderLabels.X5T);
        response.ProtectedHeaders.Should().ContainKey(CWTClaimsHeaderLabels.CWTClaims);
        response.ProtectedHeaders.Should().ContainKey(CoseHeaderLabel.ContentType);

        // Verify unprotected headers contains the custom header from TestHeaderExtender
        response.UnprotectedHeaders.Should().NotBeNull();
        response.UnprotectedHeaders.Should().HaveCount(c => c == 1);
        CoseHeaderLabel expectedUnprotectedLabel = new("test-header-label1");
        response.UnprotectedHeaders.Should().ContainKey(expectedUnprotectedLabel);
    }

    /// <summary>
    /// Testing when payload is empty or of length 0.
    /// </summary>
    [Test]
    public void TestArgumentOutOfRangeExceptionForBuilder()
    {
        // Provide test cert and test testPayload.
        X509Certificate2 testSigningCert = TestCertificateUtils.CreateCertificate();
        ReadOnlyMemory<byte> testPayload = ReadOnlyMemory<byte>.Empty;

        // Create coseSignKeyProvider with local cert
        ICoseSigningKeyProvider testSigningKeyProvider = new X509Certificate2CoseSigningKeyProvider(testSigningCert);

        // Create factory class object.
        CoseSign1MessageBuilder testBuilder = new(testSigningKeyProvider);

        // Call SetPayloadBytes method of CoseSign1MessageBuilder
        ArgumentOutOfRangeException? exceptionText = Assert.Throws<ArgumentOutOfRangeException>(() => testBuilder.SetPayloadBytes(testPayload).Build());
        exceptionText.Message.Should().Be("The payload to sign is empty.");
    }
}

