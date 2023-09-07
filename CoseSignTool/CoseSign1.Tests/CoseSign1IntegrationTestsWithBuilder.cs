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
        X509Certificate2 testSigningCert = TestCertificateUtils.CreateCertificate(nameof(TestBuildSuccess));
        ReadOnlyMemory<byte> testPayload = Encoding.ASCII.GetBytes("Payload1!");

        // Custom Test Class for implementing ICertificateChainBuilder
        ICertificateChainBuilder testChainBuilder = new TestChainBuilder(nameof(TestBuildSuccess));

        // Create coseSignKeyProvider with local cert
        ICoseSigningKeyProvider testSigningKeyProvider = new X509Certificate2CoseSigningKeyProvider(testChainBuilder, testSigningCert);

        // Create the builder class object
        CoseSign1MessageBuilder testBuilder = new(testSigningKeyProvider);

        // Call build method which calls CreateCoseSign1Message method of CoseSign1MessageFactory
        var response = testBuilder.SetPayloadBytes(testPayload)
                                                .SetContentType(ContentTypeConstants.Cose)
                                                .SetEmbedPayload(false).Build();

        // Verify response
        response.Should().NotBeNull();
        response.Should().BeOfType<CoseSign1Message>();
        response.ProtectedHeaders.Should().NotBeNull();

        // There should be 4 ProtectedHeaders.
        // First one is the algo header provided by Cosesigner. The second and third are from the Default ProtectedHeaders provided by CertificateCoseSignerKeyProvider
        // The last is the Content Type header provided by the user.
        response.ProtectedHeaders.Should().HaveCount(c => c == 4);

        response.UnprotectedHeaders.Should().BeEmpty();
    }

    /// <summary>
    /// Tests Build() with Custom HeaderExtender
    /// </summary>
    [Test]
    public void TestBuildSuccessWithCustomHeaderExtender()
    {
        // Provide the test cert and test testPayload
        X509Certificate2 testSigningCert = TestCertificateUtils.CreateCertificate(nameof(TestBuildSuccessWithCustomHeaderExtender));
        ReadOnlyMemory<byte> testPayload = Encoding.ASCII.GetBytes("Payload1!");

        // Custom Test Class for implementing ICertificateChainBuilder
        ICertificateChainBuilder testChainBuilder = new TestChainBuilder(nameof(TestBuildSuccessWithCustomHeaderExtender));

        // Create coseSignKeyProvider with local cert
        ICoseSigningKeyProvider testSigningKeyProvider = new X509Certificate2CoseSigningKeyProvider(testChainBuilder, testSigningCert);

        // Create ICoseHeaderExtender instance to extend the CoseHeaders with the custom headers
        ICoseHeaderExtender testHeaderExtender = new TestHeaderExtender();

        // Create the builder class object
        CoseSign1MessageBuilder testBuilder = new(testSigningKeyProvider);

        // Call the Build method which calls CreateCoseSign1Message method of CoseSign1MessageFactory
        var response = testBuilder.SetPayloadBytes(testPayload)
                                    .SetContentType(ContentTypeConstants.Cose)
                                    .SetEmbedPayload(false)
                                    .ExtendCoseHeader(testHeaderExtender).Build();

        // Verify response
        response.Should().NotBeNull();
        response.Should().BeOfType<CoseSign1Message>();
        response.ProtectedHeaders.Should().NotBeNull();

        // The count of protected headers should be 5.
        response.ProtectedHeaders.Should().HaveCount(c => c == 5);
        response.ProtectedHeaders.First().Key.Should().Be(CoseHeaderLabel.Algorithm); // this is the algo header added by the CoseSigner

        // Count of Unprotected headers should be 1.
        response.UnprotectedHeaders.Should().NotBeNull();
        response.UnprotectedHeaders.Should().HaveCount(c => c == 1);
    }

    /// <summary>
    /// Testing when payload is empty or of length 0.
    /// </summary>
    [Test]
    public void TestArgumentOutOfRangeExceptionForBuilder()
    {
        // Provide test cert and test testPayload.
        X509Certificate2 testSigningCert = TestCertificateUtils.CreateCertificate(nameof(TestArgumentOutOfRangeExceptionForBuilder));
        ReadOnlyMemory<byte> testPayload = ReadOnlyMemory<byte>.Empty;

        // Create coseSignKeyProvider with local cert
        ICoseSigningKeyProvider testSigningKeyProvider = new X509Certificate2CoseSigningKeyProvider(testSigningCert);

        // Create factory class object.
        CoseSign1MessageBuilder testBuilder = new(testSigningKeyProvider);

        // Call SetPayloadBytes method of CoseSign1MessageBuilder
        var exceptionText = Assert.Throws<ArgumentOutOfRangeException>(() => testBuilder.SetPayloadBytes(testPayload).Build());
        exceptionText.Message.Should().Be("The payload to sign is empty.");
    }
}

