// ---------------------------------------------------------------------------
// <copyright file="CoseSign1IntegrationTestsWithFactory.cs" company="Microsoft">
//     Copyright (c) Microsoft Corporation. All rights reserved.
// </copyright>
// ---------------------------------------------------------------------------

namespace CoseSign1.Tests;

using Category = NUnit.Framework.CategoryAttribute;

/// <summary>
/// Tests CreateCoseSign1 Message Using <see cref="ICoseSign1MessageFactory"/>
/// </summary>
[Category("Integration")]
public class CoseSign1IntegrationTestsWithFactory
{
    /// <summary>
    /// Integration Tests using factory class method.
    /// </summary>
    [Test]
    public void TestCreateCoseSign1MessageBytesSuccess()
    {
        //provide test cert and test testPayload
        X509Certificate2 testSigningCert = TestCertificateUtils.CreateCertificate(nameof(TestCreateCoseSign1MessageBytesSuccess));
        byte[] testPayload = Encoding.ASCII.GetBytes("Payload1!");

        //create object of custom ChainBuilder
        ICertificateChainBuilder testChainBuilder = new TestChainBuilder(nameof(TestCreateCoseSign1MessageBytesSuccess));

        //create coseSignKeyProvider with custom chainbuilder and local cert
        //if no chainbuilder is specified, it will default to X509ChainBuilder, but that can't be used for integration tests
        ICoseSigningKeyProvider testSigningKeyProvider = new X509Certificate2CoseSigningKeyProvider(testChainBuilder, testSigningCert);

        ICoseSign1MessageFactory Factory = new CoseSign1MessageFactory();

        //call CreateCoseSign1MessageBytes method of CoseSign1MessageFactory
        var responseAsBytes = Factory.CreateCoseSign1MessageBytes(testPayload, testSigningKeyProvider);

        //verify response
        responseAsBytes.Should().NotBeNull();
        responseAsBytes.Should().BeOfType<ReadOnlyMemory<byte>>();

        var responseAsCoseSign1Message = Factory.CreateCoseSign1Message(testPayload, testSigningKeyProvider);
        responseAsCoseSign1Message.Equals(CoseMessage.DecodeSign1(responseAsBytes.ToArray()));

        responseAsCoseSign1Message.ProtectedHeaders.Should().HaveCount(c => c == 4);

        responseAsCoseSign1Message.UnprotectedHeaders.Should().BeEmpty();
    }

    /// <summary>
    /// Integration Tests using With Custom Header Extender using factory class method.
    /// </summary>
    [Test]
    public void TestWithCustomHeaderExtender()
    {
        //provide test cert and test testPayload.
        X509Certificate2 testSigningCert = TestCertificateUtils.CreateCertificate(nameof(TestWithCustomHeaderExtender));

        ReadOnlyMemory<byte> testPayload = Encoding.ASCII.GetBytes("Payload1!");

        //TestChainBuilder is the custom test implementation class for ICertificateChainBuilder
        ICertificateChainBuilder testChainBuilder = new TestChainBuilder(nameof(TestWithCustomHeaderExtender));

        //create coseSignKeyProvider with local cert.
        ICoseSigningKeyProvider testSigningKeyProvider = new X509Certificate2CoseSigningKeyProvider(testChainBuilder, testSigningCert);

        //create TestHeaderExtender object to extend the CoseHeaders with the custom headers.
        //TestHeaderExtender is the test implementation class for ICoseHeaderExtender.
        ICoseHeaderExtender testHeaderExtender = new TestHeaderExtender();

        //create factory class object.
        ICoseSign1MessageFactory Factory = new CoseSign1MessageFactory();

        //call CreateCoseSign1MessageBytes method of CoseSign1MessageFactory
        var responseAsBytes = Factory.CreateCoseSign1MessageBytes(testPayload, testSigningKeyProvider, false, ContentTypeConstants.Cose, testHeaderExtender);

        //verify response
        responseAsBytes.Should().NotBeNull();
        responseAsBytes.Should().BeOfType<ReadOnlyMemory<byte>>();
        var responseAsCoseSign1Message = Factory.CreateCoseSign1Message(testPayload, testSigningKeyProvider, false, ContentTypeConstants.Cose, testHeaderExtender);

        responseAsCoseSign1Message.ProtectedHeaders.Should().NotBeNull();

        //checking if the count of protected headers are 4.
        responseAsCoseSign1Message.ProtectedHeaders.Should().HaveCount(c => c == 5);

        responseAsCoseSign1Message.ProtectedHeaders.First().Key.Should().Be(CoseHeaderLabel.Algorithm); // this is the algo header added by the CoseSigner

        responseAsCoseSign1Message.UnprotectedHeaders.Should().NotBeNull();

        responseAsCoseSign1Message.UnprotectedHeaders.Should().HaveCount(c => c == 1);

    }

    /// <summary>
    /// Testing when signing key provider is supplied as null
    /// </summary>
    [Test]
    public void TestForNullArgumentException()
    {
        CoseSign1MessageFactory coseSign1MessageFactory = new();
        ReadOnlyMemory<byte> testPayload = Encoding.ASCII.GetBytes("Payload1!");

        // Try creating CoseSign1Message with a null signing key provider
        var exceptionText = Assert.Throws<ArgumentNullException>(() =>
            coseSign1MessageFactory.CreateCoseSign1Message(testPayload,
            signingKeyProvider: null, embedPayload: false, ContentTypeConstants.Cose, headerExtender: null));

        exceptionText.Message.Should().Be("Signing key provider is not provided.");
    }

    /// <summary>
    /// Testing when payload is empty or of length 0.
    /// </summary>
    [Test]
    public void TestForArgumentOutOfRangeException()
    {
        //provide test cert and test testPayload.
        X509Certificate2 testSigningCert = TestCertificateUtils.CreateCertificate(nameof(TestForArgumentOutOfRangeException));

        ReadOnlyMemory<byte> testPayload = ReadOnlyMemory<byte>.Empty;

        //create coseSignKeyProvider with local cert.
        ICoseSigningKeyProvider testSigningKeyProvider = new X509Certificate2CoseSigningKeyProvider(testSigningCert);

        //create factory class object.
        ICoseSign1MessageFactory testFactory = new CoseSign1MessageFactory();

        //call CreateCoseSign1MessageBytes method of CoseSign1MessageFactory
        var exceptionText = Assert.Throws<ArgumentOutOfRangeException>(() => testFactory.CreateCoseSign1MessageBytes(testPayload, testSigningKeyProvider));

        exceptionText.Message.Should().Be("The payload to sign is empty.");
    }

    /// <summary>
    /// Checking for exceptions when ChainBuilder.Build runs in SigningKeyProvider's GetCertificateChain
    /// </summary>
    [Test]
    public void TestExceptionWhenChainBuilderBuildFalse()
    {
        // Provide test cert and payload.
        X509Certificate2Collection testSigningCerts = TestCertificateUtils.CreateTestChain(nameof(TestExceptionWhenChainBuilderBuildFalse));
        ReadOnlyMemory<byte> testPayload = Encoding.ASCII.GetBytes("Payload1!");

        // Create SigningKeyProvider from the leaf cert.
        // This will use the default ChainBuilder, which would normally fail when Build is called because the leaf cert doesn't chain to a trusted root,
        // but should pass because we set the valiadion policy to ValidationFlags.AllFlags.
        ICoseSigningKeyProvider testSigningKeyProvider = new X509Certificate2CoseSigningKeyProvider(testSigningCerts.Last());

        // Create TestHeaderExtender object to extend the CoseHeaders with the custom headers.
        ICoseHeaderExtender testHeaderExtender = new TestHeaderExtender();

        // Create factory and call it's CreateCoseSign1MessageBytes method.
        ICoseSign1MessageFactory Factory = new CoseSign1MessageFactory();
        _ = Factory.CreateCoseSign1MessageBytes(testPayload, testSigningKeyProvider, false, ContentTypeConstants.Cose, testHeaderExtender);
    }
}
