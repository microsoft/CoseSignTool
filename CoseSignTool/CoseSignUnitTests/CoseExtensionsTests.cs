// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignUnitTests;

[TestClass]
public class CoseExtensionsTests
{
    private readonly byte[] Payload1 = Encoding.ASCII.GetBytes("Payload1!");
    private const string SubjectName1 = $"{nameof(CoseExtensionsTests)}_TestCert";
    private static readonly X509Certificate2Collection CertChain = TestCertificateUtils.CreateTestChain(SubjectName1);
    private static readonly X509Certificate2 SelfSignedRoot = CertChain[0];
    private static readonly X509Certificate2 ChainedCert = CertChain[^1];

    [TestMethod]
    public void TryGetSigningCert()
    {
        // Create a COSE signature from a chained cert
        string signedFile = Path.GetTempFileName();
        X509Certificate2CoseSigningKeyProvider signer = new (ChainedCert);
        ReadOnlyMemory<byte> sigBlock = CoseHandler.Sign(Payload1, signer, false, new FileInfo(signedFile));

        // Make sure we can read it
        byte[] bytesFromMemory = sigBlock.ToArray();
        CoseSign1Message msg = CoseMessage.DecodeSign1(bytesFromMemory);
        msg.Should().NotBeNull();

        // Read it from the output file we created
        byte[] bytesFromFile = File.ReadAllBytes(signedFile);

        // The byte arrays should match and be readable as COSE messages
        bytesFromFile.Should().Equal(bytesFromMemory);
        msg = CoseMessage.DecodeSign1(bytesFromMemory);

        CoseSign1MessageExtensions.TryGetSigningCertificate(msg, out X509Certificate2? signCert).Should().BeTrue();
        signCert.Should().NotBeNull();
        signCert?.Thumbprint.Should().Be(ChainedCert.Thumbprint);
    }
}