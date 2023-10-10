// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignUnitTests;

internal class TestsForTheUnderlyingAPI
{
    private readonly byte[] Payload1 = Encoding.ASCII.GetBytes("Payload1!");
    private const string SubjectName1 = $"{nameof(TestsForTheUnderlyingAPI)}_Cert1";
    private static readonly X509Certificate2 SelfSignedCert = TestCertificateUtils.CreateCertificate(SubjectName1); //HelperFunctions.GenerateTestCert(SubjectName1);

    /// <summary>
    /// Validates consistency between the CoseSign1Message methods SignDetached, DecodeSign1, and VerifyDetached.
    /// </summary>
    [TestMethod]
    public void ValidateCoseRoundTripDetached()
    {
        var rsaPublicKey = SelfSignedCert.GetRSAPublicKey();
        var rsaPrivateKey = SelfSignedCert.GetRSAPrivateKey();

        var signer = new CoseSigner(rsaPrivateKey, RSASignaturePadding.Pss, HashAlgorithmName.SHA256);
        byte[] encodedMsg = CoseSign1Message.SignDetached(Payload1, signer);

        CoseSign1Message msg = CoseMessage.DecodeSign1(encodedMsg);

        msg.VerifyDetached(rsaPublicKey, Payload1).Should().BeTrue("Validated CoseSign1Message");
    }

    /// <summary>
    /// Validates consistency between the CborReader, CborWriter, and CoseHeaderMap structures.
    /// </summary>
    [TestMethod]
    public void ValidateCoseRoundTripCustomHeader()
    {
        var rsaPublicKey = SelfSignedCert.GetRSAPublicKey();
        var rsaPrivateKey = SelfSignedCert.GetRSAPrivateKey();

        var writer = new CborWriter();
        writer.WriteStartArray(definiteLength: 3);
        writer.WriteInt32(42);
        writer.WriteTextString("foo");
        writer.WriteTextString("bar");
        writer.WriteEndArray();

        var myArrayHeader = new CoseHeaderLabel("my-array-header");

        CoseHeaderMap unprotectedHeaders = new()
            {
                { myArrayHeader, CoseHeaderValue.FromEncodedValue(writer.Encode()) }
            };

        // Encode but with user-defined headers.
        var signer = new CoseSigner(rsaPrivateKey, RSASignaturePadding.Pss, HashAlgorithmName.SHA256, new CoseHeaderMap(), unprotectedHeaders);
        byte[] encodedMsg = CoseSign1Message.SignDetached(Payload1, signer);

        CoseSign1Message msg = CoseMessage.DecodeSign1(encodedMsg);
        var encodedHeader = msg.UnprotectedHeaders[myArrayHeader].EncodedValue;
        CborReader reader = new(encodedHeader);

        CborReaderState.StartArray.Should().Be(reader.PeekState(), "encoded as array");

        // If the structure is wrong this will throw an exception and break the test
        reader.ReadStartArray().Should().Be(3);
        reader.ReadInt32().Should().Be(42);
        reader.ReadTextString().Should().Be("foo");
        reader.ReadTextString().Should().Be("bar");

        reader.ReadEndArray();

        msg.VerifyDetached(rsaPublicKey, Payload1).Should().BeTrue("Validated CoseSign1Message");
    }
}
