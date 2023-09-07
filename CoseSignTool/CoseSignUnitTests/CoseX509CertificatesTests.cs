// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignUnitTests;

[TestClass]
public class CoseX509CertificatesTests
{
    [TestMethod]
    public void CoseX509Certificates_EncodeCertList_OneCert()
    {
        List<X509Certificate2> expectedCerts = new()
        {
            TestCertificateUtils.CreateCertificate($"{nameof(CoseX509Certificates_EncodeCertList_OneCert)}_TestCert")

        };

        CborWriter cborWriter = new();
        cborWriter.WriteTextString("woohoo");
        cborWriter.EncodeCertList(expectedCerts);

        CborReader cborReader = new(cborWriter.Encode());

        CborReaderState.ByteString.Should().Be(cborReader.PeekState(), "Validate that the writer was reset");

        //Work through the structure as CborReader will throw if the state machine does not match the read request
        _ = cborReader.ReadByteString();
    }

    [TestMethod]
    public void CoseX509Certificates_EncodeCertList_TwoCerts()
    {
        X509Certificate2Collection expectedCerts = new()
        {
            TestCertificateUtils.CreateCertificate($"{nameof(CoseX509Certificates_EncodeCertList_TwoCerts)}_Cert1"),
            TestCertificateUtils.CreateCertificate($"{nameof(CoseX509Certificates_EncodeCertList_OneCert)}_Cert2")
        };

        CborWriter cborWriter = new();
        cborWriter.WriteTextString("woo");
        cborWriter.EncodeCertList(expectedCerts);

        CborReader cborReader = new(cborWriter.Encode());

        CborReaderState.StartArray.Should().Be(cborReader.PeekState(), "Validate that the writer was reset and starts with an array");
        expectedCerts.Count.Should().Be(cborReader.ReadStartArray(), "Array sizes match");

        //Work through the structure as CborReader will throw if the state machine does not match the read request
        _ = cborReader.ReadByteString();
        _ = cborReader.ReadByteString();
        cborReader.ReadEndArray();
    }
}