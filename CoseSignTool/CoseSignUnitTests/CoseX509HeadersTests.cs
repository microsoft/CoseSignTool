// ---------------------------------------------------------------------------
// <copyright file="CoseX509HeadersTests.cs" company="Microsoft">
//     Copyright (c) Microsoft Corporation. All rights reserved.
// </copyright>
// ---------------------------------------------------------------------------

namespace CoseSignUnitTests;

[TestClass]
public class CoseX509HeadersTests
{
    [TestCategory("WindowsOnly"), TestMethod]
    [ExpectedException(typeof(CoseSign1CertificateException))]
    public void CertificateHelper_LookupUnknownCertificate()
    {
        _ = CoseHandler.LookupCertificate("unknown");
    }

    [TestMethod]
    public void CoseX509Header_ParseEmptyCertBag()
    {
        CborWriter writer = new(CborConformanceMode.Strict);
        writer.WriteByteString(Array.Empty<byte>());
        CborReader reader = new(writer.Encode());
        List<X509Certificate2> certs = new();

        reader.ReadCertificateSet(ref certs);

        bool certCountZero = (certs.Count == 0);
        certCountZero.Should().BeTrue("Certificate collection should be empty");
    }

    [TestMethod]
    public void CoseX509Header_ParseCertBagOfOne()
    {
        X509Certificate2Collection expectedCerts = new()
        {
            // expectedCerts.Add(HelperFunctions.GenerateTestCert("cn=test1"));
            TestCertificateUtils.CreateCertificate($"{nameof(CoseX509Header_ParseCertBagOfOne)}_TestCert")
        };

        CborWriter writer = new(CborConformanceMode.Strict);
        writer.WriteByteString(expectedCerts[0].RawData);
        CborReader reader = new(writer.Encode());
        List<X509Certificate2> certs = new();

        reader.ReadCertificateSet(ref certs);

        expectedCerts.Count.Should().Be(certs.Count, $"Parsed cert count should match expected of {expectedCerts.Count}");

        expectedCerts.Should().BeEquivalentTo(certs, options => options.WithStrictOrdering(), "Expected certs should match actual");
    }

    [TestMethod]
    public void CoseX509Header_ParseCertBagOfTwo()
    {
        X509Certificate2Collection expectedCerts = new()
        {
            //expectedCerts.Add(HelperFunctions.GenerateTestCert("cn=test1"));
            //expectedCerts.Add(HelperFunctions.GenerateTestCert("cn=test2"));
            TestCertificateUtils.CreateCertificate($"{nameof(CoseX509Header_ParseCertBagOfTwo)}_Cert1"),
            TestCertificateUtils.CreateCertificate($"{nameof(CoseX509Header_ParseCertBagOfTwo)}_Cert2")
        };

        CborWriter writer = new(CborConformanceMode.Strict);
        writer.WriteStartArray(expectedCerts.Count);
        foreach (var cert in expectedCerts)
        {
            writer.WriteByteString(cert.RawData);
        }
        writer.WriteEndArray();
        CborReader reader = new(writer.Encode());
        List<X509Certificate2> certs = new();

        reader.ReadCertificateSet(ref certs);

        expectedCerts.Count.Should().Be(certs.Count, $"Parsed cert count should match expected of {expectedCerts.Count}");

        expectedCerts.Should().BeEquivalentTo(certs, options => options.WithStrictOrdering(), "Expected certs should match actual");
    }

    [TestMethod]
    [ExpectedException(typeof(CoseX509FormatException))]
    public void CoseX509Header_ParseCertBag_FirstLevelIncorrectType()
    {
        CborWriter writer = new(CborConformanceMode.Strict);
        writer.WriteInt32(42);
        CborReader reader = new(writer.Encode());
        List<X509Certificate2> certs = new();

        reader.ReadCertificateSet(ref certs);
    }

    [TestMethod]
    [ExpectedException(typeof(CoseX509FormatException))]
    public void CoseX509Header_ParseCertBag_ArrayElement1WrongType()
    {
        CborWriter writer = new(CborConformanceMode.Strict);
        writer.WriteStartArray(1);
        writer.WriteInt32(42);
        writer.WriteEndArray();
        CborReader reader = new(writer.Encode());
        List<X509Certificate2> certs = new();

        reader.ReadCertificateSet(ref certs);
    }

    [TestMethod]
    [ExpectedException(typeof(CoseX509FormatException))]
    public void CoseX509Header_ParseCertBag_ArrayElementNWrongType()
    {
        CborWriter writer = new(CborConformanceMode.Strict);
        writer.WriteStartArray(2);
        writer.WriteByteString(Array.Empty<byte>());
        writer.WriteInt32(42);
        writer.WriteEndArray();
        CborReader reader = new(writer.Encode());
        List<X509Certificate2> certs = new();

        reader.ReadCertificateSet(ref certs);
    }

    [TestMethod]
    [ExpectedException(typeof(CoseX509FormatException))]
    public void CoseX509Thumbprint_EmptyEnvelope()
    {
        CborWriter writer = new(CborConformanceMode.Strict);
        writer.WriteByteString(Array.Empty<byte>());

        var thumbprint = CoseX509Thumprint.Deserialize(new CborReader(writer.Encode()));
    }

    [TestMethod]
    [ExpectedException(typeof(CoseX509FormatException))]
    public void CoseX509Thumbprint_ArrayWrongSize()
    {
        CborWriter writer = new(CborConformanceMode.Strict);
        writer.WriteStartArray(1);
        writer.WriteInt32(42);
        writer.WriteEndArray();

        var thumbprint = CoseX509Thumprint.Deserialize(new CborReader(writer.Encode()));
    }

    [TestMethod]
    [ExpectedException(typeof(CoseX509FormatException))]
    public void CoseX509Thumbprint_ArrayFirstElementWrongType()
    {
        CborWriter writer = new(CborConformanceMode.Strict);
        writer.WriteStartArray(2);
        writer.WriteTextString("break");
        writer.WriteByteString(Array.Empty<byte>());
        writer.WriteEndArray();

        var thumbprint = CoseX509Thumprint.Deserialize(new CborReader(writer.Encode()));
    }


    [TestMethod]
    [ExpectedException(typeof(CoseX509FormatException))]
    public void CoseX509Thumbprint_ArraySecondElementWrongType()
    {
        CborWriter writer = new(CborConformanceMode.Strict);
        writer.WriteStartArray(2);
        writer.WriteInt32(42);
        writer.WriteInt32(42);
        writer.WriteEndArray();

        var thumbprint = CoseX509Thumprint.Deserialize(new CborReader(writer.Encode()));
    }
}
