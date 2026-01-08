// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Formats.Cbor;
using CoseSign1.Certificates.Extensions;

namespace CoseSign1.Certificates.Tests.Extensions;

[TestFixture]
public class CborWriterExtensionsTests
{
    [Test]
    public void EncodeCertList_WithNullWriter_ThrowsArgumentNullException()
    {
        // Arrange
        var certs = new List<X509Certificate2>();

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            ((CborWriter)null!).EncodeCertList(certs));
    }

    [Test]
    public void EncodeCertList_WithNullCerts_ThrowsArgumentNullException()
    {
        // Arrange
        var writer = new CborWriter();

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            writer.EncodeCertList(null!));
    }

    [Test]
    public void EncodeCertList_WithEmptyCertList_WritesEmptyByteString()
    {
        // Arrange
        var writer = new CborWriter();
        var certs = new List<X509Certificate2>();

        // Act
        writer.EncodeCertList(certs);
        var encoded = writer.Encode();

        // Assert
        Assert.That(encoded.Length, Is.GreaterThan(0));
        var reader = new CborReader(encoded);
        var byteString = reader.ReadByteString();
        Assert.That(byteString.Length, Is.EqualTo(0));
    }

    [Test]
    public void EncodeCertList_WithSingleCert_WritesByteString()
    {
        // Arrange
        var writer = new CborWriter();
        var cert = TestCertificateUtils.CreateCertificate("CN=Test");
        var certs = new List<X509Certificate2> { cert };

        try
        {
            // Act
            writer.EncodeCertList(certs);
            var encoded = writer.Encode();

            // Assert
            Assert.That(encoded.Length, Is.GreaterThan(0));
            var reader = new CborReader(encoded);
            var byteString = reader.ReadByteString();
            Assert.That(byteString, Is.EqualTo(cert.RawData));
        }
        finally
        {
            cert.Dispose();
        }
    }

    [Test]
    public void EncodeCertList_WithMultipleCerts_WritesArray()
    {
        // Arrange
        var writer = new CborWriter();
        var cert1 = TestCertificateUtils.CreateCertificate("CN=Test1");
        var cert2 = TestCertificateUtils.CreateCertificate("CN=Test2");
        var certs = new List<X509Certificate2> { cert1, cert2 };

        try
        {
            // Act
            writer.EncodeCertList(certs);
            var encoded = writer.Encode();

            // Assert
            Assert.That(encoded.Length, Is.GreaterThan(0));
            var reader = new CborReader(encoded);

            // Should be an array
            var arrayLength = reader.ReadStartArray();
            Assert.That(arrayLength, Is.EqualTo(2));

            // First cert
            var cert1Data = reader.ReadByteString();
            Assert.That(cert1Data, Is.EqualTo(cert1.RawData));

            // Second cert
            var cert2Data = reader.ReadByteString();
            Assert.That(cert2Data, Is.EqualTo(cert2.RawData));

            reader.ReadEndArray();
        }
        finally
        {
            cert1.Dispose();
            cert2.Dispose();
        }
    }

    [Test]
    public void EncodeCertList_WithThreeCerts_WritesArrayWithAllCerts()
    {
        // Arrange
        var writer = new CborWriter();
        var cert1 = TestCertificateUtils.CreateCertificate("CN=Cert1");
        var cert2 = TestCertificateUtils.CreateCertificate("CN=Cert2");
        var cert3 = TestCertificateUtils.CreateCertificate("CN=Cert3");
        var certs = new List<X509Certificate2> { cert1, cert2, cert3 };

        try
        {
            // Act
            writer.EncodeCertList(certs);
            var encoded = writer.Encode();

            // Assert
            var reader = new CborReader(encoded);
            var arrayLength = reader.ReadStartArray();
            Assert.That(arrayLength, Is.EqualTo(3));

            reader.ReadByteString(); // cert1
            reader.ReadByteString(); // cert2
            reader.ReadByteString(); // cert3

            reader.ReadEndArray();
        }
        finally
        {
            cert1.Dispose();
            cert2.Dispose();
            cert3.Dispose();
        }
    }

    [Test]
    public void EncodeCertList_ResetsWriter()
    {
        // Arrange
        var writer = new CborWriter();
        writer.WriteInt32(42); // Write something first
        var cert = TestCertificateUtils.CreateCertificate("CN=Test");
        var certs = new List<X509Certificate2> { cert };

        try
        {
            // Act
            writer.EncodeCertList(certs);
            var encoded = writer.Encode();

            // Assert - Should only contain the cert, not the int32
            var reader = new CborReader(encoded);
            var byteString = reader.ReadByteString();
            Assert.That(byteString, Is.EqualTo(cert.RawData));
        }
        finally
        {
            cert.Dispose();
        }
    }
}