// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Tests;

using System.Security.Cryptography.Cose;
using System.Security.Cryptography.X509Certificates;
using CoseSign1.Certificates.Local;
using CoseSign1.Headers;
using CoseSign1.Tests.Common;
using NUnit.Framework;

/// <summary>
/// Tests for the X509CertificateWithCWTClaimsHeaderExtender class.
/// </summary>
[TestFixture]
public class X509CertificateWithCWTClaimsHeaderExtenderTests
{
    private static void DisposeCertificates(X509Certificate2Collection collection)
    {
        foreach (var cert in collection)
        {
            cert.Dispose();
        }
    }

    [Test]
    public void Constructor_WithNullCustomClaims_CreatesDefaultClaims()
    {
        // Arrange
        X509Certificate2Collection testChain = TestCertificateUtils.CreateTestChain();
        X509Certificate2 leafCert = testChain[^1];
        var signingKeyProvider = new X509Certificate2CoseSigningKeyProvider(null, leafCert, [.. testChain]);

        // Act
        var extender = new X509CertificateWithCWTClaimsHeaderExtender(signingKeyProvider, null);

        // Assert
        Assert.That(extender, Is.Not.Null);
        Assert.That(extender.ActiveCWTClaimsExtender, Is.Not.Null);

        // Cleanup
        DisposeCertificates(testChain);
    }

    [Test]
    public void Constructor_WithCustomClaims_UsesCustomClaims()
    {
        // Arrange
        X509Certificate2Collection testChain = TestCertificateUtils.CreateTestChain();
        X509Certificate2 leafCert = testChain[^1];
        var signingKeyProvider = new X509Certificate2CoseSigningKeyProvider(null, leafCert, [.. testChain]);
        var customClaims = new CWTClaimsHeaderExtender();
        customClaims.SetIssuer("custom-issuer");
        customClaims.SetSubject("custom-subject");

        // Act
        var extender = new X509CertificateWithCWTClaimsHeaderExtender(signingKeyProvider, customClaims);

        // Assert
        Assert.That(extender.ActiveCWTClaimsExtender, Is.SameAs(customClaims));

        // Cleanup
        DisposeCertificates(testChain);
    }

    [Test]
    public void Constructor_WithNullProvider_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            new X509CertificateWithCWTClaimsHeaderExtender(null!, null));
    }

    [Test]
    public void ActiveCWTClaimsExtender_ReturnsExtender()
    {
        // Arrange
        X509Certificate2Collection testChain = TestCertificateUtils.CreateTestChain();
        X509Certificate2 leafCert = testChain[^1];
        var signingKeyProvider = new X509Certificate2CoseSigningKeyProvider(null, leafCert, [.. testChain]);
        var extender = new X509CertificateWithCWTClaimsHeaderExtender(signingKeyProvider, null);

        // Act
        var active = extender.ActiveCWTClaimsExtender;

        // Assert
        Assert.That(active, Is.Not.Null);
        Assert.That(active, Is.InstanceOf<CWTClaimsHeaderExtender>());

        // Cleanup
        DisposeCertificates(testChain);
    }

    [Test]
    public void ExtendProtectedHeaders_AddsX509HeadersAndCWTClaims()
    {
        // Arrange
        X509Certificate2Collection testChain = TestCertificateUtils.CreateTestChain();
        X509Certificate2 leafCert = testChain[^1];
        var signingKeyProvider = new X509Certificate2CoseSigningKeyProvider(null, leafCert, [.. testChain]);
        var extender = new X509CertificateWithCWTClaimsHeaderExtender(signingKeyProvider, null);
        var headers = new CoseHeaderMap();

        // Act
        extender.ExtendProtectedHeaders(headers);

        // Assert
        // Should have X5T and CWT Claims headers
        Assert.That(headers.Count, Is.GreaterThanOrEqualTo(2));
        Assert.That(headers.ContainsKey(CWTClaimsHeaderLabels.CWTClaims), Is.True);

        // Cleanup
        DisposeCertificates(testChain);
    }

    [Test]
    public void ExtendProtectedHeaders_DefaultClaims_HasIssuerAndSubject()
    {
        // Arrange
        X509Certificate2Collection testChain = TestCertificateUtils.CreateTestChain();
        X509Certificate2 leafCert = testChain[^1];
        var signingKeyProvider = new X509Certificate2CoseSigningKeyProvider(null, leafCert, [.. testChain]);
        var extender = new X509CertificateWithCWTClaimsHeaderExtender(signingKeyProvider, null);
        var headers = new CoseHeaderMap();

        // Act
        extender.ExtendProtectedHeaders(headers);

        // Assert
        Assert.That(headers.ContainsKey(CWTClaimsHeaderLabels.CWTClaims), Is.True);
        
        // Decode the CWT claims to verify issuer and subject
        byte[] encodedClaims = headers[CWTClaimsHeaderLabels.CWTClaims].EncodedValue.ToArray();
        Assert.That(encodedClaims, Is.Not.Null);
        Assert.That(encodedClaims.Length, Is.GreaterThan(0));
        
        // Verify the claims contain the expected structure
        var reader = new System.Formats.Cbor.CborReader(encodedClaims);
        reader.ReadStartMap();
        var claimsFound = new HashSet<int>();
        while (reader.PeekState() != System.Formats.Cbor.CborReaderState.EndMap)
        {
            int label = reader.ReadInt32();
            claimsFound.Add(label);
            reader.SkipValue();
        }
        reader.ReadEndMap();

        Assert.That(claimsFound, Does.Contain(CWTClaimsHeaderLabels.Issuer));
        Assert.That(claimsFound, Does.Contain(CWTClaimsHeaderLabels.Subject));

        // Cleanup
        DisposeCertificates(testChain);
    }

    [Test]
    public void ExtendProtectedHeaders_DefaultSubject_IsUnknownIntent()
    {
        // Arrange
        X509Certificate2Collection testChain = TestCertificateUtils.CreateTestChain();
        X509Certificate2 leafCert = testChain[^1];
        var signingKeyProvider = new X509Certificate2CoseSigningKeyProvider(null, leafCert, [.. testChain]);
        var extender = new X509CertificateWithCWTClaimsHeaderExtender(signingKeyProvider, null);
        var headers = new CoseHeaderMap();

        // Act
        extender.ExtendProtectedHeaders(headers);

        // Assert
        byte[] encodedClaims = headers[CWTClaimsHeaderLabels.CWTClaims].EncodedValue.ToArray();
        var reader = new System.Formats.Cbor.CborReader(encodedClaims);
        
        reader.ReadStartMap();
        string? subjectValue = null;
        while (reader.PeekState() != System.Formats.Cbor.CborReaderState.EndMap)
        {
            int label = reader.ReadInt32();
            if (label == CWTClaimsHeaderLabels.Subject)
            {
                subjectValue = reader.ReadTextString();
            }
            else
            {
                reader.SkipValue();
            }
        }
        reader.ReadEndMap();

        Assert.That(subjectValue, Is.EqualTo("unknown.intent"));

        // Cleanup
        DisposeCertificates(testChain);
    }

    [Test]
    public void ExtendProtectedHeaders_DefaultIssuer_IsDidX509()
    {
        // Arrange
        X509Certificate2Collection testChain = TestCertificateUtils.CreateTestChain();
        X509Certificate2 leafCert = testChain[^1];
        var signingKeyProvider = new X509Certificate2CoseSigningKeyProvider(null, leafCert, [.. testChain]);
        var extender = new X509CertificateWithCWTClaimsHeaderExtender(signingKeyProvider, null);
        var headers = new CoseHeaderMap();

        // Act
        extender.ExtendProtectedHeaders(headers);

        // Assert
        byte[] encodedClaims = headers[CWTClaimsHeaderLabels.CWTClaims].EncodedValue.ToArray();
        var reader = new System.Formats.Cbor.CborReader(encodedClaims);
        
        reader.ReadStartMap();
        string? issuerValue = null;
        while (reader.PeekState() != System.Formats.Cbor.CborReaderState.EndMap)
        {
            int label = reader.ReadInt32();
            if (label == CWTClaimsHeaderLabels.Issuer)
            {
                issuerValue = reader.ReadTextString();
            }
            else
            {
                reader.SkipValue();
            }
        }
        reader.ReadEndMap();

        Assert.That(issuerValue, Does.StartWith("did:x509:0:sha256:"));
        Assert.That(issuerValue, Does.Contain("::subject:"));

        // Cleanup
        DisposeCertificates(testChain);
    }

    [Test]
    public void ExtendProtectedHeaders_CustomClaims_UsesCustomValues()
    {
        // Arrange
        X509Certificate2Collection testChain = TestCertificateUtils.CreateTestChain();
        X509Certificate2 leafCert = testChain[^1];
        var signingKeyProvider = new X509Certificate2CoseSigningKeyProvider(null, leafCert, [.. testChain]);
        var customClaims = new CWTClaimsHeaderExtender();
        customClaims.SetIssuer("custom-issuer");
        customClaims.SetSubject("custom-subject");
        var extender = new X509CertificateWithCWTClaimsHeaderExtender(signingKeyProvider, customClaims);
        var headers = new CoseHeaderMap();

        // Act
        extender.ExtendProtectedHeaders(headers);

        // Assert
        byte[] encodedClaims = headers[CWTClaimsHeaderLabels.CWTClaims].EncodedValue.ToArray();
        var reader = new System.Formats.Cbor.CborReader(encodedClaims);
        
        reader.ReadStartMap();
        var claims = new Dictionary<int, string>();
        while (reader.PeekState() != System.Formats.Cbor.CborReaderState.EndMap)
        {
            int label = reader.ReadInt32();
            string value = reader.ReadTextString();
            claims[label] = value;
        }
        reader.ReadEndMap();

        Assert.That(claims[CWTClaimsHeaderLabels.Issuer], Is.EqualTo("custom-issuer"));
        Assert.That(claims[CWTClaimsHeaderLabels.Subject], Is.EqualTo("custom-subject"));

        // Cleanup
        DisposeCertificates(testChain);
    }

    [Test]
    public void ExtendUnProtectedHeaders_DoesNotAddCWTClaims()
    {
        // Arrange
        X509Certificate2Collection testChain = TestCertificateUtils.CreateTestChain();
        X509Certificate2 leafCert = testChain[^1];
        var signingKeyProvider = new X509Certificate2CoseSigningKeyProvider(null, leafCert, [.. testChain]);
        var extender = new X509CertificateWithCWTClaimsHeaderExtender(signingKeyProvider, null);
        var headers = new CoseHeaderMap();

        // Act
        extender.ExtendUnProtectedHeaders(headers);

        // Assert
        // Unprotected headers should not contain CWT Claims (they must be in protected headers for SCITT)
        Assert.That(headers.ContainsKey(CWTClaimsHeaderLabels.CWTClaims), Is.False);

        // Cleanup
        DisposeCertificates(testChain);
    }

    [Test]
    public void ActiveCWTClaimsExtender_CanBeModified()
    {
        // Arrange
        X509Certificate2Collection testChain = TestCertificateUtils.CreateTestChain();
        X509Certificate2 leafCert = testChain[^1];
        var signingKeyProvider = new X509Certificate2CoseSigningKeyProvider(null, leafCert, [.. testChain]);
        var extender = new X509CertificateWithCWTClaimsHeaderExtender(signingKeyProvider, null);

        // Act
        extender.ActiveCWTClaimsExtender.SetAudience("test-audience");
        var headers = new CoseHeaderMap();
        extender.ExtendProtectedHeaders(headers);

        // Assert
        byte[] encodedClaims = headers[CWTClaimsHeaderLabels.CWTClaims].EncodedValue.ToArray();
        var reader = new System.Formats.Cbor.CborReader(encodedClaims);
        
        reader.ReadStartMap();
        var claimsFound = new Dictionary<int, string>();
        while (reader.PeekState() != System.Formats.Cbor.CborReaderState.EndMap)
        {
            int label = reader.ReadInt32();
            string value = reader.ReadTextString();
            claimsFound[label] = value;
        }
        reader.ReadEndMap();

        Assert.That(claimsFound.ContainsKey(CWTClaimsHeaderLabels.Audience), Is.True);
        Assert.That(claimsFound[CWTClaimsHeaderLabels.Audience], Is.EqualTo("test-audience"));

        // Cleanup
        DisposeCertificates(testChain);
    }

    [Test]
    public void ExtendProtectedHeaders_WithAdditionalCustomClaims_IncludesAllClaims()
    {
        // Arrange
        X509Certificate2Collection testChain = TestCertificateUtils.CreateTestChain();
        X509Certificate2 leafCert = testChain[^1];
        var signingKeyProvider = new X509Certificate2CoseSigningKeyProvider(null, leafCert, [.. testChain]);
        var customClaims = new CWTClaimsHeaderExtender();
        customClaims.SetIssuer("issuer");
        customClaims.SetSubject("subject");
        customClaims.SetAudience("audience");
        customClaims.SetExpirationTime(1234567890);
        var extender = new X509CertificateWithCWTClaimsHeaderExtender(signingKeyProvider, customClaims);
        var headers = new CoseHeaderMap();

        // Act
        extender.ExtendProtectedHeaders(headers);

        // Assert
        byte[] encodedClaims = headers[CWTClaimsHeaderLabels.CWTClaims].EncodedValue.ToArray();
        var reader = new System.Formats.Cbor.CborReader(encodedClaims);
        
        reader.ReadStartMap();
        var claimsFound = new HashSet<int>();
        while (reader.PeekState() != System.Formats.Cbor.CborReaderState.EndMap)
        {
            int label = reader.ReadInt32();
            claimsFound.Add(label);
            reader.SkipValue();
        }
        reader.ReadEndMap();

        Assert.That(claimsFound, Does.Contain(CWTClaimsHeaderLabels.Issuer));
        Assert.That(claimsFound, Does.Contain(CWTClaimsHeaderLabels.Subject));
        Assert.That(claimsFound, Does.Contain(CWTClaimsHeaderLabels.Audience));
        Assert.That(claimsFound, Does.Contain(CWTClaimsHeaderLabels.ExpirationTime));

        // Cleanup
        DisposeCertificates(testChain);
    }
}
