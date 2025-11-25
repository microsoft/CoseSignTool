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
        var stringClaims = new Dictionary<int, string>();
        var intClaims = new Dictionary<int, long>();
        while (reader.PeekState() != System.Formats.Cbor.CborReaderState.EndMap)
        {
            int label = reader.ReadInt32();
            // iat and nbf are auto-populated as int64
            if (label == CWTClaimsHeaderLabels.IssuedAt || label == CWTClaimsHeaderLabels.NotBefore)
            {
                intClaims[label] = reader.ReadInt64();
            }
            else
            {
                stringClaims[label] = reader.ReadTextString();
            }
        }
        reader.ReadEndMap();

        Assert.That(stringClaims[CWTClaimsHeaderLabels.Issuer], Is.EqualTo("custom-issuer"));
        Assert.That(stringClaims[CWTClaimsHeaderLabels.Subject], Is.EqualTo("custom-subject"));
        // Verify iat and nbf were auto-populated
        Assert.That(intClaims.ContainsKey(CWTClaimsHeaderLabels.IssuedAt), Is.True);
        Assert.That(intClaims.ContainsKey(CWTClaimsHeaderLabels.NotBefore), Is.True);

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
        var stringClaims = new Dictionary<int, string>();
        var intClaims = new Dictionary<int, long>();
        while (reader.PeekState() != System.Formats.Cbor.CborReaderState.EndMap)
        {
            int label = reader.ReadInt32();
            // iat and nbf are auto-populated as int64, but we only set audience (no auto-population without issuer/subject)
            if (label == CWTClaimsHeaderLabels.IssuedAt || label == CWTClaimsHeaderLabels.NotBefore)
            {
                intClaims[label] = reader.ReadInt64();
            }
            else
            {
                stringClaims[label] = reader.ReadTextString();
            }
        }
        reader.ReadEndMap();

        Assert.That(stringClaims.ContainsKey(CWTClaimsHeaderLabels.Audience), Is.True);
        Assert.That(stringClaims[CWTClaimsHeaderLabels.Audience], Is.EqualTo("test-audience"));
        // Verify iat and nbf WERE auto-populated (default extender has issuer and subject)
        Assert.That(intClaims.ContainsKey(CWTClaimsHeaderLabels.IssuedAt), Is.True);
        Assert.That(intClaims.ContainsKey(CWTClaimsHeaderLabels.NotBefore), Is.True);

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

    [Test]
    public void Constructor_WithoutCustomClaims_CreatesDefaultClaims()
    {
        // Arrange
        X509Certificate2Collection testChain = TestCertificateUtils.CreateTestChain();
        X509Certificate2 leafCert = testChain[^1];
        var signingKeyProvider = new X509Certificate2CoseSigningKeyProvider(null, leafCert, [.. testChain]);

        // Act
        var extender = new X509CertificateWithCWTClaimsHeaderExtender(signingKeyProvider);

        // Assert
        Assert.That(extender, Is.Not.Null);
        Assert.That(extender.ActiveCWTClaimsExtender, Is.Not.Null);

        // Cleanup
        DisposeCertificates(testChain);
    }

    [Test]
    public void Constructor_SingleParameterWithNullProvider_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            new X509CertificateWithCWTClaimsHeaderExtender(null!));
    }

    [Test]
    public void ExtendProtectedHeaders_WithNullProtectedHeaders_ThrowsArgumentNullException()
    {
        // Arrange
        X509Certificate2Collection testChain = TestCertificateUtils.CreateTestChain();
        X509Certificate2 leafCert = testChain[^1];
        var signingKeyProvider = new X509Certificate2CoseSigningKeyProvider(null, leafCert, [.. testChain]);
        var extender = new X509CertificateWithCWTClaimsHeaderExtender(signingKeyProvider);

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            extender.ExtendProtectedHeaders(null!));

        // Cleanup
        DisposeCertificates(testChain);
    }

    [Test]
    public void ExtendUnProtectedHeaders_WithNullUnProtectedHeaders_ReturnsNewMap()
    {
        // Arrange
        X509Certificate2Collection testChain = TestCertificateUtils.CreateTestChain();
        X509Certificate2 leafCert = testChain[^1];
        var signingKeyProvider = new X509Certificate2CoseSigningKeyProvider(null, leafCert, [.. testChain]);
        var extender = new X509CertificateWithCWTClaimsHeaderExtender(signingKeyProvider);

        // Act
        CoseHeaderMap result = extender.ExtendUnProtectedHeaders(null);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result, Is.InstanceOf<CoseHeaderMap>());

        // Cleanup
        DisposeCertificates(testChain);
    }

    [Test]
    public void Constructor_WithProviderHavingNullIssuer_ThrowsInvalidOperationException()
    {
        // Arrange
        using X509Certificate2 cert = TestCertificateUtils.CreateCertificate("TestCert");
        TestCertificateProviderWithNullIssuer provider = new(cert);

        // Act & Assert
        InvalidOperationException? exception = Assert.Throws<InvalidOperationException>(() =>
            new X509CertificateWithCWTClaimsHeaderExtender(provider));
        
        Assert.That(exception!.Message, Does.Contain("Failed to create default CWT claims"));
    }

    [Test]
    public void Constructor_WithProviderHavingEmptyIssuer_ThrowsInvalidOperationException()
    {
        // Arrange
        using X509Certificate2 cert = TestCertificateUtils.CreateCertificate("TestCert");
        TestCertificateProviderWithEmptyIssuer provider = new(cert);

        // Act & Assert
        InvalidOperationException? exception = Assert.Throws<InvalidOperationException>(() =>
            new X509CertificateWithCWTClaimsHeaderExtender(provider));
        
        Assert.That(exception!.Message, Does.Contain("Failed to create default CWT claims"));
    }

    [Test]
    public void DefaultSubject_IsUnknownIntent()
    {
        // Assert
        Assert.That(X509CertificateWithCWTClaimsHeaderExtender.DefaultSubject, Is.EqualTo("unknown.intent"));
    }

    [Test]
    public void ExtendProtectedHeaders_WithNonNullCertHeaders_AddsThem()
    {
        // Arrange
        X509Certificate2Collection testChain = TestCertificateUtils.CreateTestChain();
        X509Certificate2 leafCert = testChain[^1];
        var signingKeyProvider = new X509Certificate2CoseSigningKeyProvider(null, leafCert, [.. testChain]);
        var extender = new X509CertificateWithCWTClaimsHeaderExtender(signingKeyProvider);
        var headers = new CoseHeaderMap();

        // Act
        extender.ExtendProtectedHeaders(headers);

        // Assert - should have X5T and X5Chain from certificate provider
        Assert.That(headers.Count, Is.GreaterThan(1));

        // Cleanup
        DisposeCertificates(testChain);
    }

    [Test]
    public void ExtendUnProtectedHeaders_WithProviderReturningUnprotectedHeaders_AddsThem()
    {
        // Arrange
        using X509Certificate2 cert = TestCertificateUtils.CreateCertificate("TestCert");
        TestCertificateProviderWithUnprotectedHeaders provider = new(cert);
        var extender = new X509CertificateWithCWTClaimsHeaderExtender(provider);
        var headers = new CoseHeaderMap();

        // Act
        CoseHeaderMap result = extender.ExtendUnProtectedHeaders(headers);

        // Assert - should have the custom unprotected header
        Assert.That(result.ContainsKey(new CoseHeaderLabel(999)), Is.True);
    }

    /// <summary>
    /// Helper test provider that returns null for Issuer
    /// </summary>
    private class TestCertificateProviderWithNullIssuer : X509Certificate2CoseSigningKeyProvider
    {
        public TestCertificateProviderWithNullIssuer(X509Certificate2 signingCertificate)
            : base(signingCertificate)
        {
        }

        public override string? Issuer => null;
    }

    /// <summary>
    /// Helper test provider that returns empty string for Issuer
    /// </summary>
    private class TestCertificateProviderWithEmptyIssuer : X509Certificate2CoseSigningKeyProvider
    {
        public TestCertificateProviderWithEmptyIssuer(X509Certificate2 signingCertificate)
            : base(signingCertificate)
        {
        }

        public override string? Issuer => string.Empty;
    }

    /// <summary>
    /// Helper test provider that returns unprotected headers
    /// </summary>
    private class TestCertificateProviderWithUnprotectedHeaders : X509Certificate2CoseSigningKeyProvider
    {
        public TestCertificateProviderWithUnprotectedHeaders(X509Certificate2 signingCertificate)
            : base(signingCertificate)
        {
        }

        protected override CoseHeaderMap? GetUnProtectedHeadersImplementation()
        {
            CoseHeaderMap headers = new();
            headers.Add(new CoseHeaderLabel(999), CoseHeaderValue.FromString("test-value"));
            return headers;
        }
    }
}

