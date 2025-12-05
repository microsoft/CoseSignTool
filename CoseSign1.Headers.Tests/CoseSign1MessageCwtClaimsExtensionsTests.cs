// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Security.Cryptography.Cose;
using System.Security.Cryptography.X509Certificates;
using CoseSign1.Abstractions.Interfaces;
using CoseSign1.Certificates.Local;
using CoseSign1.Headers;
using CoseSign1.Headers.Extensions;
using CoseSign1.Tests.Common;
using CoseX509;
using NUnit.Framework;

namespace CoseSign1.Headers.Tests;

[TestFixture]
[Parallelizable(ParallelScope.All)]
public class CoseSign1MessageCwtClaimsExtensionsTests
{
    [Test]
    public void TryGetCwtClaims_WithValidClaims_ReturnsTrue()
    {
        // Arrange
        var (message, certs) = CreateMessageWithCwtClaims();

        // Act
        bool result = message.TryGetCwtClaims(out CwtClaims? claims);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(claims, Is.Not.Null);
        Assert.That(claims!.Issuer, Is.EqualTo("did:example:issuer"));
        Assert.That(claims.Subject, Is.EqualTo("test.subject"));

        // Cleanup
        DisposeCertificates(certs);
    }

    [Test]
    public void TryGetCwtClaims_WithNoClaims_ReturnsFalse()
    {
        // NOTE: This test has been updated to reflect that CertificateCoseSigningKeyProvider
        // now automatically adds default CWT claims (issuer and subject) for SCITT compliance.
        // Therefore, certificate-based signatures will always have CWT claims present.
        
        // Arrange
        var (message, certs) = CreateMessageWithoutCwtClaims();

        // Act
        bool result = message.TryGetCwtClaims(out CwtClaims? claims);

        // Assert
        // CWT claims are now automatically added for certificate-based signing
        Assert.That(result, Is.True);
        Assert.That(claims, Is.Not.Null);
        // Default claims should include issuer (DID:x509) and subject (unknown.intent)
        Assert.That(claims!.Issuer, Is.Not.Null.And.Not.Empty);
        Assert.That(claims.Subject, Is.EqualTo(CwtClaims.DefaultSubject));

        // Cleanup
        DisposeCertificates(certs);
    }

    [Test]
    public void TryGetCwtClaims_WithNullMessage_ReturnsFalse()
    {
        // Act
        bool result = ((CoseSign1Message?)null).TryGetCwtClaims(out CwtClaims? claims);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(claims, Is.Null);
    }

    [Test]
    public void TryGetCwtClaims_WithAllStandardClaims_ExtractsCorrectly()
    {
        // Arrange
        var expectedExpiration = DateTimeOffset.UtcNow.AddMonths(6);
        var expectedNotBefore = DateTimeOffset.UtcNow.AddDays(-1);
        var expectedIssuedAt = DateTimeOffset.UtcNow;

        var (message, certs) = CreateMessageWithAllClaims(expectedExpiration, expectedNotBefore, expectedIssuedAt);

        // Act
        bool result = message.TryGetCwtClaims(out CwtClaims? claims);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(claims, Is.Not.Null);
        Assert.That(claims!.Issuer, Is.EqualTo("did:example:full-issuer"));
        Assert.That(claims.Subject, Is.EqualTo("full.test.subject"));
        Assert.That(claims.Audience, Is.EqualTo("test-audience"));
        
        // Compare Unix timestamps (within 1 second tolerance due to rounding)
        Assert.That(claims.ExpirationTime!.Value.ToUnixTimeSeconds(), 
            Is.EqualTo(expectedExpiration.ToUnixTimeSeconds()));
        Assert.That(claims.NotBefore!.Value.ToUnixTimeSeconds(), 
            Is.EqualTo(expectedNotBefore.ToUnixTimeSeconds()));
        Assert.That(claims.IssuedAt!.Value.ToUnixTimeSeconds(), 
            Is.EqualTo(expectedIssuedAt.ToUnixTimeSeconds()));

        // Cleanup
        DisposeCertificates(certs);
    }

    [Test]
    public void TryGetCwtClaims_WithCwtId_ExtractsCorrectly()
    {
        // Arrange
        byte[] expectedCwtId = new byte[] { 0x01, 0x02, 0x03, 0x04 };
        var (message, certs) = CreateMessageWithCwtId(expectedCwtId);

        // Act
        bool result = message.TryGetCwtClaims(out CwtClaims? claims);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(claims, Is.Not.Null);
        Assert.That(claims!.CwtId, Is.EqualTo(expectedCwtId));

        // Cleanup
        DisposeCertificates(certs);
    }

    [Test]
    public void TryGetCwtClaims_WithCustomClaims_ExtractsCorrectly()
    {
        // Arrange
        var (message, certs) = CreateMessageWithMultipleCustomClaims();

        // Act
        bool result = message.TryGetCwtClaims(out CwtClaims? claims);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(claims, Is.Not.Null);
        Assert.That(claims!.CustomClaims.Count, Is.EqualTo(3));
        Assert.That(claims.CustomClaims[100], Is.EqualTo("string-value"));
        Assert.That(claims.CustomClaims[101], Is.EqualTo(123L));
        Assert.That(claims.CustomClaims[102], Is.EqualTo(new byte[] { 0x01, 0x02 }));

        // Cleanup
        DisposeCertificates(certs);
    }

    [Test]
    public void TryGetCwtClaims_WithMalformedCborData_ReturnsFalse()
    {
        // Arrange - Create a message with invalid CBOR data in the CWT Claims header
        var (message, certs) = CreateMessageWithMalformedCwtClaims();

        // Act
        bool result = message.TryGetCwtClaims(out CwtClaims? claims);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(claims, Is.Null);

        // Cleanup
        DisposeCertificates(certs);
    }

    // Helper methods
    private (CoseSign1Message message, X509Certificate2Collection certs) CreateMessageWithCwtClaims()
    {
        var certs = TestCertificateUtils.CreateTestChain();
        var provider = new X509Certificate2CoseSigningKeyProvider(certs[^1]);

        var extender = new CWTClaimsHeaderExtender()
            .SetIssuer("did:example:issuer")
            .SetSubject("test.subject");

        byte[] payload = new byte[] { 1, 2, 3 };
        byte[] signature = CoseHandler.Sign(payload, provider, embedSign: false, headerExtender: extender).ToArray();
        return (CoseSign1Message.DecodeSign1(signature), certs);
    }

    private (CoseSign1Message message, X509Certificate2Collection certs) CreateMessageWithoutCwtClaims()
    {
        var certs = TestCertificateUtils.CreateTestChain();
        var provider = new X509Certificate2CoseSigningKeyProvider(certs[^1]);

        byte[] payload = new byte[] { 1, 2, 3 };
        byte[] signature = CoseHandler.Sign(payload, provider, embedSign: false).ToArray();
        return (CoseSign1Message.DecodeSign1(signature), certs);
    }

    private (CoseSign1Message message, X509Certificate2Collection certs) CreateMessageWithAllClaims(
        DateTimeOffset expiration,
        DateTimeOffset notBefore,
        DateTimeOffset issuedAt)
    {
        var certs = TestCertificateUtils.CreateTestChain();
        var provider = new X509Certificate2CoseSigningKeyProvider(certs[^1]);

        var extender = new CWTClaimsHeaderExtender()
            .SetIssuer("did:example:full-issuer")
            .SetSubject("full.test.subject")
            .SetAudience("test-audience")
            .SetExpirationTime(expiration)
            .SetNotBefore(notBefore)
            .SetIssuedAt(issuedAt);

        byte[] payload = new byte[] { 1, 2, 3 };
        byte[] signature = CoseHandler.Sign(payload, provider, embedSign: false, headerExtender: extender).ToArray();
        return (CoseSign1Message.DecodeSign1(signature), certs);
    }

    private (CoseSign1Message message, X509Certificate2Collection certs) CreateMessageWithCwtId(byte[] cwtId)
    {
        var certs = TestCertificateUtils.CreateTestChain();
        var provider = new X509Certificate2CoseSigningKeyProvider(certs[^1]);

        var extender = new CWTClaimsHeaderExtender()
            .SetIssuer("did:example:issuer")
            .SetCWTID(cwtId);

        byte[] payload = new byte[] { 1, 2, 3 };
        byte[] signature = CoseHandler.Sign(payload, provider, embedSign: false, headerExtender: extender).ToArray();
        return (CoseSign1Message.DecodeSign1(signature), certs);
    }

    private (CoseSign1Message message, X509Certificate2Collection certs) CreateMessageWithMultipleCustomClaims()
    {
        var certs = TestCertificateUtils.CreateTestChain();
        var provider = new X509Certificate2CoseSigningKeyProvider(certs[^1]);

        var extender = new CWTClaimsHeaderExtender()
            .SetIssuer("did:example:issuer")
            .SetCustomClaim(100, "string-value")
            .SetCustomClaim(101, 123L)
            .SetCustomClaim(102, new byte[] { 0x01, 0x02 });

        byte[] payload = new byte[] { 1, 2, 3 };
        byte[] signature = CoseHandler.Sign(payload, provider, embedSign: false, headerExtender: extender).ToArray();
        return (CoseSign1Message.DecodeSign1(signature), certs);
    }

    private (CoseSign1Message message, X509Certificate2Collection certs) CreateMessageWithMalformedCwtClaims()
    {
        var certs = TestCertificateUtils.CreateTestChain();
        var provider = new X509Certificate2CoseSigningKeyProvider(certs[^1]);

        // Create a custom header extender that adds malformed CBOR data
        var malformedExtender = new MalformedCwtClaimsExtender();

        byte[] payload = new byte[] { 1, 2, 3 };
        byte[] signature = CoseHandler.Sign(payload, provider, embedSign: false, headerExtender: malformedExtender).ToArray();
        return (CoseSign1Message.DecodeSign1(signature), certs);
    }

    // Helper class to inject malformed CBOR data
    private class MalformedCwtClaimsExtender : ICoseHeaderExtender
    {
        public CoseHeaderMap ExtendProtectedHeaders(CoseHeaderMap protectedHeaders)
        {
            // Add valid CBOR that will fail CwtClaims parsing
            // Create a CBOR map with an unexpected structure (array instead of map for a claim value)
            var writer = new System.Formats.Cbor.CborWriter();
            writer.WriteStartMap(1);
            writer.WriteInt32(CWTClaimsHeaderLabels.Issuer);
            // Write an array instead of a string, which will cause parsing to fail
            writer.WriteStartArray(2);
            writer.WriteInt32(123);
            writer.WriteInt32(456);
            writer.WriteEndArray();
            writer.WriteEndMap();
            
            var malformedValue = CoseHeaderValue.FromEncodedValue(writer.Encode());
            protectedHeaders[CWTClaimsHeaderLabels.CWTClaims] = malformedValue;
            return protectedHeaders;
        }

        public CoseHeaderMap ExtendUnProtectedHeaders(CoseHeaderMap? unProtectedHeaders)
        {
            return unProtectedHeaders ?? new CoseHeaderMap();
        }
    }

    private void DisposeCertificates(X509Certificate2Collection certs)
    {
        foreach (var cert in certs)
        {
            cert.Dispose();
        }
    }

    #region Custom Header Label Tests

    [Test]
    public void TryGetCwtClaims_WithCustomLabel_RetrievesFromProtectedHeaders()
    {
        // Arrange
        var customLabel = new CoseHeaderLabel(999);
        var extender = new CustomLabelCwtClaimsExtender(customLabel, "custom-issuer", "custom-subject");
        var (message, certs) = CreateMessageWithCustomLabelClaims(extender);

        // Act
        bool result = message.TryGetCwtClaims(out CwtClaims? claims, useUnprotectedHeaders: false, headerLabel: customLabel);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(claims, Is.Not.Null);
        Assert.That(claims!.Issuer, Is.EqualTo("custom-issuer"));
        Assert.That(claims.Subject, Is.EqualTo("custom-subject"));

        // Cleanup
        DisposeCertificates(certs);
    }

    [Test]
    public void TryGetCwtClaims_WithCustomLabel_BothLabelsCanCoexist()
    {
        // Arrange
        var customLabel = new CoseHeaderLabel(888);
        var extender = new CustomLabelCwtClaimsExtender(customLabel, "custom-issuer", "custom-subject");
        var (message, certs) = CreateMessageWithCustomLabelClaims(extender);

        // Act - Get claims from both labels
        bool defaultResult = message.TryGetCwtClaims(out CwtClaims? defaultClaims);
        bool customResult = message.TryGetCwtClaims(out CwtClaims? customClaims, headerLabel: customLabel);

        // Assert - Both should exist but have different values
        Assert.That(defaultResult, Is.True, "Default label claims should exist (added by certificate provider)");
        Assert.That(defaultClaims, Is.Not.Null);
        Assert.That(customResult, Is.True, "Custom label claims should exist");
        Assert.That(customClaims, Is.Not.Null);
        
        // Custom claims should have the values we set
        Assert.That(customClaims!.Issuer, Is.EqualTo("custom-issuer"));
        Assert.That(customClaims!.Subject, Is.EqualTo("custom-subject"));
        
        // Default claims should have different values (from certificate provider)
        Assert.That(defaultClaims!.Issuer, Is.Not.EqualTo("custom-issuer"), "Default and custom labels have independent values");

        // Cleanup
        DisposeCertificates(certs);
    }

    [Test]
    public void TryGetCwtClaims_WithWrongCustomLabel_ReturnsFalse()
    {
        // Arrange
        var customLabel = new CoseHeaderLabel(777);
        var wrongLabel = new CoseHeaderLabel(666);
        var extender = new CustomLabelCwtClaimsExtender(customLabel, "test-issuer", "test-subject");
        var (message, certs) = CreateMessageWithCustomLabelClaims(extender);

        // Act
        bool result = message.TryGetCwtClaims(out CwtClaims? claims, useUnprotectedHeaders: false, headerLabel: wrongLabel);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(claims, Is.Null);

        // Cleanup
        DisposeCertificates(certs);
    }

    [Test]
    public void TryGetCwtClaims_WithNullCustomLabel_UsesDefaultLabel()
    {
        // Arrange
        var (message, certs) = CreateMessageWithCwtClaims();

        // Act
        bool result = message.TryGetCwtClaims(out CwtClaims? claims, useUnprotectedHeaders: false, headerLabel: null);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(claims, Is.Not.Null);

        // Cleanup
        DisposeCertificates(certs);
    }

    // Helper class for custom label testing
    private class CustomLabelCwtClaimsExtender : ICoseHeaderExtender
    {
        private readonly CoseHeaderLabel CustomLabel;
        private readonly string Issuer;
        private readonly string Subject;

        public CustomLabelCwtClaimsExtender(CoseHeaderLabel customLabel, string issuer, string subject)
        {
            CustomLabel = customLabel;
            Issuer = issuer;
            Subject = subject;
        }

        public CoseHeaderMap ExtendProtectedHeaders(CoseHeaderMap protectedHeaders)
        {
            var extender = new CWTClaimsHeaderExtender(customHeaderLabel: CustomLabel)
                .SetIssuer(Issuer)
                .SetSubject(Subject);
            return extender.ExtendProtectedHeaders(protectedHeaders);
        }

        public CoseHeaderMap ExtendUnProtectedHeaders(CoseHeaderMap? unProtectedHeaders)
        {
            return unProtectedHeaders ?? new CoseHeaderMap();
        }
    }

    private (CoseSign1Message Message, X509Certificate2Collection Certs) CreateMessageWithCustomLabelClaims(ICoseHeaderExtender extender)
    {
        var certs = TestCertificateUtils.CreateTestChain();
        var provider = new X509Certificate2CoseSigningKeyProvider(certs[^1]);

        byte[] payload = new byte[] { 1, 2, 3 };
        byte[] signature = CoseHandler.Sign(payload, provider, embedSign: false, headerExtender: extender).ToArray();
        return (CoseSign1Message.DecodeSign1(signature), certs);
    }

    #endregion
}

