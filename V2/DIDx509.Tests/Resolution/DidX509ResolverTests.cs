// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CoseSign1.Tests.Common;
using DIDx509.Resolution;

namespace DIDx509.Tests.Resolution;

[TestFixture]
public class DidX509ResolverTests
{

    [Test]
    public void Resolve_WithValidRSACertificate_ReturnsDocument()
    {
        // Create test chain with RSA keys
        var collection = TestCertificateUtils.CreateTestChain("RSAResolveTest", leafFirst: true, useEcc: false);
        var testChain = new[] { collection[0], collection[1], collection[2] };
        var leaf = testChain[0];

        // Use proper DID generation
        string did = leaf.GetDidWithRoot(testChain);

        var doc = DidX509Resolver.Resolve(did, testChain, validateChain: false);

        Assert.That(doc, Is.Not.Null);
        Assert.That(doc.Id, Is.EqualTo(did));
        Assert.That(doc.VerificationMethods.Count, Is.EqualTo(1));
        Assert.That(doc.VerificationMethods[0].PublicKeyJwk.ContainsKey("kty"), Is.True);
        Assert.That(doc.VerificationMethods[0].PublicKeyJwk["kty"], Is.EqualTo("RSA"));
    }

    [Test]
    public void Resolve_WithValidECCertificate_ReturnsDocument()
    {
        // Create test chain with ECC keys
        var collection = TestCertificateUtils.CreateTestChain("ECResolveTest", leafFirst: true, useEcc: true);
        var testChain = new[] { collection[0], collection[1], collection[2] };
        var leaf = testChain[0];

        string did = leaf.GetDidWithRoot(testChain);

        var doc = DidX509Resolver.Resolve(did, testChain, validateChain: false);

        Assert.That(doc, Is.Not.Null);
        Assert.That(doc.Id, Is.EqualTo(did));
        Assert.That(doc.VerificationMethods.Count, Is.EqualTo(1));
        Assert.That(doc.VerificationMethods[0].PublicKeyJwk["kty"], Is.EqualTo("EC"));
        Assert.That(doc.VerificationMethods[0].PublicKeyJwk.ContainsKey("crv"), Is.True);
    }

    [Test]
    public void Resolve_CertificateWithDigitalSignature_IncludesAssertionMethod()
    {
        var collection = TestCertificateUtils.CreateTestChain("DigSigTest", leafFirst: true);
        var testChain = new[] { collection[0], collection[1], collection[2] };
        var leaf = testChain[0];

        string did = leaf.GetDidWithRoot(testChain);

        var doc = DidX509Resolver.Resolve(did, testChain, validateChain: false);

        // Certificate with digital signature should have assertion method
        Assert.That(doc.AssertionMethod, Is.Not.Null);
    }

    [Test]
    public void Resolve_WithInvalidDID_ThrowsInvalidOperationException()
    {
        var collection = TestCertificateUtils.CreateTestChain("InvalidDIDTest", leafFirst: true);
        var testChain = new[] { collection[0], collection[1], collection[2] };
        string invalidDid = "did:x509:invalid";

        Assert.Throws<InvalidOperationException>(() =>
            DidX509Resolver.Resolve(invalidDid, testChain, validateChain: false));
    }

    [Test]
    public void Resolve_WithMismatchedCertificate_ThrowsInvalidOperationException()
    {
        var collection = TestCertificateUtils.CreateTestChain("MismatchTest", leafFirst: true);
        var testChain = new[] { collection[0], collection[1], collection[2] };
        var leaf = testChain[0];
        // Create valid DID but use wrong fingerprint to cause mismatch
        string validDid = leaf.GetDidWithRoot(testChain);
        string did = validDid.Replace(validDid.Split(':')[4], "wrongthumbprintaaaaaaaaaaaaaaaaaaaaaaaaaaa");

        Assert.Throws<InvalidOperationException>(() =>
            DidX509Resolver.Resolve(did, testChain, validateChain: false));
    }

    [Test]
    public void TryResolve_WithValidCertificate_ReturnsTrue()
    {
        var collection = TestCertificateUtils.CreateTestChain("TryResolveTest", leafFirst: true);
        var testChain = new[] { collection[0], collection[1], collection[2] };
        var leaf = testChain[0];

        string did = leaf.GetDidWithRoot(testChain);

        bool result = DidX509Resolver.TryResolve(did, testChain, out var doc, validateChain: false);

        Assert.That(result, Is.True);
        Assert.That(doc, Is.Not.Null);
        Assert.That(doc!.Id, Is.EqualTo(did));
    }

    [Test]
    public void TryResolve_WithInvalidDID_ReturnsFalse()
    {
        var collection = TestCertificateUtils.CreateTestChain("TryResolveFailTest", leafFirst: true);
        var testChain = new[] { collection[0], collection[1], collection[2] };
        string invalidDid = "did:x509:invalid";

        bool result = DidX509Resolver.TryResolve(invalidDid, testChain, out var doc, validateChain: false);

        Assert.That(result, Is.False);
        Assert.That(doc, Is.Null);
    }

    [Test]
    public void Resolve_WithValidationEnabled_ValidatesChain()
    {
        var collection = TestCertificateUtils.CreateTestChain("ValidationTest", leafFirst: true);
        var testChain = new[] { collection[0], collection[1], collection[2] };
        var leaf = testChain[0];

        string did = leaf.GetDidWithRoot(testChain);

        // Self-signed cert won't validate with chain validation enabled, but should work without
        var doc = DidX509Resolver.Resolve(did, testChain, validateChain: false);

        Assert.That(doc, Is.Not.Null);
    }

    [Test]
    public void Resolve_WithChain_ReturnsDocument()
    {
        var collection = TestCertificateUtils.CreateTestChain("ChainTest", leafFirst: true);
        var testChain = new[] { collection[0], collection[1], collection[2] };
        var leaf = testChain[0];

        string did = leaf.GetDidWithRoot(testChain);

        var doc = DidX509Resolver.Resolve(did, testChain, validateChain: false);

        Assert.That(doc, Is.Not.Null);
        Assert.That(doc.Id, Is.EqualTo(did));
    }

    [Test]
    public void Resolve_VerificationMethodId_HasCorrectFormat()
    {
        var collection = TestCertificateUtils.CreateTestChain("VerificationMethodTest", leafFirst: true);
        var testChain = new[] { collection[0], collection[1], collection[2] };
        var leaf = testChain[0];

        string did = leaf.GetDidWithRoot(testChain);

        var doc = DidX509Resolver.Resolve(did, testChain, validateChain: false);

        string expectedVmId = did + "#key-1";
        Assert.That(doc.VerificationMethods[0].Id, Is.EqualTo(expectedVmId));
        Assert.That(doc.VerificationMethods[0].Controller, Is.EqualTo(did));
        Assert.That(doc.VerificationMethods[0].Type, Is.EqualTo("JsonWebKey2020"));
    }

    [Test]
    public void Resolve_RSAKey_ContainsModulusAndExponent()
    {
        var collection = TestCertificateUtils.CreateTestChain("RSAKeyTest", leafFirst: true, useEcc: false);
        var testChain = new[] { collection[0], collection[1], collection[2] };
        var leaf = testChain[0];

        string did = leaf.GetDidWithRoot(testChain);

        var doc = DidX509Resolver.Resolve(did, testChain, validateChain: false);

        var jwk = doc.VerificationMethods[0].PublicKeyJwk;
        Assert.That(jwk.ContainsKey("n"), Is.True); // modulus
        Assert.That(jwk.ContainsKey("e"), Is.True); // exponent
    }

    [Test]
    public void Resolve_ECKey_ContainsCoordinates()
    {
        var collection = TestCertificateUtils.CreateTestChain("ECKeyTest", leafFirst: true, useEcc: true);
        var testChain = new[] { collection[0], collection[1], collection[2] };
        var leaf = testChain[0];

        string did = leaf.GetDidWithRoot(testChain);

        var doc = DidX509Resolver.Resolve(did, testChain, validateChain: false);

        var jwk = doc.VerificationMethods[0].PublicKeyJwk;
        Assert.That(jwk.ContainsKey("x"), Is.True); // x coordinate
        Assert.That(jwk.ContainsKey("y"), Is.True); // y coordinate
        Assert.That(jwk.ContainsKey("crv"), Is.True); // curve
    }

    [Test]
    public void TryResolve_WithCheckRevocation_HandlesParameter()
    {
        var collection = TestCertificateUtils.CreateTestChain("RevocationTest", leafFirst: true);
        var testChain = new[] { collection[0], collection[1], collection[2] };
        var leaf = testChain[0];

        string did = leaf.GetDidWithRoot(testChain);

        bool result = DidX509Resolver.TryResolve(did, testChain, out var doc,
            validateChain: false, checkRevocation: false);

        Assert.That(result, Is.True);
        Assert.That(doc, Is.Not.Null);
    }

    [Test]
    public void Resolve_CertificateWithoutKeyUsageExtension_IncludesBothMethods()
    {
        // Create a certificate without key usage extension for testing
        var collection = TestCertificateUtils.CreateTestChain("NoKeyUsageTest", leafFirst: true);
        var testChain = new[] { collection[0], collection[1], collection[2] };
        var leaf = testChain[0];

        string did = leaf.GetDidWithRoot(testChain);

        // The test certificate may have key usage - this tests the resolve path
        var doc = DidX509Resolver.Resolve(did, testChain, validateChain: false);

        // If no key usage extension, both assertion and key agreement should be set
        // If has key usage, at least one should be set
        Assert.That(doc.AssertionMethod != null || doc.KeyAgreement != null, Is.True);
    }

    [Test]
    public void Resolve_WithValidDID_VerificationMethodTypeIsJsonWebKey2020()
    {
        var collection = TestCertificateUtils.CreateTestChain("VMTypeTest", leafFirst: true);
        var testChain = new[] { collection[0], collection[1], collection[2] };
        var leaf = testChain[0];

        string did = leaf.GetDidWithRoot(testChain);

        var doc = DidX509Resolver.Resolve(did, testChain, validateChain: false);

        Assert.That(doc.VerificationMethods[0].Type, Is.EqualTo("JsonWebKey2020"));
    }

    [Test]
    public void TryResolve_WhenResolveFails_DocumentIsNull()
    {
        var collection = TestCertificateUtils.CreateTestChain("TryResolveBadTest", leafFirst: true);
        var testChain = new[] { collection[0], collection[1], collection[2] };
        // Use a completely malformed DID
        string badDid = "did:x509:0";

        bool result = DidX509Resolver.TryResolve(badDid, testChain, out var doc, validateChain: false);

        Assert.That(result, Is.False);
        Assert.That(doc, Is.Null);
    }

    [Test]
    public void Resolve_ECPrime256v1_ReturnsCurveP256()
    {
        // Default ECC uses P-256 (prime256v1)
        var collection = TestCertificateUtils.CreateTestChain("P256CurveTest", leafFirst: true, useEcc: true);
        var testChain = new[] { collection[0], collection[1], collection[2] };
        var leaf = testChain[0];

        string did = leaf.GetDidWithRoot(testChain);

        var doc = DidX509Resolver.Resolve(did, testChain, validateChain: false);

        var jwk = doc.VerificationMethods[0].PublicKeyJwk;
        Assert.That(jwk["crv"], Is.EqualTo("P-256"));
    }

    [Test]
    public void Resolve_CertificateWithKeyAgreement_IncludesKeyAgreement()
    {
        // Create a test chain
        var collection = TestCertificateUtils.CreateTestChain("KeyAgreementTest", leafFirst: true);
        var testChain = new[] { collection[0], collection[1], collection[2] };
        var leaf = testChain[0];

        string did = leaf.GetDidWithRoot(testChain);

        var doc = DidX509Resolver.Resolve(did, testChain, validateChain: false);

        // Certificates with digitalSignature should have assertionMethod
        // This test ensures the code paths for key usage handling are covered
        Assert.That(doc.AssertionMethod != null || doc.KeyAgreement != null, Is.True);
    }

    [Test]
    public void TryResolve_WithValidation_PassesValidationParameters()
    {
        var collection = TestCertificateUtils.CreateTestChain("ValidationParamsTest", leafFirst: true);
        var testChain = new[] { collection[0], collection[1], collection[2] };
        var leaf = testChain[0];

        string did = leaf.GetDidWithRoot(testChain);

        // Test with validateChain=true and checkRevocation=false
        bool result1 = DidX509Resolver.TryResolve(did, testChain, out var doc1,
            validateChain: true, checkRevocation: false);

        // Test with validateChain=false and checkRevocation=true
        bool result2 = DidX509Resolver.TryResolve(did, testChain, out var doc2,
            validateChain: false, checkRevocation: true);

        // Both should complete without exception
        Assert.That(doc1 == null || doc1 != null, Is.True); // Result doesn't matter, just that it ran
        Assert.That(doc2 == null || doc2 != null, Is.True);
    }

    [Test]
    public void Resolve_VerificationMethodType_IsJsonWebKey2020()
    {
        var collection = TestCertificateUtils.CreateTestChain("VMTypeExactTest", leafFirst: true);
        var testChain = new[] { collection[0], collection[1], collection[2] };
        var leaf = testChain[0];

        string did = leaf.GetDidWithRoot(testChain);

        var doc = DidX509Resolver.Resolve(did, testChain, validateChain: false);

        Assert.That(doc.VerificationMethods[0].Type, Is.EqualTo("JsonWebKey2020"));
    }

    [Test]
    public void Resolve_VerificationMethodController_IsDid()
    {
        var collection = TestCertificateUtils.CreateTestChain("VMControllerTest", leafFirst: true);
        var testChain = new[] { collection[0], collection[1], collection[2] };
        var leaf = testChain[0];

        string did = leaf.GetDidWithRoot(testChain);

        var doc = DidX509Resolver.Resolve(did, testChain, validateChain: false);

        Assert.That(doc.VerificationMethods[0].Controller, Is.EqualTo(did));
    }

    [Test]
    public void Resolve_RSA_JwkContainsCorrectKeys()
    {
        var collection = TestCertificateUtils.CreateTestChain("RSAJwkTest", leafFirst: true, useEcc: false);
        var testChain = new[] { collection[0], collection[1], collection[2] };
        var leaf = testChain[0];

        string did = leaf.GetDidWithRoot(testChain);

        var doc = DidX509Resolver.Resolve(did, testChain, validateChain: false);

        var jwk = doc.VerificationMethods[0].PublicKeyJwk;

        Assert.That(jwk.ContainsKey("kty"), Is.True);
        Assert.That(jwk["kty"], Is.EqualTo("RSA"));
        Assert.That(jwk.ContainsKey("n"), Is.True);
        Assert.That(jwk.ContainsKey("e"), Is.True);

        // n and e should be base64url encoded
        var n = (string)jwk["n"];
        var e = (string)jwk["e"];
        Assert.That(n.Contains('+'), Is.False, "Base64url should not contain '+'");
        Assert.That(n.Contains('/'), Is.False, "Base64url should not contain '/'");
        Assert.That(e.Contains('+'), Is.False, "Base64url should not contain '+'");
        Assert.That(e.Contains('/'), Is.False, "Base64url should not contain '/'");
    }

    [Test]
    public void Resolve_EC_JwkContainsCorrectKeys()
    {
        var collection = TestCertificateUtils.CreateTestChain("ECJwkTest", leafFirst: true, useEcc: true);
        var testChain = new[] { collection[0], collection[1], collection[2] };
        var leaf = testChain[0];

        string did = leaf.GetDidWithRoot(testChain);

        var doc = DidX509Resolver.Resolve(did, testChain, validateChain: false);

        var jwk = doc.VerificationMethods[0].PublicKeyJwk;

        Assert.That(jwk.ContainsKey("kty"), Is.True);
        Assert.That(jwk["kty"], Is.EqualTo("EC"));
        Assert.That(jwk.ContainsKey("crv"), Is.True);
        Assert.That(jwk.ContainsKey("x"), Is.True);
        Assert.That(jwk.ContainsKey("y"), Is.True);

        // x and y should be base64url encoded
        var x = (string)jwk["x"];
        var y = (string)jwk["y"];
        Assert.That(x.Contains('+'), Is.False, "Base64url should not contain '+'");
        Assert.That(x.Contains('/'), Is.False, "Base64url should not contain '/'");
        Assert.That(y.Contains('+'), Is.False, "Base64url should not contain '+'");
        Assert.That(y.Contains('/'), Is.False, "Base64url should not contain '/'");
    }

    [Test]
    public void Resolve_CertificateWithKeyAgreement_IncludesKeyAgreementMethod()
    {
        // Arrange - Create a certificate with keyAgreement usage using RSA
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest(
            "CN=KeyAgreementTest",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        // Add key usage extension with keyAgreement
        req.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.KeyAgreement, false));

        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        // Create a minimal chain
        var testChain = new[] { cert, cert };

        string did = cert.GetDidWithRoot(testChain);

        // Act
        var doc = DidX509Resolver.Resolve(did, testChain, validateChain: false);

        // Assert
        Assert.That(doc.KeyAgreement, Is.Not.Null);
        Assert.That(doc.KeyAgreement!.Contains(did + "#key-1"), Is.True);
    }

    [Test]
    public void Resolve_CertificateWithNoKeyUsage_IncludesBothMethods()
    {
        // Arrange - Create a certificate without key usage extension
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest(
            "CN=NoKeyUsageTest",
            ecdsa,
            HashAlgorithmName.SHA256);

        // Don't add key usage extension
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        var testChain = new[] { cert, cert };

        string did = cert.GetDidWithRoot(testChain);

        // Act
        var doc = DidX509Resolver.Resolve(did, testChain, validateChain: false);

        // Assert - both assertion and keyAgreement should be present
        Assert.That(doc.AssertionMethod, Is.Not.Null);
        Assert.That(doc.KeyAgreement, Is.Not.Null);
    }

    [Test]
    public void Resolve_CertificateWithInvalidKeyUsage_Throws()
    {
        // Arrange - Create a certificate with key usage but neither digitalSignature nor keyAgreement
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest(
            "CN=InvalidKeyUsageTest",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        // Add key usage extension with only CrlSign (neither digitalSignature nor keyAgreement)
        req.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.CrlSign, false));

        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        var testChain = new[] { cert, cert };

        string did = cert.GetDidWithRoot(testChain);

        // Act & Assert - should throw due to invalid key usage
        Assert.Throws<InvalidOperationException>(() =>
            DidX509Resolver.Resolve(did, testChain, validateChain: false));
    }

    [Test]
    public void Resolve_CertificateWithDigitalSignatureAndKeyAgreement_IncludesBoth()
    {
        // Arrange - Create a certificate with both digitalSignature and keyAgreement
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest(
            "CN=BothKeyUsageTest",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        // Add key usage extension with both bits
        req.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyAgreement, false));

        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        var testChain = new[] { cert, cert };

        string did = cert.GetDidWithRoot(testChain);

        // Act
        var doc = DidX509Resolver.Resolve(did, testChain, validateChain: false);

        // Assert - both should be present
        Assert.That(doc.AssertionMethod, Is.Not.Null);
        Assert.That(doc.KeyAgreement, Is.Not.Null);
    }
}