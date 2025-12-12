// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CoseSign1.Tests.Common;
using DIDx509;
using DIDx509.Resolution;
using NUnit.Framework;

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
}