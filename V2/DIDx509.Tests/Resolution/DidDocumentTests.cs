// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using DIDx509.Resolution;
using NUnit.Framework;
using System;
using System.Collections.Generic;

namespace DIDx509.Tests.Resolution;

[TestFixture]
public class DidDocumentTests
{
    [Test]
    public void Constructor_WithValidParameters_CreatesDocument()
    {
        var verificationMethods = new List<VerificationMethod>
        {
            new VerificationMethod("did:x509:0:test#key-1", "JsonWebKey2020", "did:x509:0:test", new Dictionary<string, object>())
        };

        var doc = new DidDocument("did:x509:0:test", verificationMethods);

        Assert.That(doc.Id, Is.EqualTo("did:x509:0:test"));
        Assert.That(doc.Context, Is.EqualTo("https://www.w3.org/ns/did/v1"));
        Assert.That(doc.VerificationMethods, Is.Not.Null);
        Assert.That(doc.VerificationMethods.Count, Is.EqualTo(1));
        Assert.That(doc.AssertionMethod, Is.Null);
        Assert.That(doc.KeyAgreement, Is.Null);
    }

    [Test]
    public void Constructor_WithNullId_ThrowsArgumentNullException()
    {
        var verificationMethods = new List<VerificationMethod>
        {
            new VerificationMethod("did:x509:0:test#key-1", "JsonWebKey2020", "did:x509:0:test", new Dictionary<string, object>())
        };

        Assert.Throws<ArgumentNullException>(() => new DidDocument(null!, verificationMethods));
    }

    [Test]
    public void Constructor_WithNullVerificationMethods_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => new DidDocument("did:x509:0:test", null!));
    }

    [Test]
    public void Constructor_WithAssertionMethod_StoresValue()
    {
        var verificationMethods = new List<VerificationMethod>
        {
            new VerificationMethod("did:x509:0:test#key-1", "JsonWebKey2020", "did:x509:0:test", new Dictionary<string, object>())
        };
        var assertionMethod = new List<string> { "did:x509:0:test#key-1" };

        var doc = new DidDocument("did:x509:0:test", verificationMethods, assertionMethod);

        Assert.That(doc.AssertionMethod, Is.Not.Null);
        Assert.That(doc.AssertionMethod!.Count, Is.EqualTo(1));
        Assert.That(doc.AssertionMethod[0], Is.EqualTo("did:x509:0:test#key-1"));
    }

    [Test]
    public void Constructor_WithKeyAgreement_StoresValue()
    {
        var verificationMethods = new List<VerificationMethod>
        {
            new VerificationMethod("did:x509:0:test#key-1", "JsonWebKey2020", "did:x509:0:test", new Dictionary<string, object>())
        };
        var keyAgreement = new List<string> { "did:x509:0:test#key-1" };

        var doc = new DidDocument("did:x509:0:test", verificationMethods, null, keyAgreement);

        Assert.That(doc.KeyAgreement, Is.Not.Null);
        Assert.That(doc.KeyAgreement!.Count, Is.EqualTo(1));
        Assert.That(doc.KeyAgreement[0], Is.EqualTo("did:x509:0:test#key-1"));
    }

    [Test]
    public void ToJson_WithMinimalDocument_ReturnsValidJson()
    {
        var jwk = new Dictionary<string, object>
        {
            ["kty"] = "RSA",
            ["n"] = "test-modulus",
            ["e"] = "AQAB"
        };
        var verificationMethods = new List<VerificationMethod>
        {
            new VerificationMethod("did:x509:0:test#key-1", "JsonWebKey2020", "did:x509:0:test", jwk)
        };

        var doc = new DidDocument("did:x509:0:test", verificationMethods);
        var json = doc.ToJson();

        Assert.That(json, Is.Not.Null);
        Assert.That(json, Does.Contain("\"@context\""));
        Assert.That(json, Does.Contain("\"id\""));
        Assert.That(json, Does.Contain("\"verificationMethod\""));
        Assert.That(json, Does.Contain("did:x509:0:test"));
    }

    [Test]
    public void ToJson_WithAssertionMethod_IncludesInJson()
    {
        var jwk = new Dictionary<string, object> { ["kty"] = "RSA" };
        var verificationMethods = new List<VerificationMethod>
        {
            new VerificationMethod("did:x509:0:test#key-1", "JsonWebKey2020", "did:x509:0:test", jwk)
        };
        var assertionMethod = new List<string> { "did:x509:0:test#key-1" };

        var doc = new DidDocument("did:x509:0:test", verificationMethods, assertionMethod);
        var json = doc.ToJson();

        Assert.That(json, Does.Contain("\"assertionMethod\""));
    }

    [Test]
    public void ToJson_WithKeyAgreement_IncludesInJson()
    {
        var jwk = new Dictionary<string, object> { ["kty"] = "RSA" };
        var verificationMethods = new List<VerificationMethod>
        {
            new VerificationMethod("did:x509:0:test#key-1", "JsonWebKey2020", "did:x509:0:test", jwk)
        };
        var keyAgreement = new List<string> { "did:x509:0:test#key-1" };

        var doc = new DidDocument("did:x509:0:test", verificationMethods, null, keyAgreement);
        var json = doc.ToJson();

        Assert.That(json, Does.Contain("\"keyAgreement\""));
    }

    [Test]
    public void ToJson_NonIndented_ReturnsCompactJson()
    {
        var jwk = new Dictionary<string, object> { ["kty"] = "RSA" };
        var verificationMethods = new List<VerificationMethod>
        {
            new VerificationMethod("did:x509:0:test#key-1", "JsonWebKey2020", "did:x509:0:test", jwk)
        };

        var doc = new DidDocument("did:x509:0:test", verificationMethods);
        var json = doc.ToJson(indented: false);

        Assert.That(json, Is.Not.Null);
        Assert.That(json, Does.Not.Contain("\n"));
    }

    [Test]
    public void ToJson_Indented_ReturnsFormattedJson()
    {
        var jwk = new Dictionary<string, object> { ["kty"] = "RSA" };
        var verificationMethods = new List<VerificationMethod>
        {
            new VerificationMethod("did:x509:0:test#key-1", "JsonWebKey2020", "did:x509:0:test", jwk)
        };

        var doc = new DidDocument("did:x509:0:test", verificationMethods);
        var json = doc.ToJson(indented: true);

        Assert.That(json, Is.Not.Null);
        Assert.That(json, Does.Contain("\n"));
    }
}
