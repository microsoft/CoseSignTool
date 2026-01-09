// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace DIDx509.Tests.Resolution;

using DIDx509.Resolution;

[TestFixture]
public class VerificationMethodTests
{
    [Test]
    public void Constructor_WithValidParameters_CreatesVerificationMethod()
    {
        var jwk = new Dictionary<string, object>
        {
            ["kty"] = "RSA",
            ["n"] = "modulus",
            ["e"] = "AQAB"
        };

        var vm = new VerificationMethod("did:x509:0:test#key-1", "JsonWebKey2020", "did:x509:0:test", jwk);

        Assert.That(vm.Id, Is.EqualTo("did:x509:0:test#key-1"));
        Assert.That(vm.Type, Is.EqualTo("JsonWebKey2020"));
        Assert.That(vm.Controller, Is.EqualTo("did:x509:0:test"));
        Assert.That(vm.PublicKeyJwk, Is.Not.Null);
        Assert.That(vm.PublicKeyJwk["kty"], Is.EqualTo("RSA"));
    }

    [Test]
    public void Constructor_WithNullId_ThrowsArgumentNullException()
    {
        var jwk = new Dictionary<string, object>();
        Assert.Throws<ArgumentNullException>(() =>
            new VerificationMethod(null!, "JsonWebKey2020", "did:x509:0:test", jwk));
    }

    [Test]
    public void Constructor_WithNullType_ThrowsArgumentNullException()
    {
        var jwk = new Dictionary<string, object>();
        Assert.Throws<ArgumentNullException>(() =>
            new VerificationMethod("did:x509:0:test#key-1", null!, "did:x509:0:test", jwk));
    }

    [Test]
    public void Constructor_WithNullController_ThrowsArgumentNullException()
    {
        var jwk = new Dictionary<string, object>();
        Assert.Throws<ArgumentNullException>(() =>
            new VerificationMethod("did:x509:0:test#key-1", "JsonWebKey2020", null!, jwk));
    }

    [Test]
    public void Constructor_WithNullPublicKeyJwk_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() =>
            new VerificationMethod("did:x509:0:test#key-1", "JsonWebKey2020", "did:x509:0:test", null!));
    }

    [Test]
    public void Constructor_WithECKey_StoresCorrectly()
    {
        var jwk = new Dictionary<string, object>
        {
            ["kty"] = "EC",
            ["crv"] = "P-256",
            ["x"] = "x-coordinate",
            ["y"] = "y-coordinate"
        };

        var vm = new VerificationMethod("did:x509:0:test#key-1", "JsonWebKey2020", "did:x509:0:test", jwk);

        Assert.That(vm.PublicKeyJwk["kty"], Is.EqualTo("EC"));
        Assert.That(vm.PublicKeyJwk["crv"], Is.EqualTo("P-256"));
    }
}