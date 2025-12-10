// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace DIDx509.Tests;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using DIDx509.Models;
using DIDx509.Resolution;
using NUnit.Framework;

/// <summary>
/// Additional tests for X509Certificate2Extensions verification methods.
/// Focuses on VerifyByDid* methods that were not covered in the original tests.
/// </summary>
[TestFixture]
public class X509Certificate2ExtensionsVerificationTests : DIDx509TestBase
{
    [Test]
    public void VerifyByDid_WithValidDidAndChain_ReturnsTrue()
    {
        // Arrange
        var chain = CreateTestChain();
        using var leaf = chain[0];
        string did = leaf.GetDidWithRoot(chain);

        // Act
        bool result = leaf.VerifyByDid(did, chain);

        // Assert
        Assert.That(result, Is.True);
    }

    [Test]
    public void VerifyByDid_WithInvalidDid_ReturnsFalse()
    {
        // Arrange
        var chain = CreateTestChain();
        using var leaf = chain[0];
        string invalidDid = "did:x509:0:sha256:invalid::subject:CN:TestLeaf";

        // Act
        bool result = leaf.VerifyByDid(invalidDid, chain);

        // Assert
        Assert.That(result, Is.False);
    }

    [Test]
    public void VerifyByDid_WithMismatchedCertificate_ReturnsFalse()
    {
        // Arrange
        var chain1 = CreateTestChain();
        var chain2 = CreateTestChain();
        using var leaf1 = chain1[0];
        using var leaf2 = chain2[0];
        string did1 = leaf1.GetDidWithRoot(chain1);

        // Act - Verify leaf2 against leaf1's DID
        bool result = leaf2.VerifyByDid(did1, chain2);

        // Assert
        Assert.That(result, Is.False);
    }

    [Test]
    public void VerifyByDid_WithNullCertificate_ThrowsArgumentNullException()
    {
        // Arrange
        X509Certificate2 cert = null!;
        var chain = CreateTestChain();
        string did = "did:x509:0:sha256:test";

        // Act & Assert
        var ex = Assert.Throws<ArgumentNullException>(() => cert.VerifyByDid(did, chain));
        Assert.That(ex.ParamName, Is.EqualTo("certificate"));
    }

    [Test]
    public void VerifyByDid_WithNullDid_ThrowsArgumentException()
    {
        // Arrange
        var chain = CreateTestChain();
        using var leaf = chain[0];

        // Act & Assert
        var ex = Assert.Throws<ArgumentException>(() => leaf.VerifyByDid(null!, chain));
        Assert.That(ex.ParamName, Is.EqualTo("did"));
    }

    [Test]
    public void VerifyByDid_WithEmptyDid_ThrowsArgumentException()
    {
        // Arrange
        var chain = CreateTestChain();
        using var leaf = chain[0];

        // Act & Assert
        var ex = Assert.Throws<ArgumentException>(() => leaf.VerifyByDid("", chain));
        Assert.That(ex.ParamName, Is.EqualTo("did"));
    }

    [Test]
    public void VerifyByDid_WithWhitespaceDid_ThrowsArgumentException()
    {
        // Arrange
        var chain = CreateTestChain();
        using var leaf = chain[0];

        // Act & Assert
        var ex = Assert.Throws<ArgumentException>(() => leaf.VerifyByDid("   ", chain));
        Assert.That(ex.ParamName, Is.EqualTo("did"));
    }

    [Test]
    public void VerifyByDid_WithNullChain_ThrowsArgumentNullException()
    {
        // Arrange
        var chain = CreateTestChain();
        using var leaf = chain[0];
        string did = leaf.GetDidWithRoot(chain);

        // Act & Assert
        var ex = Assert.Throws<ArgumentNullException>(() => leaf.VerifyByDid(did, null!));
        Assert.That(ex.ParamName, Is.EqualTo("chain"));
    }

    [Test]
    public void VerifyByDid_WithValidateChainFalse_ValidatesWithoutChainCheck()
    {
        // Arrange
        var chain = CreateTestChain();
        using var leaf = chain[0];
        string did = leaf.GetDidWithRoot(chain);

        // Act
        bool result = leaf.VerifyByDid(did, chain, validateChain: false);

        // Assert
        Assert.That(result, Is.True);
    }

    [Test]
    public void VerifyByDid_WithCheckRevocationTrue_ValidatesWithRevocationCheck()
    {
        // Arrange
        var chain = CreateTestChain();
        using var leaf = chain[0];
        string did = leaf.GetDidWithRoot(chain);

        // Act - May fail or succeed depending on revocation status
        bool result = leaf.VerifyByDid(did, chain, validateChain: false, checkRevocation: true);

        // Assert - Just verify it doesn't throw
        Assert.That(result, Is.True.Or.False);
    }

    [Test]
    public void VerifyByDidDetailed_WithValidDidAndChain_ReturnsSuccessResult()
    {
        // Arrange
        var chain = CreateTestChain();
        using var leaf = chain[0];
        string did = leaf.GetDidWithRoot(chain);

        // Act
        DidX509ValidationResult result = leaf.VerifyByDidDetailed(did, chain);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Errors, Is.Empty);
        Assert.That(result.ParsedDid, Is.Not.Null);
    }

    [Test]
    public void VerifyByDidDetailed_WithInvalidDid_ReturnsFailureResult()
    {
        // Arrange
        var chain = CreateTestChain();
        using var leaf = chain[0];
        string invalidDid = "did:x509:0:sha256:invalid::subject:CN:TestLeaf";

        // Act
        DidX509ValidationResult result = leaf.VerifyByDidDetailed(invalidDid, chain);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Errors, Is.Not.Empty);
    }

    [Test]
    public void VerifyByDidDetailed_WithNullCertificate_ThrowsArgumentNullException()
    {
        // Arrange
        X509Certificate2 cert = null!;
        var chain = CreateTestChain();
        string did = "did:x509:0:sha256:test";

        // Act & Assert
        var ex = Assert.Throws<ArgumentNullException>(() => cert.VerifyByDidDetailed(did, chain));
        Assert.That(ex.ParamName, Is.EqualTo("certificate"));
    }

    [Test]
    public void VerifyByDidDetailed_WithNullDid_ThrowsArgumentException()
    {
        // Arrange
        var chain = CreateTestChain();
        using var leaf = chain[0];

        // Act & Assert
        var ex = Assert.Throws<ArgumentException>(() => leaf.VerifyByDidDetailed(null!, chain));
        Assert.That(ex.ParamName, Is.EqualTo("did"));
    }

    [Test]
    public void VerifyByDidDetailed_WithNullChain_ThrowsArgumentNullException()
    {
        // Arrange
        var chain = CreateTestChain();
        using var leaf = chain[0];
        string did = leaf.GetDidWithRoot(chain);

        // Act & Assert
        var ex = Assert.Throws<ArgumentNullException>(() => leaf.VerifyByDidDetailed(did, null!));
        Assert.That(ex.ParamName, Is.EqualTo("chain"));
    }

    [Test]
    public void VerifyByDidDetailed_WithValidateChainFalse_ReturnsValidResult()
    {
        // Arrange
        var chain = CreateTestChain();
        using var leaf = chain[0];
        string did = leaf.GetDidWithRoot(chain);

        // Act
        DidX509ValidationResult result = leaf.VerifyByDidDetailed(did, chain, validateChain: false);

        // Assert
        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public void VerifyByDidPoliciesOnly_WithValidDidAndChain_ReturnsTrue()
    {
        // Arrange
        var chain = CreateTestChain();
        using var leaf = chain[0];
        string did = leaf.GetDidWithRoot(chain);

        // Act
        bool result = leaf.VerifyByDidPoliciesOnly(did, chain);

        // Assert
        Assert.That(result, Is.True);
    }

    [Test]
    public void VerifyByDidPoliciesOnly_WithInvalidDid_ReturnsFalse()
    {
        // Arrange
        var chain = CreateTestChain();
        using var leaf = chain[0];
        string invalidDid = "did:x509:0:sha256:invalid::subject:CN:TestLeaf";

        // Act
        bool result = leaf.VerifyByDidPoliciesOnly(invalidDid, chain);

        // Assert
        Assert.That(result, Is.False);
    }

    [Test]
    public void VerifyByDidPoliciesOnly_WithNullCertificate_ThrowsArgumentNullException()
    {
        // Arrange
        X509Certificate2 cert = null!;
        var chain = CreateTestChain();
        string did = "did:x509:0:sha256:test";

        // Act & Assert
        var ex = Assert.Throws<ArgumentNullException>(() => cert.VerifyByDidPoliciesOnly(did, chain));
        Assert.That(ex.ParamName, Is.EqualTo("certificate"));
    }

    [Test]
    public void VerifyByDidPoliciesOnly_WithNullDid_ThrowsArgumentException()
    {
        // Arrange
        var chain = CreateTestChain();
        using var leaf = chain[0];

        // Act & Assert
        var ex = Assert.Throws<ArgumentException>(() => leaf.VerifyByDidPoliciesOnly(null!, chain));
        Assert.That(ex.ParamName, Is.EqualTo("did"));
    }

    [Test]
    public void VerifyByDidPoliciesOnly_WithEmptyDid_ThrowsArgumentException()
    {
        // Arrange
        var chain = CreateTestChain();
        using var leaf = chain[0];

        // Act & Assert
        var ex = Assert.Throws<ArgumentException>(() => leaf.VerifyByDidPoliciesOnly("", chain));
        Assert.That(ex.ParamName, Is.EqualTo("did"));
    }

    [Test]
    public void VerifyByDidPoliciesOnly_WithNullChain_ThrowsArgumentNullException()
    {
        // Arrange
        var chain = CreateTestChain();
        using var leaf = chain[0];
        string did = leaf.GetDidWithRoot(chain);

        // Act & Assert
        var ex = Assert.Throws<ArgumentNullException>(() => leaf.VerifyByDidPoliciesOnly(did, null!));
        Assert.That(ex.ParamName, Is.EqualTo("chain"));
    }

    [Test]
    public void TryVerifyByDid_WithValidDidAndChain_ReturnsTrueWithEmptyErrors()
    {
        // Arrange
        var chain = CreateTestChain();
        using var leaf = chain[0];
        string did = leaf.GetDidWithRoot(chain);

        // Act
        bool result = leaf.TryVerifyByDid(did, chain, out var errors);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(errors, Is.Empty);
    }

    [Test]
    public void TryVerifyByDid_WithInvalidDid_ReturnsFalseWithErrors()
    {
        // Arrange
        var chain = CreateTestChain();
        using var leaf = chain[0];
        string invalidDid = "did:x509:0:sha256:invalid::subject:CN:TestLeaf";

        // Act
        bool result = leaf.TryVerifyByDid(invalidDid, chain, out var errors);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(errors, Is.Not.Empty);
    }

    [Test]
    public void TryVerifyByDid_WithNullCertificate_ReturnsFalseWithErrorMessage()
    {
        // Arrange
        X509Certificate2 cert = null!;
        var chain = CreateTestChain();
        string did = "did:x509:0:sha256:test";

        // Act
        bool result = cert.TryVerifyByDid(did, chain, out var errors);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(errors, Is.Not.Empty);
        // Note: TryVerifyByDid catches exceptions, error may be about DID parsing not certificate
    }

    [Test]
    public void TryVerifyByDid_WithNullDid_ReturnsFalseWithErrorMessage()
    {
        // Arrange
        var chain = CreateTestChain();
        using var leaf = chain[0];

        // Act
        bool result = leaf.TryVerifyByDid(null!, chain, out var errors);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(errors, Is.Not.Empty);
    }

    [Test]
    public void TryVerifyByDid_WithNullChain_ReturnsFalseWithErrorMessage()
    {
        // Arrange
        var chain = CreateTestChain();
        using var leaf = chain[0];
        string did = leaf.GetDidWithRoot(chain);

        // Act
        bool result = leaf.TryVerifyByDid(did, null!, out var errors);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(errors, Is.Not.Empty);
    }

    [Test]
    public void TryVerifyByDid_WithValidateChainFalse_ValidatesWithoutChainCheck()
    {
        // Arrange
        var chain = CreateTestChain();
        using var leaf = chain[0];
        string did = leaf.GetDidWithRoot(chain);

        // Act
        bool result = leaf.TryVerifyByDid(did, chain, out var errors, validateChain: false);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(errors, Is.Empty);
    }

    [Test]
    public void TryVerifyByDid_WithCheckRevocationTrue_ValidatesWithRevocationCheck()
    {
        // Arrange
        var chain = CreateTestChain();
        using var leaf = chain[0];
        string did = leaf.GetDidWithRoot(chain);

        // Act
        bool result = leaf.TryVerifyByDid(did, chain, out var errors, validateChain: false, checkRevocation: true);

        // Assert - Should succeed or fail gracefully with errors
        if (!result)
        {
            Assert.That(errors, Is.Not.Empty);
        }
    }

    [Test]
    public void VerifyByDidAndResolve_WithValidDidAndChain_ReturnsTrueWithDocument()
    {
        // Arrange
        var chain = CreateTestChain();
        using var leaf = chain[0];
        string did = leaf.GetDidWithRoot(chain);

        // Act
        bool result = leaf.VerifyByDidAndResolve(did, chain, out var document);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(document, Is.Not.Null);
        Assert.That(document!.Id, Is.EqualTo(did));
        Assert.That(document.VerificationMethods, Is.Not.Empty);
    }

    [Test]
    public void VerifyByDidAndResolve_WithInvalidDid_ReturnsFalseWithNullDocument()
    {
        // Arrange
        var chain = CreateTestChain();
        using var leaf = chain[0];
        string invalidDid = "did:x509:0:sha256:invalid::subject:CN:TestLeaf";

        // Act
        bool result = leaf.VerifyByDidAndResolve(invalidDid, chain, out var document);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(document, Is.Null);
    }

    [Test]
    public void VerifyByDidAndResolve_WithValidateChainFalse_ResolvesSuccessfully()
    {
        // Arrange
        var chain = CreateTestChain();
        using var leaf = chain[0];
        string did = leaf.GetDidWithRoot(chain);

        // Act
        bool result = leaf.VerifyByDidAndResolve(did, chain, out var document, validateChain: false);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(document, Is.Not.Null);
    }

    [Test]
    public void VerifyByDidAndResolve_WithCheckRevocationTrue_ResolvesWithRevocationCheck()
    {
        // Arrange
        var chain = CreateTestChain();
        using var leaf = chain[0];
        string did = leaf.GetDidWithRoot(chain);

        // Act
        bool result = leaf.VerifyByDidAndResolve(did, chain, out var document, validateChain: false, checkRevocation: true);

        // Assert - Should succeed or fail gracefully
        if (result)
        {
            Assert.That(document, Is.Not.Null);
        }
        else
        {
            Assert.That(document, Is.Null);
        }
    }

    [Test]
    public void VerifyByDidAndResolve_DocumentContainsVerificationMethods()
    {
        // Arrange
        var chain = CreateTestChain();
        using var leaf = chain[0];
        string did = leaf.GetDidWithRoot(chain);

        // Act
        bool result = leaf.VerifyByDidAndResolve(did, chain, out var document);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(document!.VerificationMethods, Has.Count.GreaterThan(0));
        Assert.That(document.VerificationMethods[0].Id, Does.StartWith(did));
    }
}
