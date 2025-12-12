// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using CoseSign1.Tests.Common;
using DIDx509;
using DIDx509.CertificateChain;
using DIDx509.Models;
using DIDx509.Validation;
using NUnit.Framework;

namespace DIDx509.Tests.Validation;

[TestFixture]
public class FulcioIssuerPolicyValidatorTests
{
    [Test]
    public void Validate_WithMatchingFulcioIssuer_ReturnsTrue()
    {
        // Arrange
        var issuerUrl = "github.com/login/oauth";
        var policy = new DidX509Policy("fulcio-issuer", issuerUrl, issuerUrl);

        // Create chain with Fulcio issuer extension
        var chain = CreateChainWithFulcioIssuer("https://github.com/login/oauth");

        // Act
        var result = FulcioIssuerPolicyValidator.Validate(policy, chain, out var errors);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(errors, Is.Empty);
    }

    [Test]
    public void Validate_WithMismatchedFulcioIssuer_ReturnsFalse()
    {
        // Arrange
        var policy = new DidX509Policy("fulcio-issuer", "github.com/login/oauth", "github.com/login/oauth");

        // Create chain with different Fulcio issuer
        var chain = CreateChainWithFulcioIssuer("https://gitlab.com/oauth");

        // Act
        var result = FulcioIssuerPolicyValidator.Validate(policy, chain, out var errors);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(errors, Has.Count.EqualTo(1));
        Assert.That(errors[0], Does.Contain("Expected 'https://github.com/login/oauth'"));
        Assert.That(errors[0], Does.Contain("got 'https://gitlab.com/oauth'"));
    }

    [Test]
    public void Validate_WithMissingFulcioIssuerExtension_ReturnsFalse()
    {
        // Arrange
        var policy = new DidX509Policy("fulcio-issuer", "github.com", "github.com");

        // Create chain without Fulcio issuer extension
        var chain = CreateChainWithoutFulcioIssuer();

        // Act
        var result = FulcioIssuerPolicyValidator.Validate(policy, chain, out var errors);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(errors, Has.Count.EqualTo(1));
        Assert.That(errors[0], Does.Contain("no Fulcio issuer extension"));
    }

    [Test]
    public void Validate_WithNullParsedValue_ReturnsFalse()
    {
        // Arrange - policy with null parsed value
        var policy = new DidX509Policy("fulcio-issuer", "github.com", null);

        var chain = CreateChainWithFulcioIssuer("https://github.com");

        // Act
        var result = FulcioIssuerPolicyValidator.Validate(policy, chain, out var errors);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(errors, Has.Count.EqualTo(1));
        Assert.That(errors[0], Does.Contain("Failed to parse policy value"));
    }

    [Test]
    public void Validate_WithNonStringParsedValue_ReturnsFalse()
    {
        // Arrange - policy with integer parsed value instead of string
        var policy = new DidX509Policy("fulcio-issuer", "123", 123);

        var chain = CreateChainWithFulcioIssuer("https://github.com");

        // Act
        var result = FulcioIssuerPolicyValidator.Validate(policy, chain, out var errors);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(errors, Has.Count.EqualTo(1));
        Assert.That(errors[0], Does.Contain("Failed to parse policy value"));
    }

    [Test]
    public void Validate_WithEmptyFulcioIssuer_ReturnsFalse()
    {
        // Arrange
        var policy = new DidX509Policy("fulcio-issuer", "github.com", "github.com");

        // Create chain with empty Fulcio issuer
        var chain = CreateChainWithFulcioIssuer(string.Empty);

        // Act
        var result = FulcioIssuerPolicyValidator.Validate(policy, chain, out var errors);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(errors, Has.Count.EqualTo(1));
        Assert.That(errors[0], Does.Contain("no Fulcio issuer extension"));
    }

    [Test]
    public void Validate_WithCaseSensitiveComparison_EnforcesExactMatch()
    {
        // Arrange - policy with lowercase issuer
        var policy = new DidX509Policy("fulcio-issuer", "github.com/login/oauth", "github.com/login/oauth");

        // Create chain with uppercase in URL (different case)
        var chain = CreateChainWithFulcioIssuer("https://GITHUB.com/login/oauth");

        // Act
        var result = FulcioIssuerPolicyValidator.Validate(policy, chain, out var errors);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(errors, Has.Count.EqualTo(1));
        Assert.That(errors[0], Does.Contain("Expected 'https://github.com/login/oauth'"));
        Assert.That(errors[0], Does.Contain("got 'https://GITHUB.com/login/oauth'"));
    }

    [Test]
    public void Validate_WithHttpsPrefixInPolicy_StillAddsPrefix()
    {
        // Arrange - policy value should NOT include https:// (it will be added)
        var policy = new DidX509Policy("fulcio-issuer", "github.com", "github.com");

        var chain = CreateChainWithFulcioIssuer("https://github.com");

        // Act
        var result = FulcioIssuerPolicyValidator.Validate(policy, chain, out var errors);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(errors, Is.Empty);
    }

    [Test]
    public void Validate_WithTrailingSlashDifference_ReturnsFalse()
    {
        // Arrange
        var policy = new DidX509Policy("fulcio-issuer", "github.com/", "github.com/");

        var chain = CreateChainWithFulcioIssuer("https://github.com");

        // Act
        var result = FulcioIssuerPolicyValidator.Validate(policy, chain, out var errors);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(errors, Has.Count.EqualTo(1));
    }

    [Test]
    public void Validate_WithComplexGitHubOAuthUrl_ReturnsTrue()
    {
        // Arrange
        var issuerUrl = "github.com/login/oauth/authorize";
        var policy = new DidX509Policy("fulcio-issuer", issuerUrl, issuerUrl);

        var chain = CreateChainWithFulcioIssuer($"https://{issuerUrl}");

        // Act
        var result = FulcioIssuerPolicyValidator.Validate(policy, chain, out var errors);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(errors, Is.Empty);
    }

    [Test]
    public void Validate_WithGitLabIssuer_ReturnsTrue()
    {
        // Arrange
        var issuerUrl = "gitlab.com/oauth";
        var policy = new DidX509Policy("fulcio-issuer", issuerUrl, issuerUrl);

        var chain = CreateChainWithFulcioIssuer($"https://{issuerUrl}");

        // Act
        var result = FulcioIssuerPolicyValidator.Validate(policy, chain, out var errors);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(errors, Is.Empty);
    }

    [Test]
    public void Validate_WithGoogleIssuer_ReturnsTrue()
    {
        // Arrange
        var issuerUrl = "accounts.google.com";
        var policy = new DidX509Policy("fulcio-issuer", issuerUrl, issuerUrl);

        var chain = CreateChainWithFulcioIssuer($"https://{issuerUrl}");

        // Act
        var result = FulcioIssuerPolicyValidator.Validate(policy, chain, out var errors);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(errors, Is.Empty);
    }

    [Test]
    public void Validate_WithMicrosoftIssuer_ReturnsTrue()
    {
        // Arrange
        var issuerUrl = "login.microsoftonline.com/common/v2.0";
        var policy = new DidX509Policy("fulcio-issuer", issuerUrl, issuerUrl);

        var chain = CreateChainWithFulcioIssuer($"https://{issuerUrl}");

        // Act
        var result = FulcioIssuerPolicyValidator.Validate(policy, chain, out var errors);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(errors, Is.Empty);
    }

    // Helper methods to create test chains

    private static CertificateChainModel CreateChainWithFulcioIssuer(string? fulcioIssuer)
    {
        // Use CertificateChainConverter to create a proper model
        var testChain = TestCertificateUtils.CreateTestChain();
        var chainModel = CertificateChainConverter.Convert(testChain.Cast<X509Certificate2>());

        // If fulcioIssuer is provided, we need to create a custom model with that extension
        // For testing purposes, we'll use reflection or create a mock
        // Since we can't easily modify the Extensions after creation, we'll rely on test setup
        // However, CertificateChainConverter won't have Fulcio extensions from our test certs
        // So we need to manually build the model

        var leaf = testChain[0];
        var intermediate = testChain[1];
        var root = testChain[2];

        // Parse names from certificates
        var leafInfo = CreateCertInfoWithFulcio(leaf, fulcioIssuer);
        var intermediateInfo = CreateCertInfoNoExtensions(intermediate);
        var rootInfo = CreateCertInfoNoExtensions(root);

        return new CertificateChainModel(new[] { leafInfo, intermediateInfo, rootInfo });
    }

    private static CertificateInfo CreateCertInfoWithFulcio(X509Certificate2 cert, string? fulcioIssuer)
    {
        var fingerprints = ComputeFingerprint(cert);
        var issuer = ParseName(cert.IssuerName);
        var subject = ParseName(cert.SubjectName);
        var extensions = new CertificateExtensions(eku: null, san: null, fulcioIssuer: fulcioIssuer);

        return new CertificateInfo(fingerprints, issuer, subject, extensions, cert);
    }

    private static CertificateInfo CreateCertInfoNoExtensions(X509Certificate2 cert)
    {
        var fingerprints = ComputeFingerprint(cert);
        var issuer = ParseName(cert.IssuerName);
        var subject = ParseName(cert.SubjectName);
        var extensions = new CertificateExtensions(eku: null, san: null, fulcioIssuer: null);

        return new CertificateInfo(fingerprints, issuer, subject, extensions, cert);
    }

    private static CertificateFingerprints ComputeFingerprint(X509Certificate2 cert)
    {
        var hash = System.Security.Cryptography.SHA256.HashData(cert.RawData);
        var base64Url = Convert.ToBase64String(hash).Replace('+', '-').Replace('/', '_').TrimEnd('=');
        return new CertificateFingerprints(base64Url, base64Url, base64Url);
    }

    private static X509Name ParseName(X500DistinguishedName dn)
    {
        var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var parts = dn.Name.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        foreach (var part in parts)
        {
            var kv = part.Split('=', 2, StringSplitOptions.TrimEntries);
            if (kv.Length == 2)
            {
                dict[kv[0]] = kv[1];
            }
        }
        return new X509Name(dict);
    }

    private static CertificateChainModel CreateChainWithoutFulcioIssuer()
    {
        return CreateChainWithFulcioIssuer(null);
    }
}