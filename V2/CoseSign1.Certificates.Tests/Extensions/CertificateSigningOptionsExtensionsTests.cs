// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSign1.Abstractions;
using CoseSign1.Certificates;
using CoseSign1.Certificates.Extensions;
using NUnit.Framework;
using System.Collections.Generic;

namespace CoseSign1.Certificates.Tests.Extensions;

[TestFixture]
public class CertificateSigningOptionsExtensionsTests
{
    [Test]
    public void TryGetCertificateOptions_WithValidOptions_ReturnsTrue()
    {
        var certOptions = new CertificateSigningOptions();
        var additionalContext = new Dictionary<string, object>
        {
            [CertificateSigningOptionsExtensions.CertificateSigningOptionsKey] = certOptions
        };
        var context = new SigningContext(
            new byte[] { 1, 2, 3 },
            "application/test",
            additionalContext: additionalContext);

        var result = context.TryGetCertificateOptions(out var retrievedOptions);

        Assert.That(result, Is.True);
        Assert.That(retrievedOptions, Is.SameAs(certOptions));
    }

    [Test]
    public void TryGetCertificateOptions_WithNullContext_ReturnsFalse()
    {
        SigningContext? context = null;

        var result = context!.TryGetCertificateOptions(out var retrievedOptions);

        Assert.That(result, Is.False);
        Assert.That(retrievedOptions, Is.Null);
    }

    [Test]
    public void TryGetCertificateOptions_WithNullAdditionalContext_ReturnsFalse()
    {
        var context = new SigningContext(
            new byte[] { 1, 2, 3 },
            "application/test",
            additionalContext: null);

        var result = context.TryGetCertificateOptions(out var retrievedOptions);

        Assert.That(result, Is.False);
        Assert.That(retrievedOptions, Is.Null);
    }

    [Test]
    public void TryGetCertificateOptions_WithMissingKey_ReturnsFalse()
    {
        var additionalContext = new Dictionary<string, object>
        {
            ["OtherKey"] = "some value"
        };
        var context = new SigningContext(
            new byte[] { 1, 2, 3 },
            "application/test",
            additionalContext: additionalContext);

        var result = context.TryGetCertificateOptions(out var retrievedOptions);

        Assert.That(result, Is.False);
        Assert.That(retrievedOptions, Is.Null);
    }

    [Test]
    public void TryGetCertificateOptions_WithWrongValueType_ReturnsFalse()
    {
        var additionalContext = new Dictionary<string, object>
        {
            [CertificateSigningOptionsExtensions.CertificateSigningOptionsKey] = "not a CertificateSigningOptions"
        };
        var context = new SigningContext(
            new byte[] { 1, 2, 3 },
            "application/test",
            additionalContext: additionalContext);

        var result = context.TryGetCertificateOptions(out var retrievedOptions);

        Assert.That(result, Is.False);
        Assert.That(retrievedOptions, Is.Null);
    }
}
