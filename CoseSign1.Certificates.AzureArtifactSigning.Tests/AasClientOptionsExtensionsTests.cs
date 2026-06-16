// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.AzureArtifactSigning.Tests;

using System;
using Azure.CodeSigning;
using Azure.Core;
using Azure.Developer.ArtifactSigning.CryptoProvider.Models;
using NUnit.Framework;

/// <summary>
/// Tests for <see cref="AasClientOptionsExtensions"/> — the AAS analogue of the MST
/// performance optimisation extensions. These verify that interactive signing latency
/// is bounded by short, fixed-delay retries and that callers can override defaults
/// without losing fluent chaining.
/// </summary>
[TestFixture]
public class AasClientOptionsExtensionsTests
{
    [Test]
    public void ConfigureAasPerformanceOptimizations_AppliesFastFixedRetries()
    {
        // Arrange
        CertificateProfileClientOptions options = new CertificateProfileClientOptions();

        // Act
        CertificateProfileClientOptions returned = options.ConfigureAasPerformanceOptimizations();

        // Assert
        Assert.That(returned, Is.SameAs(options), "Extension method must return the same instance for fluent chaining.");
        Assert.That(options.Retry.Mode, Is.EqualTo(RetryMode.Fixed), "Retry mode must be Fixed for predictable interactive latency.");
        Assert.That(options.Retry.Delay, Is.EqualTo(AasClientOptionsExtensions.DefaultRetryDelay));
        Assert.That(options.Retry.MaxRetries, Is.EqualTo(AasClientOptionsExtensions.DefaultMaxRetries));
    }

    [Test]
    public void ConfigureAasPerformanceOptimizations_HonoursOverrides()
    {
        // Arrange
        CertificateProfileClientOptions options = new CertificateProfileClientOptions();
        TimeSpan customDelay = TimeSpan.FromMilliseconds(100);
        const int customRetries = 16;

        // Act
        options.ConfigureAasPerformanceOptimizations(customDelay, customRetries);

        // Assert
        Assert.That(options.Retry.Delay, Is.EqualTo(customDelay));
        Assert.That(options.Retry.MaxRetries, Is.EqualTo(customRetries));
    }

    [Test]
    public void ConfigureAasPerformanceOptimizations_NullOptions_Throws()
    {
        // Act / Assert
        ArgumentNullException ex = Assert.Throws<ArgumentNullException>(
            () => AasClientOptionsExtensions.ConfigureAasPerformanceOptimizations(null!));
        Assert.That(ex.ParamName, Is.EqualTo("options"));
    }

    [Test]
    public void ConfigureAasSigningPerformance_ReturnsDefaultsWhenUnset()
    {
        // Act
        AzSignContextOptions opts = AasClientOptionsExtensions.ConfigureAasSigningPerformance();

        // Assert
        Assert.That(opts, Is.Not.Null);
        Assert.That(opts.TaskRetryCount, Is.EqualTo(AasClientOptionsExtensions.DefaultSigningTaskRetryCount));
        Assert.That(opts.TaskTimeOutInSeconds, Is.EqualTo(AasClientOptionsExtensions.DefaultSigningTaskTimeoutSeconds));
    }

    [Test]
    public void ConfigureAasSigningPerformance_HonoursOverrides()
    {
        // Act
        AzSignContextOptions opts = AasClientOptionsExtensions.ConfigureAasSigningPerformance(
            taskRetryCount: 5,
            taskTimeoutSeconds: 30);

        // Assert
        Assert.That(opts.TaskRetryCount, Is.EqualTo(5));
        Assert.That(opts.TaskTimeOutInSeconds, Is.EqualTo(30));
    }
}
