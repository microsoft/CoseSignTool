// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSignTool.Plugins;

namespace CoseSignTool.Tests.Plugins;

/// <summary>
/// Tests for the SigningOptions class.
/// </summary>
public class SigningOptionsTests
{
    [Fact]
    public void SigningOptions_DefaultConstructor_InitializesProperties()
    {
        // Act
        var options = new SigningOptions();

        // Assert
        options.Detached.Should().BeFalse();
        options.CertificateId.Should().BeNull();
        options.CustomOptions.Should().BeNull();
    }

    [Fact]
    public void SigningOptions_CanSetDetached()
    {
        // Arrange
        var options = new SigningOptions();

        // Act
        options.Detached = true;

        // Assert
        options.Detached.Should().BeTrue();
    }

    [Fact]
    public void SigningOptions_CanSetCertificateId()
    {
        // Arrange
        var options = new SigningOptions();

        // Act
        options.CertificateId = "test-cert-id";

        // Assert
        options.CertificateId.Should().Be("test-cert-id");
    }

    [Fact]
    public void SigningOptions_CanSetCustomOptions()
    {
        // Arrange
        var options = new SigningOptions();
        var customOptions = new Dictionary<string, object>
        {
            { "key1", "value1" },
            { "key2", 42 }
        };

        // Act
        options.CustomOptions = customOptions;

        // Assert
        options.CustomOptions.Should().NotBeNull();
        options.CustomOptions!["key1"].Should().Be("value1");
        options.CustomOptions["key2"].Should().Be(42);
    }
}
