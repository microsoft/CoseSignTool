// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member

namespace CoseSignTool.Abstractions.Tests;

using CoseSign1.Abstractions.Interfaces;
using Microsoft.Extensions.Configuration;
using Moq;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;

/// <summary>
/// Tests for <see cref="CertificateProviderPluginManager"/>.
/// </summary>
[TestClass]
public class CertificateProviderPluginManagerTests
{
    /// <summary>
    /// Tests that constructor succeeds without a logger.
    /// </summary>
    [TestMethod]
    public void Constructor_WithoutLogger_ShouldSucceed()
    {
        // Act
        CertificateProviderPluginManager manager = new CertificateProviderPluginManager();

        // Assert
        Assert.IsNotNull(manager);
        Assert.AreEqual(0, manager.Providers.Count);
    }

    [TestMethod]
    public void Constructor_WithLogger_ShouldSucceed()
    {
        // Arrange
        Mock<IPluginLogger> mockLogger = new Mock<IPluginLogger>();

        // Act
        CertificateProviderPluginManager manager = new CertificateProviderPluginManager(mockLogger.Object);

        // Assert
        Assert.IsNotNull(manager);
        Assert.AreEqual(0, manager.Providers.Count);
    }

    [TestMethod]
    public void RegisterPlugin_WithValidPlugin_ShouldSucceed()
    {
        // Arrange
        CertificateProviderPluginManager manager = new CertificateProviderPluginManager();
        Mock<ICertificateProviderPlugin> mockPlugin = CreateMockPlugin("test-provider", "Test Provider");

        // Act
        manager.RegisterPlugin(mockPlugin.Object);

        // Assert
        Assert.AreEqual(1, manager.Providers.Count);
        Assert.IsTrue(manager.Providers.ContainsKey("test-provider"));
    }

    [TestMethod]
    public void RegisterPlugin_WithNullPlugin_ShouldThrowArgumentNullException()
    {
        // Arrange
        CertificateProviderPluginManager manager = new CertificateProviderPluginManager();

        // Act & Assert
        Assert.ThrowsException<ArgumentNullException>(() => manager.RegisterPlugin(null!));
    }

    [TestMethod]
    public void RegisterPlugin_WithDuplicateName_ShouldThrowArgumentException()
    {
        // Arrange
        CertificateProviderPluginManager manager = new CertificateProviderPluginManager();
        Mock<ICertificateProviderPlugin> mockPlugin1 = CreateMockPlugin("test-provider", "Test Provider 1");
        Mock<ICertificateProviderPlugin> mockPlugin2 = CreateMockPlugin("test-provider", "Test Provider 2");

        manager.RegisterPlugin(mockPlugin1.Object);

        // Act & Assert
        ArgumentException ex = Assert.ThrowsException<ArgumentException>(() => manager.RegisterPlugin(mockPlugin2.Object));
        Assert.IsTrue(ex.Message.Contains("test-provider"));
        Assert.IsTrue(ex.Message.Contains("already registered"));
    }

    [TestMethod]
    public void RegisterPlugin_WithCaseInsensitiveName_ShouldTreatAsDuplicate()
    {
        // Arrange
        CertificateProviderPluginManager manager = new CertificateProviderPluginManager();
        Mock<ICertificateProviderPlugin> mockPlugin1 = CreateMockPlugin("Test-Provider", "Test Provider 1");
        Mock<ICertificateProviderPlugin> mockPlugin2 = CreateMockPlugin("test-provider", "Test Provider 2");

        manager.RegisterPlugin(mockPlugin1.Object);

        // Act & Assert
        ArgumentException ex = Assert.ThrowsException<ArgumentException>(() => manager.RegisterPlugin(mockPlugin2.Object));
        Assert.IsTrue(ex.Message.Contains("test-provider"));
    }

    [TestMethod]
    public void GetProvider_WithValidName_ShouldReturnProvider()
    {
        // Arrange
        CertificateProviderPluginManager manager = new CertificateProviderPluginManager();
        Mock<ICertificateProviderPlugin> mockPlugin = CreateMockPlugin("test-provider", "Test Provider");
        manager.RegisterPlugin(mockPlugin.Object);

        // Act
        ICertificateProviderPlugin? result = manager.GetProvider("test-provider");

        // Assert
        Assert.IsNotNull(result);
        Assert.AreEqual("test-provider", result.ProviderName);
    }

    [TestMethod]
    public void GetProvider_WithCaseInsensitiveName_ShouldReturnProvider()
    {
        // Arrange
        CertificateProviderPluginManager manager = new CertificateProviderPluginManager();
        Mock<ICertificateProviderPlugin> mockPlugin = CreateMockPlugin("Test-Provider", "Test Provider");
        manager.RegisterPlugin(mockPlugin.Object);

        // Act
        ICertificateProviderPlugin? result = manager.GetProvider("test-provider");

        // Assert
        Assert.IsNotNull(result);
        Assert.AreEqual("Test-Provider", result.ProviderName);
    }

    [TestMethod]
    public void GetProvider_WithNonExistentName_ShouldReturnNull()
    {
        // Arrange
        CertificateProviderPluginManager manager = new CertificateProviderPluginManager();

        // Act
        ICertificateProviderPlugin? result = manager.GetProvider("non-existent");

        // Assert
        Assert.IsNull(result);
    }

    [TestMethod]
    public void GetProvider_WithNullOrWhitespaceName_ShouldReturnNull()
    {
        // Arrange
        CertificateProviderPluginManager manager = new CertificateProviderPluginManager();

        // Act & Assert
        Assert.IsNull(manager.GetProvider(null!));
        Assert.IsNull(manager.GetProvider(""));
        Assert.IsNull(manager.GetProvider("   "));
    }

    [TestMethod]
    public void MergeProviderOptions_WithValidInputs_ShouldMergeOptions()
    {
        // Arrange
        Dictionary<string, string> baseOptions = new Dictionary<string, string>
        {
            ["--payload"] = "payload",
            ["--signature"] = "signature"
        };

        Mock<ICertificateProviderPlugin> mockPlugin = CreateMockPlugin("test-provider", "Test Provider");
        mockPlugin.Setup(p => p.GetProviderOptions()).Returns(new Dictionary<string, string>
        {
            ["--test-option"] = "test-option"
        });

        // Act
        Dictionary<string, string> merged = CertificateProviderPluginManager.MergeProviderOptions(baseOptions, mockPlugin.Object);

        // Assert
        Assert.AreEqual(5, merged.Count); // 2 base + 2 cert-provider + 1 plugin
        Assert.IsTrue(merged.ContainsKey("--payload"));
        Assert.IsTrue(merged.ContainsKey("--signature"));
        Assert.IsTrue(merged.ContainsKey("--cert-provider"));
        Assert.IsTrue(merged.ContainsKey("-cp"));
        Assert.IsTrue(merged.ContainsKey("--test-option"));
    }

    [TestMethod]
    public void MergeProviderOptions_WithConflictingKeys_ShouldThrowInvalidOperationException()
    {
        // Arrange
        Dictionary<string, string> baseOptions = new Dictionary<string, string>
        {
            ["--payload"] = "payload"
        };

        Mock<ICertificateProviderPlugin> mockPlugin = CreateMockPlugin("test-provider", "Test Provider");
        mockPlugin.Setup(p => p.GetProviderOptions()).Returns(new Dictionary<string, string>
        {
            ["--payload"] = "conflicting-payload"
        });

        // Act & Assert
        InvalidOperationException ex = Assert.ThrowsException<InvalidOperationException>(
            () => CertificateProviderPluginManager.MergeProviderOptions(baseOptions, mockPlugin.Object));
        Assert.IsTrue(ex.Message.Contains("test-provider"));
        Assert.IsTrue(ex.Message.Contains("--payload"));
        Assert.IsTrue(ex.Message.Contains("conflicts"));
    }

    [TestMethod]
    public void MergeProviderOptions_WithNullBaseOptions_ShouldThrowArgumentNullException()
    {
        // Arrange
        Mock<ICertificateProviderPlugin> mockPlugin = CreateMockPlugin("test-provider", "Test Provider");

        // Act & Assert
        Assert.ThrowsException<ArgumentNullException>(
            () => CertificateProviderPluginManager.MergeProviderOptions(null!, mockPlugin.Object));
    }

    [TestMethod]
    public void MergeProviderOptions_WithNullPlugin_ShouldThrowArgumentNullException()
    {
        // Arrange
        Dictionary<string, string> baseOptions = new Dictionary<string, string>();

        // Act & Assert
        Assert.ThrowsException<ArgumentNullException>(
            () => CertificateProviderPluginManager.MergeProviderOptions(baseOptions, null!));
    }

    [TestMethod]
    public void GetAllOptions_WithMultiplePlugins_ShouldIncludeCertProviderOption()
    {
        // Arrange
        CertificateProviderPluginManager manager = new CertificateProviderPluginManager();
        Mock<ICertificateProviderPlugin> mockPlugin1 = CreateMockPlugin("provider1", "Provider 1");
        Mock<ICertificateProviderPlugin> mockPlugin2 = CreateMockPlugin("provider2", "Provider 2");
        manager.RegisterPlugin(mockPlugin1.Object);
        manager.RegisterPlugin(mockPlugin2.Object);

        Dictionary<string, string> baseOptions = new Dictionary<string, string>
        {
            ["--payload"] = "payload"
        };

        // Act
        Dictionary<string, string> allOptions = manager.GetAllOptions(baseOptions);

        // Assert
        Assert.IsTrue(allOptions.ContainsKey("--payload"));
        Assert.IsTrue(allOptions.ContainsKey("--cert-provider"));
        Assert.IsTrue(allOptions.ContainsKey("-cp"));
    }

    [TestMethod]
    public void GetProvidersUsageDocumentation_WithNoPlugins_ShouldReturnNoPluginsMessage()
    {
        // Arrange
        CertificateProviderPluginManager manager = new CertificateProviderPluginManager();

        // Act
        string usage = manager.GetProvidersUsageDocumentation();

        // Assert
        Assert.IsTrue(usage.Contains("No certificate provider plugins"));
    }

    [TestMethod]
    public void GetProvidersUsageDocumentation_WithPlugins_ShouldIncludeAllPlugins()
    {
        // Arrange
        CertificateProviderPluginManager manager = new CertificateProviderPluginManager();
        Mock<ICertificateProviderPlugin> mockPlugin1 = CreateMockPlugin("provider1", "Provider 1");
        Mock<ICertificateProviderPlugin> mockPlugin2 = CreateMockPlugin("provider2", "Provider 2");
        
        mockPlugin1.Setup(p => p.GetUsageDocumentation()).Returns("Usage for provider1");
        mockPlugin2.Setup(p => p.GetUsageDocumentation()).Returns("Usage for provider2");
        
        manager.RegisterPlugin(mockPlugin1.Object);
        manager.RegisterPlugin(mockPlugin2.Object);

        // Act
        string usage = manager.GetProvidersUsageDocumentation();

        // Assert
        Assert.IsTrue(usage.Contains("provider1"));
        Assert.IsTrue(usage.Contains("Provider 1"));
        Assert.IsTrue(usage.Contains("provider2"));
        Assert.IsTrue(usage.Contains("Provider 2"));
        Assert.IsTrue(usage.Contains("Usage for provider1"));
        Assert.IsTrue(usage.Contains("Usage for provider2"));
        Assert.IsTrue(usage.Contains("--cert-provider"));
    }

    [TestMethod]
    public void DiscoverAndLoadPlugins_WithNullDirectory_ShouldNotThrow()
    {
        // Arrange
        CertificateProviderPluginManager manager = new CertificateProviderPluginManager();

        // Act & Assert - Should not throw
        manager.DiscoverAndLoadPlugins(null!);
        Assert.AreEqual(0, manager.Providers.Count);
    }

    [TestMethod]
    public void DiscoverAndLoadPlugins_WithNonExistentDirectory_ShouldNotThrow()
    {
        // Arrange
        CertificateProviderPluginManager manager = new CertificateProviderPluginManager();
        string nonExistentPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());

        // Act & Assert - Should not throw
        manager.DiscoverAndLoadPlugins(nonExistentPath);
        Assert.AreEqual(0, manager.Providers.Count);
    }

    [TestMethod]
    public void LoadPluginFromAssembly_WithNonExistentFile_ShouldThrowFileNotFoundException()
    {
        // Arrange
        CertificateProviderPluginManager manager = new CertificateProviderPluginManager();
        string nonExistentFile = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid()}.dll");

        // Act & Assert
        Assert.ThrowsException<FileNotFoundException>(() => manager.LoadPluginFromAssembly(nonExistentFile));
    }

    [TestMethod]
    public void LoadPluginFromAssembly_WithCurrentAssembly_ShouldLoadTestPlugin()
    {
        // Arrange
        CertificateProviderPluginManager manager = new CertificateProviderPluginManager();
        string assemblyPath = Assembly.GetExecutingAssembly().Location;

        // Act
        manager.LoadPluginFromAssembly(assemblyPath);

        // Assert
        // This test assembly contains TestCertificateProviderPlugin
        Assert.IsTrue(manager.Providers.Count > 0);
        Assert.IsTrue(manager.Providers.ContainsKey("test"));
    }

    [TestMethod]
    public void RegisterPlugin_WithNullProviderName_ShouldThrowArgumentException()
    {
        // Arrange
        CertificateProviderPluginManager manager = new CertificateProviderPluginManager();
        Mock<ICertificateProviderPlugin> mockPlugin = new Mock<ICertificateProviderPlugin>();
        mockPlugin.Setup(p => p.ProviderName).Returns<string?>(null);
        mockPlugin.Setup(p => p.Description).Returns("Test");

        // Act & Assert
        ArgumentException ex = Assert.ThrowsException<ArgumentException>(() => manager.RegisterPlugin(mockPlugin.Object));
        Assert.IsTrue(ex.Message.Contains("provider name"));
    }

    [TestMethod]
    public void RegisterPlugin_WithEmptyProviderName_ShouldRegisterWithEmptyKey()
    {
        // Arrange
        CertificateProviderPluginManager manager = new CertificateProviderPluginManager();
        Mock<ICertificateProviderPlugin> mockPlugin = new Mock<ICertificateProviderPlugin>();
        mockPlugin.Setup(p => p.ProviderName).Returns("");
        mockPlugin.Setup(p => p.Description).Returns("Test");
        mockPlugin.Setup(p => p.GetProviderOptions()).Returns(new Dictionary<string, string>());
        mockPlugin.Setup(p => p.GetUsageDocumentation()).Returns("Test");

        // Act
        manager.RegisterPlugin(mockPlugin.Object);

        // Assert - Empty string becomes empty string after ToLowerInvariant()
        Assert.AreEqual(1, manager.Providers.Count);
        Assert.IsTrue(manager.Providers.ContainsKey(""));
    }

    [TestMethod]
    public void DiscoverAndLoadPlugins_WithEmptyDirectory_ShouldNotThrow()
    {
        // Arrange
        Mock<IPluginLogger> mockLogger = new Mock<IPluginLogger>();
        CertificateProviderPluginManager manager = new CertificateProviderPluginManager(mockLogger.Object);

        // Act & Assert - Should not throw
        manager.DiscoverAndLoadPlugins("");
        Assert.AreEqual(0, manager.Providers.Count);
        mockLogger.Verify(l => l.LogVerbose(It.Is<string>(s => s.Contains("No plugins directory"))), Times.Once);
    }

    [TestMethod]
    public void DiscoverAndLoadPlugins_WithWhitespaceDirectory_ShouldNotThrow()
    {
        // Arrange
        Mock<IPluginLogger> mockLogger = new Mock<IPluginLogger>();
        CertificateProviderPluginManager manager = new CertificateProviderPluginManager(mockLogger.Object);

        // Act & Assert - Should not throw
        manager.DiscoverAndLoadPlugins("   ");
        Assert.AreEqual(0, manager.Providers.Count);
        mockLogger.Verify(l => l.LogVerbose(It.Is<string>(s => s.Contains("No plugins directory"))), Times.Once);
    }

    [TestMethod]
    public void DiscoverAndLoadPlugins_WithNonExistentDirectory_ShouldLogVerbose()
    {
        // Arrange
        Mock<IPluginLogger> mockLogger = new Mock<IPluginLogger>();
        CertificateProviderPluginManager manager = new CertificateProviderPluginManager(mockLogger.Object);
        string nonExistentPath = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid()}");

        // Act
        manager.DiscoverAndLoadPlugins(nonExistentPath);

        // Assert
        mockLogger.Verify(l => l.LogVerbose(It.Is<string>(s => s.Contains("does not exist"))), Times.Once);
    }

    [TestMethod]
    public void DiscoverAndLoadPlugins_WithValidDirectory_ShouldLogDiscovery()
    {
        // Arrange
        Mock<IPluginLogger> mockLogger = new Mock<IPluginLogger>();
        CertificateProviderPluginManager manager = new CertificateProviderPluginManager(mockLogger.Object);
        string tempDir = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid()}");
        Directory.CreateDirectory(tempDir);

        try
        {
            // Act
            manager.DiscoverAndLoadPlugins(tempDir);

            // Assert
            mockLogger.Verify(l => l.LogVerbose(It.Is<string>(s => s.Contains("Discovering certificate provider"))), Times.Once);
            mockLogger.Verify(l => l.LogVerbose(It.Is<string>(s => s.Contains("Found") && s.Contains("potential plugin"))), Times.Once);
            mockLogger.Verify(l => l.LogInformation(It.Is<string>(s => s.Contains("Loaded") && s.Contains("certificate provider plugin"))), Times.Once);
        }
        finally
        {
            // Cleanup
            if (Directory.Exists(tempDir))
            {
                Directory.Delete(tempDir, true);
            }
        }
    }

    [TestMethod]
    public void LoadPluginFromAssembly_WithValidAssembly_ShouldLogVerbose()
    {
        // Arrange
        Mock<IPluginLogger> mockLogger = new Mock<IPluginLogger>();
        CertificateProviderPluginManager manager = new CertificateProviderPluginManager(mockLogger.Object);
        string assemblyPath = Assembly.GetExecutingAssembly().Location;

        // Act
        manager.LoadPluginFromAssembly(assemblyPath);

        // Assert
        mockLogger.Verify(l => l.LogVerbose(It.Is<string>(s => s.Contains("Loading plugins from"))), Times.Once);
        mockLogger.Verify(l => l.LogVerbose(It.Is<string>(s => s.Contains("Registered certificate provider plugin"))), Times.AtLeastOnce);
    }

    // Helper method to create a mock plugin
    private static Mock<ICertificateProviderPlugin> CreateMockPlugin(string name, string description)
    {
        Mock<ICertificateProviderPlugin> mockPlugin = new Mock<ICertificateProviderPlugin>();
        mockPlugin.Setup(p => p.ProviderName).Returns(name);
        mockPlugin.Setup(p => p.Description).Returns(description);
        mockPlugin.Setup(p => p.GetProviderOptions()).Returns(new Dictionary<string, string>());
        mockPlugin.Setup(p => p.CanCreateProvider(It.IsAny<IConfiguration>())).Returns(true);
        mockPlugin.Setup(p => p.CreateProvider(It.IsAny<IConfiguration>(), It.IsAny<IPluginLogger>()))
            .Returns(new Mock<ICoseSigningKeyProvider>().Object);
        mockPlugin.Setup(p => p.GetUsageDocumentation()).Returns($"Usage for {name}");
        return mockPlugin;
    }
}

/// <summary>
/// Test certificate provider plugin for testing plugin discovery.
/// </summary>
public class TestCertificateProviderPlugin : ICertificateProviderPlugin
{
    public string ProviderName => "test";
    public string Description => "Test certificate provider";

    public IDictionary<string, string> GetProviderOptions()
    {
        return new Dictionary<string, string>
        {
            ["--test-param"] = "test-param"
        };
    }

    public bool CanCreateProvider(IConfiguration configuration)
    {
        return !string.IsNullOrWhiteSpace(configuration["test-param"]);
    }

    public ICoseSigningKeyProvider CreateProvider(IConfiguration configuration, IPluginLogger? logger = null)
    {
        throw new NotImplementedException("Test plugin does not actually create providers");
    }

    public string GetUsageDocumentation()
    {
        return "Test usage documentation";
    }
}
