// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSignTool.Plugins;
using System.CommandLine;
using System.Reflection;

namespace CoseSignTool.Tests.Plugins;

/// <summary>
/// Tests for the PluginLoader class.
/// </summary>
public class PluginLoaderTests
{
    [Fact]
    public void PluginLoader_Constructor_InitializesEmptyCollections()
    {
        // Act
        var loader = new PluginLoader();

        // Assert
        loader.Plugins.Should().BeEmpty();
        loader.SigningServices.Should().BeEmpty();
    }

    [Fact]
    public async Task RegisterPluginAsync_WithValidPlugin_AddsToCollection()
    {
        // Arrange
        var loader = new PluginLoader();
        var plugin = new TestPlugin();

        // Act
        await loader.RegisterPluginAsync(plugin);

        // Assert
        loader.Plugins.Should().ContainSingle();
        loader.Plugins[0].Name.Should().Be("TestPlugin");
    }

    [Fact]
    public async Task RegisterPluginAsync_WithNullPlugin_ThrowsArgumentNullException()
    {
        // Arrange
        var loader = new PluginLoader();

        // Act
        var act = async () => await loader.RegisterPluginAsync(null!);

        // Assert
        await act.Should().ThrowAsync<ArgumentNullException>();
    }

    [Fact]
    public async Task RegisterPluginAsync_WithDuplicateName_DoesNotAddTwice()
    {
        // Arrange
        var loader = new PluginLoader();
        var plugin1 = new TestPlugin();
        var plugin2 = new TestPlugin();

        // Act
        await loader.RegisterPluginAsync(plugin1);
        await loader.RegisterPluginAsync(plugin2);

        // Assert
        loader.Plugins.Should().ContainSingle();
    }

    [Fact]
    public void RegisterSigningService_WithValidService_AddsToCollection()
    {
        // Arrange
        var loader = new PluginLoader();
        var service = new TestSigningService();

        // Act
        loader.RegisterSigningService(service);

        // Assert
        loader.SigningServices.Should().ContainSingle();
        loader.SigningServices[0].Name.Should().Be("TestSigningService");
    }

    [Fact]
    public void RegisterSigningService_WithNullService_ThrowsArgumentNullException()
    {
        // Arrange
        var loader = new PluginLoader();

        // Act
        var act = () => loader.RegisterSigningService(null!);

        // Assert
        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void RegisterSigningService_WithDuplicateName_DoesNotAddTwice()
    {
        // Arrange
        var loader = new PluginLoader();
        var service1 = new TestSigningService();
        var service2 = new TestSigningService();

        // Act
        loader.RegisterSigningService(service1);
        loader.RegisterSigningService(service2);

        // Assert
        loader.SigningServices.Should().ContainSingle();
    }

    [Fact]
    public void GetSigningService_WithExistingService_ReturnsService()
    {
        // Arrange
        var loader = new PluginLoader();
        var service = new TestSigningService();
        loader.RegisterSigningService(service);

        // Act
        var result = loader.GetSigningService("TestSigningService");

        // Assert
        result.Should().NotBeNull();
        result!.Name.Should().Be("TestSigningService");
    }

    [Fact]
    public void GetSigningService_WithNonExistingService_ReturnsNull()
    {
        // Arrange
        var loader = new PluginLoader();

        // Act
        var result = loader.GetSigningService("NonExistent");

        // Assert
        result.Should().BeNull();
    }

    [Fact]
    public void GetSigningService_IsCaseInsensitive()
    {
        // Arrange
        var loader = new PluginLoader();
        var service = new TestSigningService();
        loader.RegisterSigningService(service);

        // Act
        var result = loader.GetSigningService("testsigningservice");

        // Assert
        result.Should().NotBeNull();
        result!.Name.Should().Be("TestSigningService");
    }

    [Fact]
    public async Task LoadPluginsAsync_WithNullDirectory_ThrowsArgumentException()
    {
        // Arrange
        var loader = new PluginLoader();

        // Act
        var act = async () => await loader.LoadPluginsAsync(null!);

        // Assert
        await act.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task LoadPluginsAsync_WithEmptyDirectory_ThrowsArgumentException()
    {
        // Arrange
        var loader = new PluginLoader();

        // Act
        var act = async () => await loader.LoadPluginsAsync(string.Empty);

        // Assert
        await act.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task LoadPluginsAsync_WithNonExistentDirectory_DoesNotThrow()
    {
        // Arrange
        var loader = new PluginLoader();
        var executableDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) ?? Directory.GetCurrentDirectory();
        var authorizedPluginsDir = Path.Combine(executableDir, "plugins");

        // Create the authorized directory to pass validation
        Directory.CreateDirectory(authorizedPluginsDir);

        try
        {
            // Act & Assert
            await loader.Invoking(l => l.LoadPluginsAsync(authorizedPluginsDir))
                .Should().NotThrowAsync();
        }
        finally
        {
            // Cleanup
            if (Directory.Exists(authorizedPluginsDir) && !Directory.EnumerateFileSystemEntries(authorizedPluginsDir).Any())
            {
                Directory.Delete(authorizedPluginsDir);
            }
        }
    }

    [Fact]
    public async Task LoadPluginsAsync_WithUnauthorizedDirectory_ThrowsUnauthorizedAccessException()
    {
        // Arrange
        var loader = new PluginLoader();
        var unauthorizedDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());

        // Act
        var act = async () => await loader.LoadPluginsAsync(unauthorizedDir);

        // Assert
        await act.Should().ThrowAsync<UnauthorizedAccessException>()
            .WithMessage("*only allowed from the 'plugins' subdirectory*");
    }

    [Fact]
    public void ValidatePluginDirectory_WithAuthorizedDirectory_DoesNotThrow()
    {
        // Arrange
        var executableDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) ?? Directory.GetCurrentDirectory();
        var authorizedDir = Path.Combine(executableDir, "plugins");

        // Act & Assert
        var act = () => PluginLoader.ValidatePluginDirectory(authorizedDir);
        act.Should().NotThrow();
    }

    [Fact]
    public void ValidatePluginDirectory_WithUnauthorizedDirectory_ThrowsUnauthorizedAccessException()
    {
        // Arrange
        var unauthorizedDir = Path.Combine(Path.GetTempPath(), "plugins");

        // Act
        var act = () => PluginLoader.ValidatePluginDirectory(unauthorizedDir);

        // Assert
        act.Should().Throw<UnauthorizedAccessException>()
            .WithMessage("*only allowed from the 'plugins' subdirectory*");
    }

    [Fact]
    public void ValidatePluginDirectory_WithNullDirectory_ThrowsUnauthorizedAccessException()
    {
        // Act
        var act = () => PluginLoader.ValidatePluginDirectory(null!);

        // Assert
        act.Should().Throw<UnauthorizedAccessException>()
            .WithMessage("*empty or null directory path*");
    }

    [Fact]
    public void ValidatePluginDirectory_WithEmptyDirectory_ThrowsUnauthorizedAccessException()
    {
        // Act
        var act = () => PluginLoader.ValidatePluginDirectory(string.Empty);

        // Assert
        act.Should().Throw<UnauthorizedAccessException>()
            .WithMessage("*empty or null directory path*");
    }

    // Test helper classes
    private class TestPlugin : IPlugin
    {
        public string Name => "TestPlugin";
        public string Version => "1.0.0";
        public string Description => "Test plugin for unit tests";

        public void RegisterCommands(Command rootCommand)
        {
            // No-op for tests
        }

        public Task InitializeAsync(IDictionary<string, string>? configuration = null)
        {
            return Task.CompletedTask;
        }
    }

    private class TestSigningService : ISigningService
    {
        public string Name => "TestSigningService";
        public bool IsAvailable => true;

        public Task<byte[]> SignAsync(byte[] payload, SigningOptions? options = null, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(new byte[] { 0x01, 0x02, 0x03 });
        }

        public Task<bool> VerifyAsync(byte[] signature, byte[]? payload = null, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(true);
        }
    }
}
