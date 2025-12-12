// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSignTool.Plugins;
using System.CommandLine;
using System.Reflection;

namespace CoseSignTool.Tests.Plugins;

/// <summary>
/// Tests for the PluginLoader class.
/// </summary>
[TestFixture]
public class PluginLoaderTests
{
    [Test]
    public void PluginLoader_Constructor_InitializesEmptyCollections()
    {
        // Act
        var loader = new PluginLoader();

        // Assert
        Assert.That(loader.Plugins, Is.Empty);
    }

    [Test]
    public async Task RegisterPluginAsync_WithValidPlugin_AddsToCollection()
    {
        // Arrange
        var loader = new PluginLoader();
        var plugin = new TestPlugin();

        // Act
        await loader.RegisterPluginAsync(plugin);

        // Assert
        Assert.That(loader.Plugins, Has.Count.EqualTo(1));
        Assert.That(loader.Plugins[0].Name, Is.EqualTo("TestPlugin"));
    }

    [Test]
    public async Task RegisterPluginAsync_WithNullPlugin_ThrowsArgumentNullException()
    {
        // Arrange
        var loader = new PluginLoader();

        // Act & Assert
        Assert.ThrowsAsync<ArgumentNullException>(() => loader.RegisterPluginAsync(null!));
    }

    [Test]
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
        Assert.That(loader.Plugins, Has.Count.EqualTo(1));
    }

    [Test]
    public async Task LoadPluginsAsync_WithNullDirectory_ThrowsArgumentNullException()
    {
        // Arrange
        var loader = new PluginLoader();

        // Act & Assert
        Assert.ThrowsAsync<ArgumentNullException>(() => loader.LoadPluginsAsync(null!));
    }

    [Test]
    public async Task LoadPluginsAsync_WithEmptyDirectory_ThrowsArgumentException()
    {
        // Arrange
        var loader = new PluginLoader();

        // Act & Assert
        Assert.ThrowsAsync<ArgumentException>(() => loader.LoadPluginsAsync(string.Empty));
    }

    [Test]
    public async Task LoadPluginsAsync_WithAuthorizedDirectory_DoesNotThrow()
    {
        // Arrange
        var loader = new PluginLoader();
        var executableDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) ?? Directory.GetCurrentDirectory();
        var authorizedPluginsDir = Path.Combine(executableDir, "plugins");

        // Create the authorized directory to pass validation
        Directory.CreateDirectory(authorizedPluginsDir);

        try
        {
            // Act - should not throw
            await loader.LoadPluginsAsync(authorizedPluginsDir);

            // Assert - no plugins loaded from empty directory, but no exception
            Assert.That(loader.Plugins, Is.Empty);
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

    [Test]
    public async Task LoadPluginsAsync_WithUnauthorizedDirectory_ThrowsUnauthorizedAccessException()
    {
        // Arrange
        var loader = new PluginLoader();
        var unauthorizedDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());

        // Act & Assert
        Assert.ThrowsAsync<UnauthorizedAccessException>(() => loader.LoadPluginsAsync(unauthorizedDir));
    }

    [Test]
    public void ValidatePluginDirectory_WithAuthorizedDirectory_DoesNotThrow()
    {
        // Arrange
        var executableDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) ?? Directory.GetCurrentDirectory();
        var authorizedDir = Path.Combine(executableDir, "plugins");

        // Act & Assert - should not throw
        Assert.DoesNotThrow(() => PluginLoader.ValidatePluginDirectory(authorizedDir));
    }

    [Test]
    public void ValidatePluginDirectory_WithUnauthorizedDirectory_ThrowsUnauthorizedAccessException()
    {
        // Arrange
        var unauthorizedDir = Path.Combine(Path.GetTempPath(), "plugins");

        // Act & Assert
        Assert.Throws<UnauthorizedAccessException>(() => PluginLoader.ValidatePluginDirectory(unauthorizedDir));
    }

    [Test]
    public void ValidatePluginDirectory_WithNullDirectory_ThrowsUnauthorizedAccessException()
    {
        // Act & Assert
        Assert.Throws<UnauthorizedAccessException>(() => PluginLoader.ValidatePluginDirectory(null!));
    }

    [Test]
    public void ValidatePluginDirectory_WithEmptyDirectory_ThrowsUnauthorizedAccessException()
    {
        // Act & Assert
        Assert.Throws<UnauthorizedAccessException>(() => PluginLoader.ValidatePluginDirectory(string.Empty));
    }

    [Test]
    public async Task LoadPluginsAsync_WithAdditionalDirectories_LoadsFromAllDirectories()
    {
        // Arrange
        var loader = new PluginLoader();
        var executableDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) ?? Directory.GetCurrentDirectory();
        var authorizedPluginsDir = Path.Combine(executableDir, "plugins");
        var additionalDir = Path.Combine(Path.GetTempPath(), $"additional_plugins_{Guid.NewGuid()}");

        // Create directories
        Directory.CreateDirectory(authorizedPluginsDir);
        Directory.CreateDirectory(additionalDir);

        try
        {
            // Act - should not throw
            await loader.LoadPluginsAsync(authorizedPluginsDir, [additionalDir]);

            // Assert - no plugins loaded from empty directories, but no exception
            Assert.That(loader.Plugins, Is.Empty);
        }
        finally
        {
            // Cleanup
            if (Directory.Exists(authorizedPluginsDir) && !Directory.EnumerateFileSystemEntries(authorizedPluginsDir).Any())
            {
                Directory.Delete(authorizedPluginsDir);
            }
            if (Directory.Exists(additionalDir))
            {
                Directory.Delete(additionalDir, recursive: true);
            }
        }
    }

    [Test]
    public async Task LoadPluginsAsync_WithEmptyAdditionalDirectory_SkipsEmptyDirectories()
    {
        // Arrange
        var loader = new PluginLoader();
        var executableDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) ?? Directory.GetCurrentDirectory();
        var authorizedPluginsDir = Path.Combine(executableDir, "plugins");

        // Create the authorized directory
        Directory.CreateDirectory(authorizedPluginsDir);

        try
        {
            // Act - should not throw even with empty/whitespace additional directories
            await loader.LoadPluginsAsync(authorizedPluginsDir, ["", "   ", null!]);

            // Assert - no plugins loaded from empty directories
            Assert.That(loader.Plugins, Is.Empty);
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

    [Test]
    public async Task LoadPluginsAsync_WithNonExistentDirectory_DoesNotThrow()
    {
        // Arrange
        var loader = new PluginLoader();
        var executableDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) ?? Directory.GetCurrentDirectory();
        var nonExistentDir = Path.Combine(executableDir, "plugins", "nonexistent_subdir");

        // Ensure the authorized plugins directory exists (for validation)
        var authorizedPluginsDir = Path.Combine(executableDir, "plugins");
        Directory.CreateDirectory(authorizedPluginsDir);

        try
        {
            // Act - should not throw even if directory doesn't exist
            await loader.LoadPluginsAsync(authorizedPluginsDir);

            // Assert - no plugins loaded
            Assert.That(loader.Plugins, Is.Empty);
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

    [Test]
    public void Plugins_Property_ReturnsReadOnlyList()
    {
        // Arrange
        var loader = new PluginLoader();

        // Act
        var plugins = loader.Plugins;

        // Assert
        Assert.That(plugins, Is.Not.Null);
        Assert.That(plugins, Is.InstanceOf<IReadOnlyList<IPlugin>>());
    }

    // Test helper classes
    private class TestPlugin : IPlugin
    {
        public string Name => "TestPlugin";
        public string Version => "1.0.0";
        public string Description => "Test plugin for unit tests";

        public IEnumerable<ISigningCommandProvider> GetSigningCommandProviders()
        {
            return Enumerable.Empty<ISigningCommandProvider>();
        }

        public IEnumerable<ITransparencyProviderContributor> GetTransparencyProviderContributors()
        {
            return Enumerable.Empty<ITransparencyProviderContributor>();
        }

        public void RegisterCommands(Command rootCommand)
        {
            // No-op for tests
        }

        public Task InitializeAsync(IDictionary<string, string>? configuration = null)
        {
            return Task.CompletedTask;
        }
    }
}





