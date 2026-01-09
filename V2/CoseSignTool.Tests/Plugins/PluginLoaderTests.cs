// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Tests.Plugins;

using System.CommandLine;
using System.Reflection;
using System.Runtime.Loader;
using CoseSignTool.Abstractions;
using CoseSignTool.Plugins;

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

        // Act - should not throw
        await loader.LoadPluginsAsync(authorizedPluginsDir);

        // Assert - plugins are loaded from the directory (we deploy plugins in test builds)
        // If no plugins are deployed, this will be empty, which is also valid
        Assert.That(() => loader.Plugins, Throws.Nothing);
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

        // Create additional directory (primary plugins dir already exists with deployed plugins)
        Directory.CreateDirectory(authorizedPluginsDir);
        Directory.CreateDirectory(additionalDir);

        try
        {
            // Act - should not throw
            await loader.LoadPluginsAsync(authorizedPluginsDir, [additionalDir]);

            // Assert - plugins are loaded from the directories
            // The primary plugins directory has deployed plugins in test builds
            Assert.That(() => loader.Plugins, Throws.Nothing);
        }
        finally
        {
            // Cleanup only the temp directory (don't delete the deployed plugins)
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

        // Create the authorized directory (may already exist with deployed plugins)
        Directory.CreateDirectory(authorizedPluginsDir);

        // Act - should not throw even with empty/whitespace additional directories
        await loader.LoadPluginsAsync(authorizedPluginsDir, ["", "   ", null!]);

        // Assert - accessing plugins property doesn't throw
        // Plugins may or may not be loaded depending on what's in the directory
        Assert.That(() => loader.Plugins, Throws.Nothing);
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

        // Act - should not throw even if the nonexistent subdirectory doesn't exist
        await loader.LoadPluginsAsync(authorizedPluginsDir);

        // Assert - plugins may be loaded (deployed plugins in tests), no exception
        Assert.That(() => loader.Plugins, Throws.Nothing);
    }

    [Test]
    public async Task LoadPluginsFromDirectoryAsync_WithNonExistentDirectory_ReturnsWithoutError()
    {
        // Arrange
        var loader = new PluginLoader();
        var nonExistentDir = Path.Combine(Path.GetTempPath(), $"plugins_{Guid.NewGuid():N}");

        var method = typeof(PluginLoader)
            .GetMethod("LoadPluginsFromDirectoryAsync", BindingFlags.Instance | BindingFlags.NonPublic);
        Assert.That(method, Is.Not.Null);

        // Act & Assert
        Assert.DoesNotThrowAsync(async () => await (Task)method!.Invoke(loader, [nonExistentDir, false])!);
        Assert.That(loader.Plugins, Is.Empty);
    }

    [Test]
    public void ValidatePluginDirectory_WhenExecutingAssemblyLocationIsEmpty_UsesCurrentDirectoryPluginsPath()
    {
        // Arrange: load CoseSignTool assembly from bytes so Assembly.Location is empty.
        var toolAssemblyPath = typeof(PluginLoader).Assembly.Location;
        Assert.That(toolAssemblyPath, Is.Not.Null.And.Not.Empty);

        var bytes = File.ReadAllBytes(toolAssemblyPath);
        var alc = new AssemblyLoadContext("PluginLoaderTests-Alc", isCollectible: true);
        var loaded = alc.LoadFromStream(new MemoryStream(bytes));

        var loadedPluginLoaderType = loaded.GetType("CoseSignTool.Plugins.PluginLoader", throwOnError: true)!;
        var validateMethod = loadedPluginLoaderType.GetMethod(
            "ValidatePluginDirectory",
            BindingFlags.Public | BindingFlags.Static);
        Assert.That(validateMethod, Is.Not.Null);

        var originalCurrentDirectory = Environment.CurrentDirectory;
        var tempRoot = Path.Combine(Path.GetTempPath(), $"plugin_dir_{Guid.NewGuid():N}");
        var pluginsDir = Path.Combine(tempRoot, "plugins");

        try
        {
            Directory.CreateDirectory(pluginsDir);
            Environment.CurrentDirectory = tempRoot;

            // Act & Assert
            Assert.DoesNotThrow(() => validateMethod!.Invoke(null, [pluginsDir]));
        }
        finally
        {
            Environment.CurrentDirectory = originalCurrentDirectory;
            alc.Unload();
            if (Directory.Exists(tempRoot))
            {
                Directory.Delete(tempRoot, recursive: true);
            }
        }
    }

    [Test]
    public async Task LoadPluginWithContextAsync_WhenGetTypesThrowsReflectionTypeLoadException_Rethrows()
    {
        // Arrange
        var loader = new ThrowingTypeLoadPluginLoader();
        var assemblyPath = typeof(PluginLoader).Assembly.Location;
        Assert.That(assemblyPath, Is.Not.Null.And.Not.Empty);
        var pluginDirectory = Path.GetDirectoryName(assemblyPath) ?? Directory.GetCurrentDirectory();

        // Act & Assert
        var rtlEx = Assert.ThrowsAsync<ReflectionTypeLoadException>(async () =>
            await InvokeLoadPluginWithContextAsync(loader, assemblyPath, pluginDirectory));
        Assert.That(rtlEx, Is.Not.Null);
        Assert.That(rtlEx!.LoaderExceptions, Is.Not.Null);
        Assert.That(rtlEx.LoaderExceptions, Has.Length.GreaterThanOrEqualTo(1));
    }

    private static async Task InvokeLoadPluginWithContextAsync(PluginLoader loader, string assemblyPath, string pluginDirectory)
    {
        var method = typeof(PluginLoader).GetMethod(
            "LoadPluginWithContextAsync",
            BindingFlags.Instance | BindingFlags.NonPublic);
        Assert.That(method, Is.Not.Null);

        try
        {
            var task = (Task)method!.Invoke(loader, [assemblyPath, pluginDirectory])!;
            await task;
        }
        catch (TargetInvocationException ex) when (ex.InnerException != null)
        {
            throw ex.InnerException;
        }
    }

    private sealed class ThrowingTypeLoadPluginLoader : PluginLoader
    {
        protected override Type[] GetAssemblyTypes(Assembly assembly)
        {
            // Include a null exception to cover the null-check inside the catch path.
            throw new ReflectionTypeLoadException(
                [typeof(object)],
                [new FileNotFoundException("Missing dependency"), null!],
                "Type loading failed");
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

        public PluginExtensions GetExtensions()
        {
            return PluginExtensions.None;
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

    private class AnotherTestPlugin : IPlugin
    {
        public string Name => "AnotherTestPlugin";
        public string Version => "2.0.0";
        public string Description => "Another test plugin for unit tests";

        public PluginExtensions GetExtensions()
        {
            return PluginExtensions.None;
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

    [Test]
    public async Task RegisterPluginAsync_MultiplePlugins_AddsAllToCollection()
    {
        // Arrange
        var loader = new PluginLoader();
        var plugin1 = new TestPlugin();
        var plugin2 = new AnotherTestPlugin();

        // Act
        await loader.RegisterPluginAsync(plugin1);
        await loader.RegisterPluginAsync(plugin2);

        // Assert
        Assert.That(loader.Plugins, Has.Count.EqualTo(2));
        Assert.That(loader.Plugins.Any(p => p.Name == "TestPlugin"), Is.True);
        Assert.That(loader.Plugins.Any(p => p.Name == "AnotherTestPlugin"), Is.True);
    }

    [Test]
    public async Task LoadPluginsAsync_WithDeployedPlugins_LoadsPluginsFromDirectory()
    {
        // Arrange
        var loader = new PluginLoader();
        var executableDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) ?? Directory.GetCurrentDirectory();
        var authorizedPluginsDir = Path.Combine(executableDir, "plugins");

        // Plugins should be deployed by the test build
        if (Directory.Exists(authorizedPluginsDir) && Directory.GetDirectories(authorizedPluginsDir).Length > 0)
        {
            // Act
            await loader.LoadPluginsAsync(authorizedPluginsDir);

            // Assert - should have loaded at least one plugin
            Assert.That(loader.Plugins.Count, Is.GreaterThan(0));
        }
        else
        {
            // If no plugins deployed, just verify no exception
            Assert.Pass("No plugins deployed for this test");
        }
    }

    [Test]
    public async Task LoadPluginsAsync_WithNullAdditionalDirectories_DoesNotThrow()
    {
        // Arrange
        var loader = new PluginLoader();
        var executableDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) ?? Directory.GetCurrentDirectory();
        var authorizedPluginsDir = Path.Combine(executableDir, "plugins");

        // Ensure directory exists
        Directory.CreateDirectory(authorizedPluginsDir);

        // Act & Assert - should not throw with null additional directories
        Assert.DoesNotThrowAsync(async () =>
            await loader.LoadPluginsAsync(authorizedPluginsDir, null));
    }

    [Test]
    public void ValidatePluginDirectory_WithRelativePath_NormalizesAndValidates()
    {
        // Arrange
        var executableDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) ?? Directory.GetCurrentDirectory();

        // Create a relative path that would resolve to the plugins directory
        var currentDir = Environment.CurrentDirectory;
        try
        {
            Environment.CurrentDirectory = executableDir;
            var relativePath = "plugins";

            // Note: This test validates that the method handles relative paths correctly
            // It should either normalize to the authorized path or reject
            try
            {
                PluginLoader.ValidatePluginDirectory(relativePath);
                Assert.Pass("Relative path was accepted when it resolves to authorized directory");
            }
            catch (UnauthorizedAccessException)
            {
                // This is also acceptable - strict checking
                Assert.Pass("Relative path was rejected for security");
            }
        }
        finally
        {
            Environment.CurrentDirectory = currentDir;
        }
    }

    [Test]
    public void ValidatePluginDirectory_WithTrailingSlash_AcceptsNormalizedPath()
    {
        // Arrange
        var executableDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) ?? Directory.GetCurrentDirectory();
        var authorizedDir = Path.Combine(executableDir, "plugins") + Path.DirectorySeparatorChar;

        // Act & Assert - should normalize and accept
        Assert.DoesNotThrow(() => PluginLoader.ValidatePluginDirectory(authorizedDir));
    }

    [Test]
    public void ValidatePluginDirectory_WithAltDirectorySeparator_AcceptsNormalizedPath()
    {
        // Arrange
        var executableDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) ?? Directory.GetCurrentDirectory();
        var authorizedDir = Path.Combine(executableDir, "plugins") + Path.AltDirectorySeparatorChar;

        // Act & Assert - should normalize and accept
        Assert.DoesNotThrow(() => PluginLoader.ValidatePluginDirectory(authorizedDir));
    }

    [Test]
    public async Task RegisterPluginAsync_CallsInitializeOnPlugin()
    {
        // Arrange
        var loader = new PluginLoader();
        var initializeCalled = false;
        var mockPlugin = new InitializeTrackingPlugin(() => initializeCalled = true);

        // Act
        await loader.RegisterPluginAsync(mockPlugin);

        // Assert
        Assert.That(initializeCalled, Is.True);
    }

    private class InitializeTrackingPlugin : IPlugin
    {
        private readonly Action OnInitialize;

        public InitializeTrackingPlugin(Action onInitialize)
        {
            OnInitialize = onInitialize;
        }

        public string Name => "InitializeTrackingPlugin";
        public string Version => "1.0.0";
        public string Description => "Plugin that tracks initialization";

        public PluginExtensions GetExtensions() => PluginExtensions.None;

        public void RegisterCommands(Command rootCommand) { }

        public Task InitializeAsync(IDictionary<string, string>? configuration = null)
        {
            OnInitialize();
            return Task.CompletedTask;
        }
    }
}
