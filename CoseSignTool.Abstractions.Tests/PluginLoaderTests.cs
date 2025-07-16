// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Abstractions.Tests;

/// <summary>
/// Tests for the PluginLoader class.
/// </summary>
[TestClass]
public class PluginLoaderTests
{
    private string _tempDirectory = string.Empty;
    private string _pluginsDirectory = string.Empty;

    /// <summary>
    /// Initialize test setup by creating a temporary directory.
    /// </summary>
    [TestInitialize]
    public void TestInitialize()
    {
        // Create a temporary directory for test plugins
        _tempDirectory = Path.Combine(Path.GetTempPath(), $"PluginTests_{Guid.NewGuid()}");
        Directory.CreateDirectory(_tempDirectory);
        
        // Create the plugins subdirectory for authorized testing
        _pluginsDirectory = Path.Combine(_tempDirectory, "plugins");
        Directory.CreateDirectory(_pluginsDirectory);
    }

    /// <summary>
    /// Clean up test resources by deleting temporary directory.
    /// </summary>
    [TestCleanup]
    public void TestCleanup()
    {
        // Clean up temporary directory
        if (Directory.Exists(_tempDirectory))
        {
            Directory.Delete(_tempDirectory, true);
        }
    }

    /// <summary>
    /// Tests that DiscoverPlugins returns empty list for empty plugins directory.
    /// </summary>
    [TestMethod]
    public void DiscoverPlugins_EmptyDirectory_ReturnsEmptyList()
    {
        // Arrange: Use the actual plugins directory relative to the test executable
        string executablePath = System.Reflection.Assembly.GetExecutingAssembly().Location;
        string executableDirectory = Path.GetDirectoryName(executablePath) ?? Directory.GetCurrentDirectory();
        string pluginsDirectory = Path.Combine(executableDirectory, "plugins");
        
        // Ensure the plugins directory exists but is empty
        if (Directory.Exists(pluginsDirectory))
        {
            Directory.Delete(pluginsDirectory, true);
        }
        Directory.CreateDirectory(pluginsDirectory);

        // Act
        var plugins = PluginLoader.DiscoverPlugins(pluginsDirectory);

        // Assert
        Assert.IsNotNull(plugins);
        Assert.AreEqual(0, plugins.Count());
        
        // Cleanup
        Directory.Delete(pluginsDirectory, true);
    }

    /// <summary>
    /// Tests that DiscoverPlugins returns empty list when no plugin files exist.
    /// </summary>
    [TestMethod]
    public void DiscoverPlugins_NoPluginFiles_ReturnsEmptyList()
    {
        // Arrange: Use the actual plugins directory relative to the test executable
        string executablePath = System.Reflection.Assembly.GetExecutingAssembly().Location;
        string executableDirectory = Path.GetDirectoryName(executablePath) ?? Directory.GetCurrentDirectory();
        string pluginsDirectory = Path.Combine(executableDirectory, "plugins");
        
        // Ensure the plugins directory exists but only has non-plugin files
        if (Directory.Exists(pluginsDirectory))
        {
            Directory.Delete(pluginsDirectory, true);
        }
        Directory.CreateDirectory(pluginsDirectory);
        
        var regularDll = Path.Combine(pluginsDirectory, "RegularLibrary.dll");
        File.WriteAllText(regularDll, "fake dll content");

        // Act
        var plugins = PluginLoader.DiscoverPlugins(pluginsDirectory);

        // Assert
        Assert.IsNotNull(plugins);
        Assert.AreEqual(0, plugins.Count());
        
        // Cleanup
        Directory.Delete(pluginsDirectory, true);
    }

    /// <summary>
    /// Tests that DiscoverPlugins returns empty list for non-existent directory.
    /// </summary>
    [TestMethod]
    public void DiscoverPlugins_NonExistentDirectory_ReturnsEmptyList()
    {
        // Arrange
        var nonExistentPath = Path.Combine(_tempDirectory, "DoesNotExist");

        // Act
        var plugins = PluginLoader.DiscoverPlugins(nonExistentPath);

        // Assert
        Assert.IsNotNull(plugins);
        Assert.AreEqual(0, plugins.Count());
    }

    /// <summary>
    /// Tests that DiscoverPlugins returns empty list for null directory.
    /// </summary>
    [TestMethod]
    public void DiscoverPlugins_NullDirectory_ReturnsEmptyList()
    {
        // Act
        var plugins = PluginLoader.DiscoverPlugins(null!);

        // Assert
        Assert.IsNotNull(plugins);
        Assert.AreEqual(0, plugins.Count());
    }

    /// <summary>
    /// Tests that DiscoverPlugins returns empty list for empty string directory.
    /// </summary>
    [TestMethod]
    public void DiscoverPlugins_EmptyStringDirectory_ReturnsEmptyList()
    {
        // Act
        var plugins = PluginLoader.DiscoverPlugins(string.Empty);

        // Assert
        Assert.IsNotNull(plugins);
        Assert.AreEqual(0, plugins.Count());
    }

    /// <summary>
    /// Tests that DiscoverPlugins skips non-plugin assemblies even with plugin names.
    /// </summary>
    [TestMethod]
    public void DiscoverPlugins_WithPluginNamedFiles_SkipsNonPluginAssemblies()
    {
        // Arrange: Use the actual plugins directory relative to the test executable
        string executablePath = System.Reflection.Assembly.GetExecutingAssembly().Location;
        string executableDirectory = Path.GetDirectoryName(executablePath) ?? Directory.GetCurrentDirectory();
        string pluginsDirectory = Path.Combine(executableDirectory, "plugins");
        
        // Ensure the plugins directory exists with fake plugin files
        if (Directory.Exists(pluginsDirectory))
        {
            Directory.Delete(pluginsDirectory, true);
        }
        Directory.CreateDirectory(pluginsDirectory);
        
        var pluginFile1 = Path.Combine(pluginsDirectory, "MyApp.Plugin.dll");
        var pluginFile2 = Path.Combine(pluginsDirectory, "SomeTool.Plugin.dll");
        var regularFile = Path.Combine(pluginsDirectory, "RegularLibrary.dll");
        
        File.WriteAllText(pluginFile1, "fake plugin dll content");
        File.WriteAllText(pluginFile2, "fake plugin dll content");
        File.WriteAllText(regularFile, "fake dll content");

        // Act - This will attempt to load assemblies and fail, but should handle gracefully
        var plugins = PluginLoader.DiscoverPlugins(pluginsDirectory);

        // Assert - Should return empty list since these are fake DLLs
        Assert.IsNotNull(plugins);
        Assert.AreEqual(0, plugins.Count());
        
        // Cleanup
        Directory.Delete(pluginsDirectory, true);
    }

    #region Plugin Directory Security Tests

    /// <summary>
    /// Tests that ValidatePluginDirectory allows the authorized plugins directory.
    /// </summary>
    [TestMethod]
    public void ValidatePluginDirectory_AuthorizedPluginsDirectory_DoesNotThrow()
    {
        // Arrange
        string executablePath = System.Reflection.Assembly.GetExecutingAssembly().Location;
        string executableDirectory = Path.GetDirectoryName(executablePath) ?? Directory.GetCurrentDirectory();
        string authorizedPluginsDirectory = Path.Combine(executableDirectory, "plugins");

        // Act & Assert - Should not throw
        PluginLoader.ValidatePluginDirectory(authorizedPluginsDirectory);
    }

    /// <summary>
    /// Tests that ValidatePluginDirectory throws UnauthorizedAccessException for unauthorized directories.
    /// </summary>
    [TestMethod]
    public void ValidatePluginDirectory_UnauthorizedDirectory_ThrowsUnauthorizedAccessException()
    {
        // Arrange
        string unauthorizedDirectory = _tempDirectory;

        // Act & Assert
        var exception = Assert.ThrowsException<UnauthorizedAccessException>(
            () => PluginLoader.ValidatePluginDirectory(unauthorizedDirectory));
        
        Assert.IsTrue(exception.Message.Contains("Plugin loading is only allowed from the 'plugins' subdirectory"));
        Assert.IsTrue(exception.Message.Contains(unauthorizedDirectory));
    }

    /// <summary>
    /// Tests that ValidatePluginDirectory rejects the executable directory itself.
    /// </summary>
    [TestMethod]
    public void ValidatePluginDirectory_ExecutableDirectory_ThrowsUnauthorizedAccessException()
    {
        // Arrange
        string executablePath = System.Reflection.Assembly.GetExecutingAssembly().Location;
        string executableDirectory = Path.GetDirectoryName(executablePath) ?? Directory.GetCurrentDirectory();

        // Act & Assert
        var exception = Assert.ThrowsException<UnauthorizedAccessException>(
            () => PluginLoader.ValidatePluginDirectory(executableDirectory));
        
        Assert.IsTrue(exception.Message.Contains("Plugin loading is only allowed from the 'plugins' subdirectory"));
    }

    /// <summary>
    /// Tests that ValidatePluginDirectory rejects parent directories.
    /// </summary>
    [TestMethod]
    public void ValidatePluginDirectory_ParentDirectory_ThrowsUnauthorizedAccessException()
    {
        // Arrange
        string executablePath = System.Reflection.Assembly.GetExecutingAssembly().Location;
        string executableDirectory = Path.GetDirectoryName(executablePath) ?? Directory.GetCurrentDirectory();
        string parentDirectory = Directory.GetParent(executableDirectory)?.FullName ?? executableDirectory;

        // Act & Assert
        var exception = Assert.ThrowsException<UnauthorizedAccessException>(
            () => PluginLoader.ValidatePluginDirectory(parentDirectory));
        
        Assert.IsTrue(exception.Message.Contains("Plugin loading is only allowed from the 'plugins' subdirectory"));
    }

    /// <summary>
    /// Tests that ValidatePluginDirectory rejects system directories.
    /// </summary>
    [TestMethod]
    public void ValidatePluginDirectory_SystemDirectory_ThrowsUnauthorizedAccessException()
    {
        // Arrange
        string systemDirectory = Environment.GetFolderPath(Environment.SpecialFolder.System);

        // Act & Assert
        var exception = Assert.ThrowsException<UnauthorizedAccessException>(
            () => PluginLoader.ValidatePluginDirectory(systemDirectory));
        
        Assert.IsTrue(exception.Message.Contains("Plugin loading is only allowed from the 'plugins' subdirectory"));
    }

    /// <summary>
    /// Tests that ValidatePluginDirectory handles trailing slashes correctly.
    /// </summary>
    [TestMethod]
    public void ValidatePluginDirectory_WithTrailingSlash_DoesNotThrow()
    {
        // Arrange
        string executablePath = System.Reflection.Assembly.GetExecutingAssembly().Location;
        string executableDirectory = Path.GetDirectoryName(executablePath) ?? Directory.GetCurrentDirectory();
        string authorizedPluginsDirectory = Path.Combine(executableDirectory, "plugins") + Path.DirectorySeparatorChar;

        // Act & Assert - Should not throw even with trailing slash
        PluginLoader.ValidatePluginDirectory(authorizedPluginsDirectory);
    }

    /// <summary>
    /// Tests that ValidatePluginDirectory rejects relative paths.
    /// </summary>
    [TestMethod]
    public void ValidatePluginDirectory_WithRelativePath_ThrowsUnauthorizedAccessException()
    {
        // Arrange
        string relativePath = "..\\..\\somedir";

        // Act & Assert
        var exception = Assert.ThrowsException<UnauthorizedAccessException>(
            () => PluginLoader.ValidatePluginDirectory(relativePath));
        
        Assert.IsTrue(exception.Message.Contains("Plugin loading is only allowed from the 'plugins' subdirectory"));
    }

    /// <summary>
    /// Tests that DiscoverPlugins throws UnauthorizedAccessException for unauthorized directories.
    /// </summary>
    [TestMethod]
    public void DiscoverPlugins_UnauthorizedDirectory_ThrowsUnauthorizedAccessException()
    {
        // Arrange
        string unauthorizedDirectory = _tempDirectory;
        var pluginFile = Path.Combine(unauthorizedDirectory, "Test.Plugin.dll");
        File.WriteAllText(pluginFile, "fake plugin dll content");

        // Act & Assert
        var exception = Assert.ThrowsException<UnauthorizedAccessException>(
            () => PluginLoader.DiscoverPlugins(unauthorizedDirectory).ToList());
        
        Assert.IsTrue(exception.Message.Contains("Plugin loading is only allowed from the 'plugins' subdirectory"));
    }

    /// <summary>
    /// Tests that DiscoverPlugins handles non-existent plugins directories gracefully.
    /// </summary>
    [TestMethod]
    public void DiscoverPlugins_NonExistentPluginsDirectory_DoesNotThrow()
    {
        // Arrange
        string executablePath = System.Reflection.Assembly.GetExecutingAssembly().Location;
        string executableDirectory = Path.GetDirectoryName(executablePath) ?? Directory.GetCurrentDirectory();
        string nonExistentPluginsDirectory = Path.Combine(executableDirectory, "plugins");

        // Act & Assert - Should not throw, just return empty
        var plugins = PluginLoader.DiscoverPlugins(nonExistentPluginsDirectory);
        Assert.IsNotNull(plugins);
        Assert.AreEqual(0, plugins.Count());
    }

    #endregion
}
