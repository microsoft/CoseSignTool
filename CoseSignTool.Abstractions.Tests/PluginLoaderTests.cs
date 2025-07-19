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
        _tempDirectory = Path.Join(Path.GetTempPath(), $"PluginTests_{Guid.NewGuid()}");
        Directory.CreateDirectory(_tempDirectory);
        
        // Create the plugins subdirectory for authorized testing
        _pluginsDirectory = Path.Join(_tempDirectory, "plugins");
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
        string pluginsDirectory = Path.Join(executableDirectory, "plugins");
        
        // Ensure the plugins directory exists but is empty
        if (Directory.Exists(pluginsDirectory))
        {
            Directory.Delete(pluginsDirectory, true);
        }
        Directory.CreateDirectory(pluginsDirectory);

        // Act
        IEnumerable<ICoseSignToolPlugin> plugins = PluginLoader.DiscoverPlugins(pluginsDirectory);

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
        string pluginsDirectory = Path.Join(executableDirectory, "plugins");
        
        // Ensure the plugins directory exists but only has non-plugin files
        if (Directory.Exists(pluginsDirectory))
        {
            Directory.Delete(pluginsDirectory, true);
        }
        Directory.CreateDirectory(pluginsDirectory);

        string regularDll = Path.Join(pluginsDirectory, "RegularLibrary.dll");
        File.WriteAllText(regularDll, "fake dll content");

        // Act
        IEnumerable<ICoseSignToolPlugin> plugins = PluginLoader.DiscoverPlugins(pluginsDirectory);

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
        string nonExistentPath = Path.Join(_tempDirectory, "DoesNotExist");

        // Act
        IEnumerable<ICoseSignToolPlugin> plugins = PluginLoader.DiscoverPlugins(nonExistentPath);

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
        IEnumerable<ICoseSignToolPlugin> plugins = PluginLoader.DiscoverPlugins(null!);

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
        IEnumerable<ICoseSignToolPlugin> plugins = PluginLoader.DiscoverPlugins(string.Empty);

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
        string pluginsDirectory = Path.Join(executableDirectory, "plugins");
        
        // Ensure the plugins directory exists with fake plugin files
        if (Directory.Exists(pluginsDirectory))
        {
            Directory.Delete(pluginsDirectory, true);
        }
        Directory.CreateDirectory(pluginsDirectory);

        string pluginFile1 = Path.Join(pluginsDirectory, "MyApp.Plugin.dll");
        string pluginFile2 = Path.Join(pluginsDirectory, "SomeTool.Plugin.dll");
        string regularFile = Path.Join(pluginsDirectory, "RegularLibrary.dll");
        
        File.WriteAllText(pluginFile1, "fake plugin dll content");
        File.WriteAllText(pluginFile2, "fake plugin dll content");
        File.WriteAllText(regularFile, "fake dll content");

        // Act - This will attempt to load assemblies and fail, but should handle gracefully
        IEnumerable<ICoseSignToolPlugin> plugins = PluginLoader.DiscoverPlugins(pluginsDirectory);

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
        string authorizedPluginsDirectory = Path.Join(executableDirectory, "plugins");

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
        UnauthorizedAccessException exception = Assert.ThrowsException<UnauthorizedAccessException>(
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
        UnauthorizedAccessException exception = Assert.ThrowsException<UnauthorizedAccessException>(
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
        UnauthorizedAccessException exception = Assert.ThrowsException<UnauthorizedAccessException>(
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
        
        // On some systems (like Linux), GetFolderPath might return empty, so use a fallback
        if (string.IsNullOrWhiteSpace(systemDirectory))
        {
            systemDirectory = "/usr/bin"; // Use a known system directory on Unix-like systems
        }

        // Act & Assert
        UnauthorizedAccessException exception = Assert.ThrowsException<UnauthorizedAccessException>(
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
        string authorizedPluginsDirectory = Path.Join(executableDirectory, "plugins") + Path.DirectorySeparatorChar;

        // Act & Assert - Should not throw even with trailing slash
        PluginLoader.ValidatePluginDirectory(authorizedPluginsDirectory);
    }

    /// <summary>
    /// Tests that ValidatePluginDirectory rejects relative paths.
    /// </summary>
    [TestMethod]
    public void ValidatePluginDirectory_WithRelativePath_ThrowsUnauthorizedAccessException()
    {
        // Arrange - Use cross-platform path separator
        string relativePath = ".." + Path.DirectorySeparatorChar + ".." + Path.DirectorySeparatorChar + "somedir";

        // Act & Assert
        UnauthorizedAccessException exception = Assert.ThrowsException<UnauthorizedAccessException>(
            () => PluginLoader.ValidatePluginDirectory(relativePath));
        
        Assert.IsTrue(exception.Message.Contains("Plugin loading is only allowed from the 'plugins' subdirectory"));
    }

    /// <summary>
    /// Tests that ValidatePluginDirectory rejects null directory paths.
    /// </summary>
    [TestMethod]
    public void ValidatePluginDirectory_NullDirectory_ThrowsUnauthorizedAccessException()
    {
        // Act & Assert
        UnauthorizedAccessException exception = Assert.ThrowsException<UnauthorizedAccessException>(
            () => PluginLoader.ValidatePluginDirectory(null!));
        
        Assert.IsTrue(exception.Message.Contains("Plugin loading is only allowed from the 'plugins' subdirectory"));
        Assert.IsTrue(exception.Message.Contains("empty or null directory path"));
    }

    /// <summary>
    /// Tests that ValidatePluginDirectory rejects empty directory paths.
    /// </summary>
    [TestMethod]
    public void ValidatePluginDirectory_EmptyDirectory_ThrowsUnauthorizedAccessException()
    {
        // Act & Assert
        UnauthorizedAccessException exception = Assert.ThrowsException<UnauthorizedAccessException>(
            () => PluginLoader.ValidatePluginDirectory(string.Empty));
        
        Assert.IsTrue(exception.Message.Contains("Plugin loading is only allowed from the 'plugins' subdirectory"));
        Assert.IsTrue(exception.Message.Contains("empty or null directory path"));
    }

    /// <summary>
    /// Tests that ValidatePluginDirectory rejects whitespace-only directory paths.
    /// </summary>
    [TestMethod]
    public void ValidatePluginDirectory_WhitespaceDirectory_ThrowsUnauthorizedAccessException()
    {
        // Act & Assert
        UnauthorizedAccessException exception = Assert.ThrowsException<UnauthorizedAccessException>(
            () => PluginLoader.ValidatePluginDirectory("   "));
        
        Assert.IsTrue(exception.Message.Contains("Plugin loading is only allowed from the 'plugins' subdirectory"));
        Assert.IsTrue(exception.Message.Contains("empty or null directory path"));
    }

    /// <summary>
    /// Tests that DiscoverPlugins throws UnauthorizedAccessException for unauthorized directories.
    /// </summary>
    [TestMethod]
    public void DiscoverPlugins_UnauthorizedDirectory_ThrowsUnauthorizedAccessException()
    {
        // Arrange
        string unauthorizedDirectory = _tempDirectory;
        string pluginFile = Path.Join(unauthorizedDirectory, "Test.Plugin.dll");
        File.WriteAllText(pluginFile, "fake plugin dll content");

        // Act & Assert
        UnauthorizedAccessException exception = Assert.ThrowsException<UnauthorizedAccessException>(
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
        string nonExistentPluginsDirectory = Path.Join(executableDirectory, "plugins");

        // Act & Assert - Should not throw, just return empty
        IEnumerable<ICoseSignToolPlugin> plugins = PluginLoader.DiscoverPlugins(nonExistentPluginsDirectory);
        Assert.IsNotNull(plugins);
        Assert.AreEqual(0, plugins.Count());
    }

    #endregion
}
