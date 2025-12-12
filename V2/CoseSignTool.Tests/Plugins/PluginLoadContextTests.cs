// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Reflection;
using CoseSignTool.Plugins;

namespace CoseSignTool.Tests.Plugins;

/// <summary>
/// Tests for the PluginLoadContext class.
/// </summary>
[TestFixture]
public class PluginLoadContextTests
{
    [Test]
    public void PluginLoadContext_Constructor_InitializesSuccessfully()
    {
        // Arrange
        var assemblyPath = Assembly.GetExecutingAssembly().Location;
        var pluginDir = Path.GetDirectoryName(assemblyPath)!;

        // Act
        var context = new PluginLoadContext(assemblyPath, pluginDir);

        // Assert
        Assert.That(context, Is.Not.Null);
    }

    [Test]
    public void PluginLoadContext_IsCollectible()
    {
        // Arrange
        var assemblyPath = Assembly.GetExecutingAssembly().Location;
        var pluginDir = Path.GetDirectoryName(assemblyPath)!;

        // Act
        var context = new PluginLoadContext(assemblyPath, pluginDir);

        // Assert
        Assert.That(context.IsCollectible, Is.True);
    }

    [Test]
    public void PluginLoadContext_LoadsSharedFrameworkAssembliesFromDefaultContext()
    {
        // Arrange
        var assemblyPath = Assembly.GetExecutingAssembly().Location;
        var pluginDir = Path.GetDirectoryName(assemblyPath)!;
        var context = new PluginLoadContext(assemblyPath, pluginDir);

        // Act - Try to load a System assembly
        var systemAssemblyName = new AssemblyName("System.Runtime");
        var loadedAssembly = context.LoadFromAssemblyName(systemAssemblyName);

        // Assert - Should load successfully (from default context)
        Assert.That(loadedAssembly, Is.Not.Null);
        Assert.That(loadedAssembly.GetName().Name, Is.EqualTo("System.Runtime"));
    }

    [Test]
    public void PluginLoadContext_WithInvalidPath_ThrowsException()
    {
        // Arrange
        var invalidPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString(), "nonexistent.dll");
        var pluginDir = Path.GetTempPath();

        // Act & Assert - AssemblyDependencyResolver constructor will throw InvalidOperationException for nonexistent files
        Assert.Throws<InvalidOperationException>(() => new PluginLoadContext(invalidPath, pluginDir));
    }

    [Test]
    public void PluginLoadContext_LoadFromAssemblyPath_LoadsAssembly()
    {
        // Arrange
        var assemblyPath = Assembly.GetExecutingAssembly().Location;
        var pluginDir = Path.GetDirectoryName(assemblyPath)!;
        var context = new PluginLoadContext(assemblyPath, pluginDir);

        // Act
        var loadedAssembly = context.LoadFromAssemblyPath(assemblyPath);

        // Assert
        Assert.That(loadedAssembly, Is.Not.Null);
        Assert.That(loadedAssembly.Location, Is.EqualTo(assemblyPath));
    }
}