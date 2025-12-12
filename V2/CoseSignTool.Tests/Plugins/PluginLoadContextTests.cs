// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSignTool.Plugins;
using System.Reflection;

namespace CoseSignTool.Tests.Plugins;

/// <summary>
/// Tests for the PluginLoadContext class.
/// </summary>
public class PluginLoadContextTests
{
    [Fact]
    public void PluginLoadContext_Constructor_InitializesSuccessfully()
    {
        // Arrange
        var assemblyPath = Assembly.GetExecutingAssembly().Location;
        var pluginDir = Path.GetDirectoryName(assemblyPath)!;

        // Act
        var context = new PluginLoadContext(assemblyPath, pluginDir);

        // Assert
        context.Should().NotBeNull();
    }

    [Fact]
    public void PluginLoadContext_IsCollectible()
    {
        // Arrange
        var assemblyPath = Assembly.GetExecutingAssembly().Location;
        var pluginDir = Path.GetDirectoryName(assemblyPath)!;

        // Act
        var context = new PluginLoadContext(assemblyPath, pluginDir);

        // Assert
        context.IsCollectible.Should().BeTrue();
    }

    [Fact]
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
        loadedAssembly.Should().NotBeNull();
        loadedAssembly.GetName().Name.Should().Be("System.Runtime");
    }

    [Fact]
    public void PluginLoadContext_WithInvalidPath_ThrowsException()
    {
        // Arrange
        var invalidPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString(), "nonexistent.dll");
        var pluginDir = Path.GetTempPath();

        // Act
        var act = () => new PluginLoadContext(invalidPath, pluginDir);

        // Assert - AssemblyDependencyResolver constructor will throw InvalidOperationException for nonexistent files
        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*Dependency resolution failed*");
    }

    [Fact]
    public void PluginLoadContext_LoadFromAssemblyPath_LoadsAssembly()
    {
        // Arrange
        var assemblyPath = Assembly.GetExecutingAssembly().Location;
        var pluginDir = Path.GetDirectoryName(assemblyPath)!;
        var context = new PluginLoadContext(assemblyPath, pluginDir);

        // Act
        var loadedAssembly = context.LoadFromAssemblyPath(assemblyPath);

        // Assert
        loadedAssembly.Should().NotBeNull();
        loadedAssembly.Location.Should().Be(assemblyPath);
    }
}
