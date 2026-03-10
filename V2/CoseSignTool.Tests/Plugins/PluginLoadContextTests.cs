// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Tests.Plugins;

using System.Reflection;
using CoseSignTool.Plugins;

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
        var context = new PluginLoadContext(assemblyPath, pluginDir, TextWriter.Null);

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
        var context = new PluginLoadContext(assemblyPath, pluginDir, TextWriter.Null);

        // Assert
        Assert.That(context.IsCollectible, Is.True);
    }

    [Test]
    public void PluginLoadContext_LoadsSharedFrameworkAssembliesFromDefaultContext()
    {
        // Arrange
        var assemblyPath = Assembly.GetExecutingAssembly().Location;
        var pluginDir = Path.GetDirectoryName(assemblyPath)!;
        var context = new PluginLoadContext(assemblyPath, pluginDir, TextWriter.Null);

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
        Assert.Throws<InvalidOperationException>(() => new PluginLoadContext(invalidPath, pluginDir, TextWriter.Null));
    }

    [Test]
    public void PluginLoadContext_LoadFromAssemblyPath_LoadsAssembly()
    {
        // Arrange
        var assemblyPath = Assembly.GetExecutingAssembly().Location;
        var pluginDir = Path.GetDirectoryName(assemblyPath)!;
        var context = new PluginLoadContext(assemblyPath, pluginDir, TextWriter.Null);

        // Act
        var loadedAssembly = context.LoadFromAssemblyPath(assemblyPath);

        // Assert
        Assert.That(loadedAssembly, Is.Not.Null);
        Assert.That(loadedAssembly.Location, Is.EqualTo(assemblyPath));
    }

    [Test]
    public void PluginLoadContext_LoadNonExistentAssembly_ReturnsNullFromLoad()
    {
        // Arrange
        var assemblyPath = Assembly.GetExecutingAssembly().Location;
        var pluginDir = Path.GetDirectoryName(assemblyPath)!;
        var context = new PluginLoadContext(assemblyPath, pluginDir, TextWriter.Null);

        // Act - Try to load a non-existent assembly, this should not throw but return null
        var nonExistentAssemblyName = new AssemblyName("NonExistent.Assembly.That.Does.Not.Exist");

        // Assert - Should throw FileNotFoundException when assembly can't be found
        Assert.Throws<FileNotFoundException>(() => context.LoadFromAssemblyName(nonExistentAssemblyName));
    }

    [Test]
    public void PluginLoadContext_LoadsAssemblyFromPluginDirectory()
    {
        // Arrange
        var assemblyPath = Assembly.GetExecutingAssembly().Location;
        var pluginDir = Path.GetDirectoryName(assemblyPath)!;
        var context = new PluginLoadContext(assemblyPath, pluginDir, TextWriter.Null);

        // Act - Load an assembly that exists in the plugin directory
        // Use NUnit as it should be in the output directory
        var nunitAssemblyName = new AssemblyName("nunit.framework");
        var loadedAssembly = context.LoadFromAssemblyName(nunitAssemblyName);

        // Assert
        Assert.That(loadedAssembly, Is.Not.Null);
        Assert.That(loadedAssembly.GetName().Name, Is.EqualTo("nunit.framework"));
    }

    [Test]
    public void PluginLoadContext_LoadAssemblyFromPath_UsesOnResolving()
    {
        // Arrange
        var testAssemblyPath = Assembly.GetExecutingAssembly().Location;
        var pluginDir = Path.GetDirectoryName(testAssemblyPath)!;
        var context = new PluginLoadContext(testAssemblyPath, pluginDir, TextWriter.Null);

        // Act - Try to load Moq which should be in the test output directory
        var moqAssemblyName = new AssemblyName("Moq");
        var loadedAssembly = context.LoadFromAssemblyName(moqAssemblyName);

        // Assert - Should load via OnResolving fallback
        Assert.That(loadedAssembly, Is.Not.Null);
        Assert.That(loadedAssembly.GetName().Name, Is.EqualTo("Moq"));
    }

    [Test]
    public void PluginLoadContext_LoadUnmanagedDll_WithNonExistentFile_ReturnsZero()
    {
        // Arrange
        var assemblyPath = Assembly.GetExecutingAssembly().Location;
        var pluginDir = Path.GetDirectoryName(assemblyPath)!;
        var context = new PluginLoadContext(assemblyPath, pluginDir, TextWriter.Null);

        // Use reflection to test the protected LoadUnmanagedDll method
        var loadUnmanagedDllMethod = typeof(PluginLoadContext).GetMethod(
            "LoadUnmanagedDll",
            BindingFlags.NonPublic | BindingFlags.Instance);

        Assert.That(loadUnmanagedDllMethod, Is.Not.Null, "Method LoadUnmanagedDll should exist");

        // Act - Try to load a non-existent native library
        var result = loadUnmanagedDllMethod!.Invoke(context, new object[] { "nonexistent_native_library" });

        // Assert - Should return IntPtr.Zero
        Assert.That(result, Is.EqualTo(IntPtr.Zero));
    }

    [Test]
    public void PluginLoadContext_WhenPluginDirectoryContainsInvalidDll_OnResolvingSwallowsAndLoadFails()
    {
        var pluginDir = Path.Combine(Path.GetTempPath(), $"plugin_load_ctx_{Guid.NewGuid():N}");
        Directory.CreateDirectory(pluginDir);

        var pluginPath = Assembly.GetExecutingAssembly().Location;
        var context = new PluginLoadContext(pluginPath, pluginDir, TextWriter.Null);

        var invalidAssemblyName = new AssemblyName("Bad.Assembly");
        var invalidDllPath = Path.Combine(pluginDir, "Bad.Assembly.dll");
        File.WriteAllText(invalidDllPath, "this is not a real assembly");

        try
        {
            Assert.That(
                () => context.LoadFromAssemblyName(invalidAssemblyName),
                Throws.TypeOf<FileNotFoundException>()
                    .Or.TypeOf<FileLoadException>()
                    .Or.TypeOf<BadImageFormatException>());
        }
        finally
        {
            try
            {
                context.Unload();
            }
            catch
            {
                // best-effort cleanup
            }

            if (Directory.Exists(pluginDir))
            {
                Directory.Delete(pluginDir, recursive: true);
            }
        }
    }

    [Test]
    public void PluginLoadContext_OnResolving_WhenDllIsInvalid_WritesWarningAndReturnsNull()
    {
        var pluginDir = Path.Combine(Path.GetTempPath(), $"plugin_load_ctx_{Guid.NewGuid():N}");
        Directory.CreateDirectory(pluginDir);

        var pluginPath = Assembly.GetExecutingAssembly().Location;
        var errorWriter = new StringWriter();
        var context = new PluginLoadContext(pluginPath, pluginDir, errorWriter);

        var invalidDllPath = Path.Combine(pluginDir, "Bad.Assembly.dll");
        File.WriteAllText(invalidDllPath, "this is not a real assembly");

        var onResolving = typeof(PluginLoadContext).GetMethod(
            "OnResolving",
            BindingFlags.NonPublic | BindingFlags.Instance);

        Assert.That(onResolving, Is.Not.Null);

        try
        {
            var result = (Assembly?)onResolving!.Invoke(
                context,
                new object[] { context, new AssemblyName("Bad.Assembly") });

            Assert.That(result, Is.Null);

            var stderr = errorWriter.ToString();
            Assert.That(stderr, Does.Contain("Warning: Failed to load assembly"));
        }
        finally
        {
            try
            {
                context.Unload();
            }
            catch
            {
                // best-effort cleanup
            }

            if (Directory.Exists(pluginDir))
            {
                Directory.Delete(pluginDir, recursive: true);
            }
        }
    }

    [Test]
    public void PluginLoadContext_OnResolving_WhenDllExists_LoadsFromPluginDirectory()
    {
        var pluginDir = Path.Combine(Path.GetTempPath(), $"plugin_load_ctx_{Guid.NewGuid():N}");
        Directory.CreateDirectory(pluginDir);

        var pluginPath = Assembly.GetExecutingAssembly().Location;
        var context = new PluginLoadContext(pluginPath, pluginDir, TextWriter.Null);

        // Copy an existing managed dependency into the plugin directory under its expected name.
        var commandLineAssembly = typeof(System.CommandLine.RootCommand).Assembly;
        var expectedDllPath = Path.Combine(pluginDir, "System.CommandLine.dll");
        File.Copy(commandLineAssembly.Location, expectedDllPath, overwrite: true);

        var onResolving = typeof(PluginLoadContext).GetMethod(
            "OnResolving",
            BindingFlags.NonPublic | BindingFlags.Instance);

        Assert.That(onResolving, Is.Not.Null);

        try
        {
            var result = (Assembly?)onResolving!.Invoke(
                context,
                new object[] { context, new AssemblyName("System.CommandLine") });

            Assert.That(result, Is.Not.Null);
            Assert.That(result!.GetName().Name, Is.EqualTo("System.CommandLine"));
        }
        finally
        {
            try
            {
                context.Unload();
            }
            catch
            {
                // best-effort cleanup
            }

            // Ensure the collectible ALC is fully unloaded so the copied DLL isn't locked.
            GC.Collect();
            GC.WaitForPendingFinalizers();
            GC.Collect();

            if (Directory.Exists(pluginDir))
            {
                try
                {
                    Directory.Delete(pluginDir, recursive: true);
                }
                catch
                {
                    // best-effort cleanup
                }
            }
        }
    }

    [Test]
    public void PluginLoadContext_OnResolving_WhenResolverProvidesPath_LoadsAssemblyFromResolverPath()
    {
        var pluginDir = Path.Combine(Path.GetTempPath(), $"plugin_load_ctx_{Guid.NewGuid():N}");
        Directory.CreateDirectory(pluginDir);

        var pluginPath = Assembly.GetExecutingAssembly().Location;
        var context = new PluginLoadContext(pluginPath, pluginDir, TextWriter.Null);

        var onResolving = typeof(PluginLoadContext).GetMethod(
            "OnResolving",
            BindingFlags.NonPublic | BindingFlags.Instance);

        Assert.That(onResolving, Is.Not.Null);

        try
        {
            // Ensure we hit the resolver path (not plugin directory): Moq is a managed dependency of this test assembly.
            var result = (Assembly?)onResolving!.Invoke(
                context,
                new object[] { context, new AssemblyName("Moq") });

            Assert.That(result, Is.Not.Null);
            Assert.That(result!.GetName().Name, Is.EqualTo("Moq"));
        }
        finally
        {
            try
            {
                context.Unload();
            }
            catch
            {
                // best-effort cleanup
            }

            GC.Collect();
            GC.WaitForPendingFinalizers();
            GC.Collect();

            if (Directory.Exists(pluginDir))
            {
                try
                {
                    Directory.Delete(pluginDir, recursive: true);
                }
                catch
                {
                    // best-effort cleanup
                }
            }
        }
    }
}
