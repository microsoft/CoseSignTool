// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Reflection;

namespace CoseSignTool.Abstractions.Tests;

/// <summary>
/// Basic functionality tests for PluginLoadContext.
/// </summary>
[TestClass]
public class PluginLoadContextBasicTests
{
    private string _tempDirectory = string.Empty;
    private string _pluginDirectory = string.Empty;

    /// <summary>
    /// Initialize test setup by creating a temporary directory.
    /// </summary>
    [TestInitialize]
    public void TestInitialize()
    {
        _tempDirectory = Path.Join(Path.GetTempPath(), $"PluginLoadContext_{Guid.NewGuid()}");
        Directory.CreateDirectory(_tempDirectory);
        
        _pluginDirectory = Path.Join(_tempDirectory, "TestPlugin");
        Directory.CreateDirectory(_pluginDirectory);
    }

    /// <summary>
    /// Clean up test resources.
    /// </summary>
    [TestCleanup]
    public void TestCleanup()
    {
        if (Directory.Exists(_tempDirectory))
        {
            try
            {
                Directory.Delete(_tempDirectory, true);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Warning: Failed to clean up test directory: {ex.Message}");
            }
        }
    }

    /// <summary>
    /// Tests basic construction of PluginLoadContext.
    /// </summary>
    [TestMethod]
    public void Constructor_WithValidPaths_ShouldCreateInstance()
    {
        // Arrange
        string pluginPath = Path.Join(_pluginDirectory, "Main.dll");
        File.WriteAllText(pluginPath, "main plugin content");
        
        // Act
        PluginLoadContext context = new PluginLoadContext(pluginPath, _pluginDirectory);
        
        // Assert
        Assert.IsNotNull(context);
        Assert.IsTrue(context.IsCollectible);
        
        // Cleanup
        context.Unload();
    }

    /// <summary>
    /// Tests that Load method returns null for non-existent assemblies.
    /// </summary>
    [TestMethod]
    public void Load_WithNonExistentAssembly_ShouldReturnNull()
    {
        // Arrange
        string pluginPath = Path.Join(_pluginDirectory, "Main.dll");
        File.WriteAllText(pluginPath, "main plugin content");
        
        PluginLoadContext context = new PluginLoadContext(pluginPath, _pluginDirectory);
        
        try
        {
            // Act
            AssemblyName nonExistentAssembly = new AssemblyName("NonExistentAssembly");
            Assembly? result = InvokeLoad(context, nonExistentAssembly);
            
            // Assert
            Assert.IsNull(result);
        }
        finally
        {
            context.Unload();
        }
    }

    /// <summary>
    /// Tests that shared framework assemblies return null to allow default loading.
    /// </summary>
    [TestMethod]
    public void Load_WithSharedFrameworkAssembly_ShouldReturnNull()
    {
        // Arrange
        string pluginPath = Path.Join(_pluginDirectory, "Main.dll");
        File.WriteAllText(pluginPath, "main plugin content");
        
        PluginLoadContext context = new PluginLoadContext(pluginPath, _pluginDirectory);
        
        try
        {
            // Test various shared framework assemblies
            string[] sharedAssemblies = {
                "System.Collections",
                "Microsoft.Extensions.Logging",
                "CoseSignTool.Abstractions",
                "CoseHandler",
                "System"
            };

            foreach (string assemblyName in sharedAssemblies)
            {
                // Act
                AssemblyName testAssembly = new AssemblyName(assemblyName);
                Assembly? result = InvokeLoad(context, testAssembly);
                
                // Assert
                Assert.IsNull(result, $"Shared assembly '{assemblyName}' should return null");
            }
        }
        finally
        {
            context.Unload();
        }
    }

    /// <summary>
    /// Tests LoadUnmanagedDll with non-existent library.
    /// </summary>
    [TestMethod]
    public void LoadUnmanagedDll_WithNonExistentLibrary_ShouldReturnZero()
    {
        // Arrange
        string pluginPath = Path.Join(_pluginDirectory, "Main.dll");
        File.WriteAllText(pluginPath, "main plugin content");
        
        PluginLoadContext context = new PluginLoadContext(pluginPath, _pluginDirectory);
        
        try
        {
            // Act
            IntPtr result = InvokeLoadUnmanagedDll(context, "NonExistentLibrary.dll");
            
            // Assert
            Assert.AreEqual(IntPtr.Zero, result);
        }
        finally
        {
            context.Unload();
        }
    }

    /// <summary>
    /// Tests behavior with null assembly name.
    /// </summary>
    [TestMethod]
    public void Load_WithNullAssemblyName_ShouldReturnNull()
    {
        // Arrange
        string pluginPath = Path.Join(_pluginDirectory, "Main.dll");
        File.WriteAllText(pluginPath, "main plugin content");
        
        PluginLoadContext context = new PluginLoadContext(pluginPath, _pluginDirectory);
        
        try
        {
            // Act
            AssemblyName nullNameAssembly = new AssemblyName();
            Assembly? result = InvokeLoad(context, nullNameAssembly);
            
            // Assert
            Assert.IsNull(result);
        }
        finally
        {
            context.Unload();
        }
    }

    #region Helper Methods

    /// <summary>
    /// Uses reflection to invoke the protected Load method.
    /// </summary>
    private static Assembly? InvokeLoad(PluginLoadContext context, AssemblyName assemblyName)
    {
        MethodInfo? method = typeof(PluginLoadContext).GetMethod("Load", 
            BindingFlags.NonPublic | BindingFlags.Instance);
        
        Assert.IsNotNull(method, "Load method should exist");
        
        object? result = method.Invoke(context, new object[] { assemblyName });
        
        return result as Assembly;
    }

    /// <summary>
    /// Uses reflection to invoke the protected LoadUnmanagedDll method.
    /// </summary>
    private static IntPtr InvokeLoadUnmanagedDll(PluginLoadContext context, string unmanagedDllName)
    {
        MethodInfo? method = typeof(PluginLoadContext).GetMethod("LoadUnmanagedDll", 
            BindingFlags.NonPublic | BindingFlags.Instance);
        
        Assert.IsNotNull(method, "LoadUnmanagedDll method should exist");
        
        object? result = method.Invoke(context, new object[] { unmanagedDllName });
        
        Assert.IsInstanceOfType(result, typeof(IntPtr), "LoadUnmanagedDll should return IntPtr");
        
        return (IntPtr)result;
    }

    #endregion
}
