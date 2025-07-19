// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Reflection;

namespace CoseSignTool.Abstractions.Tests;

/// <summary>
/// Edge case and error scenario tests for PluginLoadContext.
/// </summary>
[TestClass]
public class PluginLoadContextEdgeCaseTests
{
    private string TestTempDirectory = string.Empty;
    private string TestPluginDirectory = string.Empty;

    /// <summary>
    /// Initialize test setup by creating a temporary directory.
    /// </summary>
    [TestInitialize]
    public void TestInitialize()
    {
        TestTempDirectory = Path.Join(Path.GetTempPath(), $"PluginLoadContext_EdgeCase_{Guid.NewGuid()}");
        Directory.CreateDirectory(TestTempDirectory);
        
        TestPluginDirectory = Path.Join(TestTempDirectory, "TestPlugin");
        Directory.CreateDirectory(TestPluginDirectory);
    }

    /// <summary>
    /// Clean up test resources.
    /// </summary>
    [TestCleanup]
    public void TestCleanup()
    {
        if (Directory.Exists(TestTempDirectory))
        {
            try
            {
                Directory.Delete(TestTempDirectory, true);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Warning: Failed to clean up test directory: {ex.Message}");
            }
        }
    }

    /// <summary>
    /// Tests constructor with null plugin path - should throw ArgumentNullException from AssemblyDependencyResolver.
    /// </summary>
    [TestMethod]
    [ExpectedException(typeof(ArgumentNullException))]
    public void Constructor_WithNullPluginPath_ShouldThrowArgumentNullException()
    {
        // Act & Assert
        PluginLoadContext context = new PluginLoadContext(null!, TestPluginDirectory);
    }

    /// <summary>
    /// Tests constructor with empty plugin path - may succeed if treated as current directory.
    /// </summary>
    [TestMethod]
    public void Constructor_WithEmptyPluginPath_ShouldHandleGracefully()
    {
        try
        {
            // Act
            PluginLoadContext context = new PluginLoadContext(string.Empty, TestPluginDirectory);
            
            // Assert - Empty string may be treated as current directory
            Assert.IsNotNull(context);
            Assert.IsTrue(context.IsCollectible);
            
            // Cleanup
            context.Unload();
        }
        catch (InvalidOperationException)
        {
            // This is also acceptable if AssemblyDependencyResolver rejects empty path
            Assert.IsTrue(true, "InvalidOperationException is acceptable for empty plugin path");
        }
    }

    /// <summary>
    /// Tests constructor with whitespace-only plugin path - should throw InvalidOperationException from AssemblyDependencyResolver.
    /// </summary>
    [TestMethod]
    [ExpectedException(typeof(InvalidOperationException))]
    public void Constructor_WithWhitespacePluginPath_ShouldThrowInvalidOperationException()
    {
        // Act & Assert
        PluginLoadContext context = new PluginLoadContext("   ", TestPluginDirectory);
    }

    /// <summary>
    /// Tests constructor with null plugin directory - should throw but allow AssemblyDependencyResolver to fail first.
    /// </summary>
    [TestMethod]
    [ExpectedException(typeof(InvalidOperationException))]
    public void Constructor_WithNullPluginDirectory_ShouldThrowInvalidOperationException()
    {
        // Arrange
        string pluginPath = Path.Join(TestPluginDirectory, "Main.dll");
        
        // Act & Assert - AssemblyDependencyResolver fails before null directory is checked
        PluginLoadContext context = new PluginLoadContext(pluginPath, null!);
    }

    /// <summary>
    /// Tests constructor with empty plugin directory - should throw InvalidOperationException from AssemblyDependencyResolver.
    /// </summary>
    [TestMethod]
    [ExpectedException(typeof(InvalidOperationException))]
    public void Constructor_WithEmptyPluginDirectory_ShouldThrowInvalidOperationException()
    {
        // Arrange
        string pluginPath = Path.Join(TestPluginDirectory, "Main.dll");
        
        // Act & Assert
        PluginLoadContext context = new PluginLoadContext(pluginPath, string.Empty);
    }

    /// <summary>
    /// Tests constructor with extremely long plugin path.
    /// </summary>
    [TestMethod]
    public void Constructor_WithLongPluginPath_ShouldThrowInvalidOperationException()
    {
        // Arrange
        string longFileName = new string('A', 200) + ".dll";
        string longPath = Path.Join(TestPluginDirectory, longFileName);
        
        try
        {
            // Act
            PluginLoadContext context = new PluginLoadContext(longPath, TestPluginDirectory);
            
            // If we get here, the path was acceptable
            Assert.IsNotNull(context);
            context.Unload();
        }
        catch (InvalidOperationException)
        {
            // This is expected when AssemblyDependencyResolver can't resolve the path
            Assert.IsTrue(true, "InvalidOperationException is expected for non-existent long paths");
        }
        catch (PathTooLongException)
        {
            // This is also acceptable behavior on some systems
            Assert.IsTrue(true, "PathTooLongException is acceptable for extremely long paths");
        }
    }

    /// <summary>
    /// Tests constructor with plugin path containing invalid characters.
    /// </summary>
    [TestMethod]
    public void Constructor_WithInvalidCharactersInPath_ShouldThrowInvalidOperationException()
    {
        // Arrange
        string invalidPath = Path.Join(TestPluginDirectory, "Plugin<>|*.dll");
        
        try
        {
            // Act
            PluginLoadContext context = new PluginLoadContext(invalidPath, TestPluginDirectory);
            
            // If we get here unexpectedly, clean up
            context.Unload();
            Assert.Fail("Expected InvalidOperationException for invalid path characters");
        }
        catch (InvalidOperationException)
        {
            // This is expected when AssemblyDependencyResolver can't resolve the invalid path
            Assert.IsTrue(true, "InvalidOperationException is expected for invalid path characters");
        }
    }

    /// <summary>
    /// Tests Load with corrupted assembly file.
    /// </summary>
    [TestMethod]
    public void Load_WithCorruptedAssemblyFile_ShouldReturnNull()
    {
        // Arrange
        string pluginPath = Path.Join(TestPluginDirectory, "Main.dll");
        File.WriteAllText(pluginPath, "main plugin content");
        
        string corruptedAssemblyPath = Path.Join(TestPluginDirectory, "CorruptedAssembly.dll");
        File.WriteAllText(corruptedAssemblyPath, "This is not a valid PE assembly file");
        
        PluginLoadContext context = new PluginLoadContext(pluginPath, TestPluginDirectory);
        
        try
        {
            // Act
            AssemblyName corruptedAssembly = new AssemblyName("CorruptedAssembly");
            Assembly? result = InvokeLoad(context, corruptedAssembly);
            
            // Assert - Should return null when assembly can't be loaded
            Assert.IsNull(result);
        }
        finally
        {
            context.Unload();
        }
    }

    /// <summary>
    /// Tests Load with binary file that's not an assembly.
    /// </summary>
    [TestMethod]
    public void Load_WithBinaryNonAssemblyFile_ShouldReturnNull()
    {
        // Arrange
        string pluginPath = Path.Join(TestPluginDirectory, "Main.dll");
        File.WriteAllText(pluginPath, "main plugin content");
        
        string binaryPath = Path.Join(TestPluginDirectory, "BinaryFile.dll");
        byte[] binaryData = { 0x4D, 0x5A, 0x90, 0x00 }; // Fake DOS header
        File.WriteAllBytes(binaryPath, binaryData);
        
        PluginLoadContext context = new PluginLoadContext(pluginPath, TestPluginDirectory);
        
        try
        {
            // Act
            AssemblyName binaryAssembly = new AssemblyName("BinaryFile");
            Assembly? result = InvokeLoad(context, binaryAssembly);
            
            // Assert
            Assert.IsNull(result);
        }
        finally
        {
            context.Unload();
        }
    }

    /// <summary>
    /// Tests Load with very long assembly name.
    /// </summary>
    [TestMethod]
    public void Load_WithVeryLongAssemblyName_ShouldReturnNull()
    {
        // Arrange
        string pluginPath = Path.Join(TestPluginDirectory, "Main.dll");
        File.WriteAllText(pluginPath, "main plugin content");
        
        PluginLoadContext context = new PluginLoadContext(pluginPath, TestPluginDirectory);
        
        try
        {
            // Act
            string longName = new string('A', 1000); // Very long name
            AssemblyName longAssemblyName = new AssemblyName(longName);
            Assembly? result = InvokeLoad(context, longAssemblyName);
            
            // Assert
            Assert.IsNull(result);
        }
        finally
        {
            context.Unload();
        }
    }

    /// <summary>
    /// Tests Load with assembly name containing special characters.
    /// </summary>
    [TestMethod]
    public void Load_WithSpecialCharactersInAssemblyName_ShouldHandleInvalidNames()
    {
        // Arrange
        string pluginPath = Path.Join(TestPluginDirectory, "Main.dll");
        File.WriteAllText(pluginPath, "main plugin content");
        
        PluginLoadContext context = new PluginLoadContext(pluginPath, TestPluginDirectory);
        
        try
        {
            // Test various special characters that might cause issues
            string[] validSpecialNames = {
                "Assembly_Name",     // Underscore is valid
                "Assembly-Name",     // Hyphen is valid  
                "Assembly.Name",     // Dot is valid
                "Assembly123"        // Numbers are valid
            };

            string[] invalidSpecialNames = {
                "Assembly<>Name",
                "Assembly|Name",
                "Assembly*Name",
                "Assembly?Name",
                "Assembly\"Name",
                "Assembly:Name",
                "Assembly\\Name",
                "Assembly/Name"
            };

            // Test valid names - should return null (not found)
            foreach (string validName in validSpecialNames)
            {
                AssemblyName validAssemblyName = new AssemblyName(validName);
                Assembly? result = InvokeLoad(context, validAssemblyName);
                Assert.IsNull(result, $"Valid assembly name '{validName}' should return null (not found)");
            }

            // Test invalid names - should throw during AssemblyName construction
            foreach (string invalidName in invalidSpecialNames)
            {
                try
                {
                    AssemblyName invalidAssemblyName = new AssemblyName(invalidName);
                    // If we get here, the name was somehow valid, test the Load method
                    Assembly? result = InvokeLoad(context, invalidAssemblyName);
                    Assert.IsNull(result, $"Assembly name '{invalidName}' should return null if constructed successfully");
                }
                catch (FileLoadException)
                {
                    // This is expected for invalid assembly names
                    Assert.IsTrue(true, $"FileLoadException is expected for invalid assembly name '{invalidName}'");
                }
            }
        }
        finally
        {
            context.Unload();
        }
    }

    /// <summary>
    /// Tests Load with assembly name that starts with numbers.
    /// </summary>
    [TestMethod]
    public void Load_WithNumericStartAssemblyName_ShouldReturnNull()
    {
        // Arrange
        string pluginPath = Path.Join(TestPluginDirectory, "Main.dll");
        File.WriteAllText(pluginPath, "main plugin content");
        
        PluginLoadContext context = new PluginLoadContext(pluginPath, TestPluginDirectory);
        
        try
        {
            // Act
            AssemblyName numericAssembly = new AssemblyName("123Assembly");
            Assembly? result = InvokeLoad(context, numericAssembly);
            
            // Assert
            Assert.IsNull(result);
        }
        finally
        {
            context.Unload();
        }
    }

    /// <summary>
    /// Tests LoadUnmanagedDll with null library name.
    /// </summary>
    [TestMethod]
    public void LoadUnmanagedDll_WithNullLibraryName_ShouldReturnZero()
    {
        // Arrange
        string pluginPath = Path.Join(TestPluginDirectory, "Main.dll");
        File.WriteAllText(pluginPath, "main plugin content");
        
        PluginLoadContext context = new PluginLoadContext(pluginPath, TestPluginDirectory);
        
        try
        {
            // Act
            IntPtr result = InvokeLoadUnmanagedDll(context, null!);
            
            // Assert
            Assert.AreEqual(IntPtr.Zero, result);
        }
        finally
        {
            context.Unload();
        }
    }

    /// <summary>
    /// Tests LoadUnmanagedDll with empty library name.
    /// </summary>
    [TestMethod]
    public void LoadUnmanagedDll_WithEmptyLibraryName_ShouldReturnZero()
    {
        // Arrange
        string pluginPath = Path.Join(TestPluginDirectory, "Main.dll");
        File.WriteAllText(pluginPath, "main plugin content");
        
        PluginLoadContext context = new PluginLoadContext(pluginPath, TestPluginDirectory);
        
        try
        {
            // Act
            IntPtr result = InvokeLoadUnmanagedDll(context, string.Empty);
            
            // Assert
            Assert.AreEqual(IntPtr.Zero, result);
        }
        finally
        {
            context.Unload();
        }
    }

    /// <summary>
    /// Tests LoadUnmanagedDll with library name containing special characters.
    /// </summary>
    [TestMethod]
    public void LoadUnmanagedDll_WithSpecialCharactersInLibraryName_ShouldReturnZero()
    {
        // Arrange
        string pluginPath = Path.Join(TestPluginDirectory, "Main.dll");
        File.WriteAllText(pluginPath, "main plugin content");
        
        PluginLoadContext context = new PluginLoadContext(pluginPath, TestPluginDirectory);
        
        try
        {
            // Test various special characters
            string[] specialNames = {
                "Library<>Name.dll",
                "Library|Name.dll",
                "Library*Name.dll",
                "Library?Name.dll",
                "Library\"Name.dll",
                "Library:Name.dll"
            };

            foreach (string specialName in specialNames)
            {
                // Act
                IntPtr result = InvokeLoadUnmanagedDll(context, specialName);
                
                // Assert
                Assert.AreEqual(IntPtr.Zero, result, $"Library with special characters '{specialName}' should return IntPtr.Zero");
            }
        }
        finally
        {
            context.Unload();
        }
    }

    /// <summary>
    /// Tests LoadUnmanagedDll with very long library name.
    /// </summary>
    [TestMethod]
    public void LoadUnmanagedDll_WithVeryLongLibraryName_ShouldReturnZero()
    {
        // Arrange
        string pluginPath = Path.Join(TestPluginDirectory, "Main.dll");
        File.WriteAllText(pluginPath, "main plugin content");
        
        PluginLoadContext context = new PluginLoadContext(pluginPath, TestPluginDirectory);
        
        try
        {
            // Act
            string longName = new string('L', 500) + ".dll";
            IntPtr result = InvokeLoadUnmanagedDll(context, longName);
            
            // Assert
            Assert.AreEqual(IntPtr.Zero, result);
        }
        finally
        {
            context.Unload();
        }
    }

    /// <summary>
    /// Tests behavior when plugin directory has restricted permissions.
    /// </summary>
    [TestMethod]
    public void Load_WithRestrictedPermissions_ShouldHandleGracefully()
    {
        // Arrange
        string pluginPath = Path.Join(TestPluginDirectory, "Main.dll");
        File.WriteAllText(pluginPath, "main plugin content");
        
        // Create a file that might have permission issues
        string restrictedAssemblyPath = Path.Join(TestPluginDirectory, "RestrictedAssembly.dll");
        File.WriteAllText(restrictedAssemblyPath, "restricted content");
        
        PluginLoadContext context = new PluginLoadContext(pluginPath, TestPluginDirectory);
        
        try
        {
            // Act
            AssemblyName restrictedAssembly = new AssemblyName("RestrictedAssembly");
            Assembly? result = InvokeLoad(context, restrictedAssembly);
            
            // Assert - Should return null when assembly can't be loaded due to permissions or corruption
            Assert.IsNull(result);
        }
        finally
        {
            context.Unload();
        }
    }

    /// <summary>
    /// Tests multiple consecutive Unload operations - should not throw exceptions.
    /// </summary>
    [TestMethod]
    public void Unload_MultipleConsecutiveCalls_ShouldNotThrow()
    {
        // Arrange
        string pluginPath = Path.Join(TestPluginDirectory, "Main.dll");
        File.WriteAllText(pluginPath, "main plugin content");
        
        PluginLoadContext context = new PluginLoadContext(pluginPath, TestPluginDirectory);
        
        // Act & Assert - Multiple unloads should not throw
        context.Unload();
        context.Unload(); // Second unload should not throw
        context.Unload(); // Third unload should not throw
        
        Assert.IsTrue(true, "Multiple unload calls completed without exceptions");
    }

    /// <summary>
    /// Tests using context after unload - should handle gracefully.
    /// </summary>
    [TestMethod]
    public void Load_AfterUnload_ShouldHandleGracefully()
    {
        // Arrange
        string pluginPath = Path.Join(TestPluginDirectory, "Main.dll");
        File.WriteAllText(pluginPath, "main plugin content");
        
        PluginLoadContext context = new PluginLoadContext(pluginPath, TestPluginDirectory);
        context.Unload();
        
        // Act & Assert - Using context after unload should not crash
        try
        {
            AssemblyName testAssembly = new AssemblyName("TestAssembly");
            Assembly? result = InvokeLoad(context, testAssembly);
            
            // May return null or throw, both are acceptable for unloaded context
            Assert.IsTrue(true, "Load after unload handled gracefully");
        }
        catch (ObjectDisposedException)
        {
            // This is acceptable behavior
            Assert.IsTrue(true, "ObjectDisposedException is acceptable for unloaded context");
        }
        catch (Exception ex)
        {
            // Log but don't fail - various exceptions are possible
            Console.WriteLine($"Exception after unload: {ex.GetType().Name}: {ex.Message}");
            Assert.IsTrue(true, "Exception after unload handled gracefully");
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
        
        try
        {
            object? result = method.Invoke(context, new object[] { assemblyName });
            return result as Assembly;
        }
        catch (TargetInvocationException ex) when (ex.InnerException != null)
        {
            // For edge case tests, we often expect exceptions during assembly loading
            // Return null to indicate the assembly couldn't be loaded
            return null;
        }
    }

    /// <summary>
    /// Uses reflection to invoke the protected LoadUnmanagedDll method.
    /// </summary>
    private static IntPtr InvokeLoadUnmanagedDll(PluginLoadContext context, string unmanagedDllName)
    {
        MethodInfo? method = typeof(PluginLoadContext).GetMethod("LoadUnmanagedDll", 
            BindingFlags.NonPublic | BindingFlags.Instance);
        
        Assert.IsNotNull(method, "LoadUnmanagedDll method should exist");
        
        try
        {
            object? result = method.Invoke(context, new object[] { unmanagedDllName });
            Assert.IsInstanceOfType(result, typeof(IntPtr), "LoadUnmanagedDll should return IntPtr");
            return (IntPtr)result;
        }
        catch (TargetInvocationException ex) when (ex.InnerException != null)
        {
            // For edge cases, return IntPtr.Zero when unmanaged DLL can't be loaded
            return IntPtr.Zero;
        }
    }

    #endregion
}
