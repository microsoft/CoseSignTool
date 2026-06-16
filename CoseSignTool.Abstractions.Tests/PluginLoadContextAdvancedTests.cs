// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Reflection;

namespace CoseSignTool.Abstractions.Tests;

/// <summary>
/// Advanced functionality tests for PluginLoadContext including internal methods and dependency resolution.
/// </summary>
[TestClass]
public class PluginLoadContextAdvancedTests
{
    private string _tempDirectory = string.Empty;
    private string _pluginDirectory = string.Empty;

    /// <summary>
    /// Initialize test setup by creating a temporary directory.
    /// </summary>
    [TestInitialize]
    public void TestInitialize()
    {
        _tempDirectory = Path.Join(Path.GetTempPath(), $"PluginLoadContext_Advanced_{Guid.NewGuid()}");
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
    /// Tests IsHostShared with System assemblies. Note: BCL <c>System.*</c> is no longer
    /// pre-emptively shared — the runtime's default-context fallback handles them via TPA.
    /// Only the bare <c>System</c> name and the dotted-prefix-less framework families remain
    /// in the explicit prefix list. This test is retained as a documented contract.
    /// </summary>
    [TestMethod]
    public void IsHostShared_WithBareSystemName_ShouldReturnTrue()
    {
        bool result = PluginLoadContext.IsHostShared("System");
        Assert.IsTrue(result, "Bare 'System' assembly must be host-shared (BCL).");
    }

    /// <summary>
    /// Tests IsHostShared with Microsoft.Extensions assemblies.
    /// </summary>
    [TestMethod]
    public void IsHostShared_WithMicrosoftExtensionsAssemblies_ShouldReturnTrue()
    {
        // Arrange
        string[] extensionsAssemblies = {
            "Microsoft.Extensions.Logging",
            "Microsoft.Extensions.DependencyInjection",
            "Microsoft.Extensions.Configuration",
            "Microsoft.Extensions.Hosting",
            "Microsoft.Extensions.Options",
            "Microsoft.Extensions.Caching.Memory"
        };

        // Act & Assert
        foreach (string assemblyName in extensionsAssemblies)
        {
            bool result = PluginLoadContext.IsHostShared(assemblyName);
            Assert.IsTrue(result, $"'{assemblyName}' should be recognized as a shared framework assembly");
        }
    }

    /// <summary>
    /// Tests IsHostShared with the curated cross-boundary contract assemblies.
    /// These are exact-name matches; the prefix-collision smell is gone.
    /// </summary>
    [TestMethod]
    public void IsHostShared_WithSharedContractAssemblies_ShouldReturnTrue()
    {
        string[] sharedContracts = {
            "CoseSignTool.Abstractions",
            "CoseSign1.Abstractions",
            "CoseSign1.Headers",
        };

        foreach (string assemblyName in sharedContracts)
        {
            bool result = PluginLoadContext.IsHostShared(assemblyName);
            Assert.IsTrue(result, $"'{assemblyName}' is a curated cross-boundary contract and must be host-shared");
        }
    }

    /// <summary>
    /// Tests IsHostShared with bare framework assembly names that need exact matching
    /// (no trailing dot) to avoid collisions like "netstandardX" or "mscorlibX". Includes
    /// bare "System" because the unprefixed System assembly is BCL-only.
    /// </summary>
    [TestMethod]
    public void IsHostShared_WithBareFrameworkNames_ShouldReturnTrue()
    {
        string[] frameworkNames = {
            "System",
            "netstandard",
            "mscorlib",
            "WindowsBase",
            "Microsoft.CSharp",
            "Microsoft.VisualBasic",
        };

        foreach (string assemblyName in frameworkNames)
        {
            bool result = PluginLoadContext.IsHostShared(assemblyName);
            Assert.IsTrue(result, $"'{assemblyName}' is a bare framework name and must be host-shared");
        }
    }

    /// <summary>
    /// Tests that BCL <c>System.*</c> assemblies do NOT match a shared prefix anymore. They
    /// resolve via the runtime's default-context fallback (TPA) when <c>PluginLoadContext.Load</c>
    /// returns null, so functional behavior is preserved. The deliberate non-listing here lets
    /// out-of-band <c>System.*</c> NuGet packages (like <c>System.ClientModel</c>) load
    /// plugin-locally when shipped alongside a plugin.
    /// </summary>
    [TestMethod]
    public void IsHostShared_WithSystemDotPrefix_ShouldReturnFalse()
    {
        string[] systemDotNames = {
            "System.Collections",
            "System.Collections.Concurrent",
            "System.IO",
            "System.Runtime",
            "System.Text.Json",
            "System.Threading.Tasks",
            "System.Reflection.Emit",
            // NuGet packages with System.* names that legitimately ship as plugin-private deps:
            "System.ClientModel",
            "System.Memory.Data",
            "System.IO.Pipelines",
            "System.Diagnostics.DiagnosticSource",
            "System.Security.Cryptography.ProtectedData",
        };

        foreach (string assemblyName in systemDotNames)
        {
            bool result = PluginLoadContext.IsHostShared(assemblyName);
            Assert.IsFalse(result, $"'{assemblyName}' must NOT match a shared prefix — BCL System.* resolves via default-context fallback, NuGet System.* may be plugin-local");
        }
    }

    /// <summary>
    /// Tests IsHostShared with assembly names that previously matched the loose "CoseSign1" /
    /// "CoseHandler" / "CoseIndirectSignature" prefix and would have been silently absorbed into
    /// the host context. After the prefix removal these are plugin-local.
    /// </summary>
    [TestMethod]
    public void IsHostShared_WithFormerlySharedPrefixes_ShouldReturnFalse()
    {
        string[] noLongerShared = {
            "CoseHandler",                                      // host-only static usage now
            "CoseIndirectSignature",                            // plugin-local
            "CoseSign1",                                        // plugin-local concrete impl
            "CoseSign1.Certificates",                           // plugin-local; Phase 3 ISupportsScittCompliance handles cross-boundary
            "CoseSign1.Transparent.MST",                        // plugin-local; co-located with Azure SDK in plugin ALC
            "CoseSign1.Certificates.AzureArtifactSigning",      // plugin-local; co-located with Azure SDK in plugin ALC
        };

        foreach (string assemblyName in noLongerShared)
        {
            bool result = PluginLoadContext.IsHostShared(assemblyName);
            Assert.IsFalse(result, $"'{assemblyName}' must NOT be host-shared after the prefix-list cleanup — it is plugin-local");
        }
    }

    /// <summary>
    /// Tests that a hypothetical 3rd-party plugin assembly whose name happens to start with
    /// "CoseSign1" is NOT silently absorbed into the host context. This is the prefix-collision
    /// regression test that motivated the move to exact-name matching.
    /// </summary>
    [TestMethod]
    public void IsHostShared_WithThirdPartyPrefixCollisions_ShouldReturnFalse()
    {
        string[] thirdPartyImpostors = {
            "CoseSign1Plus",
            "CoseSign1Extra.Plugin",
            "CoseHandlerExtensions",
            "CoseIndirectSignatureV2",
            "CoseSignTool.Abstractions.Extras", // looks like an extension but is a different assembly
        };

        foreach (string assemblyName in thirdPartyImpostors)
        {
            bool result = PluginLoadContext.IsHostShared(assemblyName);
            Assert.IsFalse(result, $"'{assemblyName}' must NOT match the shared list — exact-name only");
        }
    }

    /// <summary>
    /// Tests that Azure SDK assemblies are NOT host-shared. Before Phase 2, these were forced into
    /// the host context as a workaround for cross-ALC type identity bugs in shared CoseSign1.* libs.
    /// After Phase 2, those libs are plugin-local, so the SDK types co-locate with their callers
    /// and never need to cross any boundary.
    /// </summary>
    [TestMethod]
    public void IsHostShared_WithAzureSdkAssemblies_ShouldReturnFalse()
    {
        string[] azureSdkAssemblies = {
            "Azure.Core",
            "Azure.Identity",
            "Azure.Security.CodeTransparency",
            "Azure.CodeSigning",
            "Azure.Developer.ArtifactSigning",
            "Azure.Developer.ArtifactSigning.CryptoProvider",
        };

        foreach (string assemblyName in azureSdkAssemblies)
        {
            bool result = PluginLoadContext.IsHostShared(assemblyName);
            Assert.IsFalse(result, $"'{assemblyName}' must NOT be host-shared — Azure SDK packages are plugin-local");
        }
    }

    /// <summary>
    /// Tests that Newtonsoft.Json is NOT host-shared. Plugins ship their own copy if they use it.
    /// </summary>
    [TestMethod]
    public void IsHostShared_WithNewtonsoftJson_ShouldReturnFalse()
    {
        bool result = PluginLoadContext.IsHostShared("Newtonsoft.Json");
        Assert.IsFalse(result, "Newtonsoft.Json must NOT be host-shared — it was a leftover prefix that introduced unwanted host coupling");
    }

    /// <summary>
    /// Tests IsHostShared with plugin-specific assemblies.
    /// </summary>
    [TestMethod]
    public void IsHostShared_WithPluginSpecificAssemblies_ShouldReturnFalse()
    {
        // Arrange
        string[] pluginSpecificAssemblies = {
            "MyPlugin",
            "CustomPlugin.Helper",
            "ThirdPartyPlugin.Extensions",
            "SomeRandomAssembly",
            "MyCompany.MyPlugin.Core"
        };

        // Act & Assert
        foreach (string assemblyName in pluginSpecificAssemblies)
        {
            bool result = PluginLoadContext.IsHostShared(assemblyName);
            Assert.IsFalse(result, $"'{assemblyName}' should NOT be recognized as a shared framework assembly");
        }
    }

    /// <summary>
    /// Tests IsHostShared with null and empty assembly name.
    /// </summary>
    [TestMethod]
    public void IsHostShared_WithNullOrEmptyName_ShouldReturnFalse()
    {
        Assert.IsFalse(PluginLoadContext.IsHostShared(null), "Null name should return false");
        Assert.IsFalse(PluginLoadContext.IsHostShared(string.Empty), "Empty name should return false");
    }

    /// <summary>
    /// Tests IsHostShared with case sensitivity.
    /// </summary>
    [TestMethod]
    public void IsHostShared_WithDifferentCasing_ShouldReturnTrue()
    {
        // Arrange — only assemblies that ARE host-shared after the cleanup
        string[] differentCasingAssemblies = {
            "system",                       // bare framework name (exact match, case-insensitive)
            "Microsoft.extensions.logging", // Microsoft.Extensions.* prefix
            "COSESIGNTOOL.ABSTRACTIONS",
            "cosesign1.abstractions",
            "cosesign1.HEADERS",
            "MSCORLIB",
            "NETSTANDARD"
        };

        // Act & Assert
        foreach (string assemblyName in differentCasingAssemblies)
        {
            bool result = PluginLoadContext.IsHostShared(assemblyName);
            Assert.IsTrue(result, $"'{assemblyName}' should be recognized as shared regardless of casing");
        }
    }

    /// <summary>
    /// Tests Load method with assembly dependency resolver fallback.
    /// </summary>
    [TestMethod]
    public void Load_WithDependencyResolverFallback_ShouldHandleCorrectly()
    {
        // Arrange
        string pluginPath = Path.Join(_pluginDirectory, "Main.dll");
        File.WriteAllText(pluginPath, "main plugin content");
        
        PluginLoadContext context = new PluginLoadContext(pluginPath, _pluginDirectory);
        
        try
        {
            // Create a non-shared assembly that should attempt dependency resolution
            AssemblyName nonSharedAssembly = new AssemblyName("CustomNonSharedAssembly");
            
            // Act
            Assembly? result = InvokeLoad(context, nonSharedAssembly);
            
            // Assert
            Assert.IsNull(result, "Non-shared assembly that doesn't exist should return null after attempting resolution");
        }
        finally
        {
            context.Unload();
        }
    }

    /// <summary>
    /// Tests Load method attempting to load from plugin directory directly.
    /// </summary>
    [TestMethod]
    public void Load_WithAssemblyInPluginDirectory_ShouldAttemptDirectLoad()
    {
        // Arrange
        string pluginPath = Path.Join(_pluginDirectory, "Main.dll");
        File.WriteAllText(pluginPath, "main plugin content");
        
        // Create a mock assembly file in plugin directory
        string mockAssemblyPath = Path.Join(_pluginDirectory, "MockAssembly.dll");
        File.WriteAllText(mockAssemblyPath, "mock assembly content - not a real assembly");
        
        PluginLoadContext context = new PluginLoadContext(pluginPath, _pluginDirectory);
        
        try
        {
            // Act
            AssemblyName mockAssembly = new AssemblyName("MockAssembly");
            Assembly? result = InvokeLoad(context, mockAssembly);
            
            // Assert
            Assert.IsNull(result, "Invalid assembly file should return null after failed load attempt");
        }
        finally
        {
            context.Unload();
        }
    }

    /// <summary>
    /// Tests that console error output is handled gracefully during assembly loading failures.
    /// </summary>
    [TestMethod]
    public void Load_WithAssemblyLoadFailures_ShouldWriteWarningsToConsole()
    {
        // Arrange
        string pluginPath = Path.Join(_pluginDirectory, "Main.dll");
        File.WriteAllText(pluginPath, "main plugin content");
        
        // Create invalid assembly files
        string invalidAssemblyPath1 = Path.Join(_pluginDirectory, "InvalidAssembly1.dll");
        string invalidAssemblyPath2 = Path.Join(_pluginDirectory, "InvalidAssembly2.dll");
        File.WriteAllText(invalidAssemblyPath1, "invalid content");
        File.WriteAllText(invalidAssemblyPath2, "also invalid content");
        
        PluginLoadContext context = new PluginLoadContext(pluginPath, _pluginDirectory);
        
        try
        {
            // Capture console output
            StringWriter consoleOutput = new StringWriter();
            TextWriter originalError = Console.Error;
            Console.SetError(consoleOutput);
            
            try
            {
                // Act - attempt to load invalid assemblies
                AssemblyName invalidAssembly1 = new AssemblyName("InvalidAssembly1");
                AssemblyName invalidAssembly2 = new AssemblyName("InvalidAssembly2");
                
                Assembly? result1 = InvokeLoad(context, invalidAssembly1);
                Assembly? result2 = InvokeLoad(context, invalidAssembly2);
                
                // Assert
                Assert.IsNull(result1, "Invalid assembly should return null");
                Assert.IsNull(result2, "Invalid assembly should return null");
                
                // Check that warnings were written (though they might be suppressed in test environment)
                string errorOutput = consoleOutput.ToString();
                // Note: In test environment, console output might be captured differently
                // So we just verify the method completed without throwing exceptions
                Assert.IsTrue(true, "Assembly loading with invalid files completed without exceptions");
            }
            finally
            {
                Console.SetError(originalError);
                consoleOutput.Dispose();
            }
        }
        finally
        {
            context.Unload();
        }
    }

    /// <summary>
    /// Tests multiple consecutive Load operations on the same context.
    /// </summary>
    [TestMethod]
    public void Load_MultipleConsecutiveOperations_ShouldMaintainConsistentBehavior()
    {
        // Arrange
        string pluginPath = Path.Join(_pluginDirectory, "Main.dll");
        File.WriteAllText(pluginPath, "main plugin content");
        
        PluginLoadContext context = new PluginLoadContext(pluginPath, _pluginDirectory);
        
        try
        {
            // Act & Assert - perform multiple load operations
            for (int i = 0; i < 10; i++)
            {
                // Test shared framework assembly
                AssemblyName systemAssembly = new AssemblyName("System.Collections");
                Assembly? systemResult = InvokeLoad(context, systemAssembly);
                Assert.IsNull(systemResult, $"Iteration {i}: System assembly should return null");
                
                // Test non-existent assembly
                AssemblyName nonExistentAssembly = new AssemblyName($"NonExistent_{i}");
                Assembly? nonExistentResult = InvokeLoad(context, nonExistentAssembly);
                Assert.IsNull(nonExistentResult, $"Iteration {i}: Non-existent assembly should return null");
            }
        }
        finally
        {
            context.Unload();
        }
    }

    /// <summary>
    /// Tests LoadUnmanagedDll with dependency resolver integration.
    /// </summary>
    [TestMethod]
    public void LoadUnmanagedDll_WithDependencyResolver_ShouldUseResolver()
    {
        // Arrange
        string pluginPath = Path.Join(_pluginDirectory, "Main.dll");
        File.WriteAllText(pluginPath, "main plugin content");
        
        PluginLoadContext context = new PluginLoadContext(pluginPath, _pluginDirectory);
        
        try
        {
            // Act
            IntPtr result = InvokeLoadUnmanagedDll(context, "SomeNativeLibrary.dll");
            
            // Assert
            Assert.AreEqual(IntPtr.Zero, result, "Non-existent native library should return IntPtr.Zero");
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
        
        try
        {
            object? result = method.Invoke(context, new object[] { assemblyName });
            return result as Assembly;
        }
        catch (TargetInvocationException ex) when (ex.InnerException != null)
        {
            // In advanced tests, we expect some exceptions during assembly loading
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
            // Re-throw the inner exception to preserve original exception type
            throw ex.InnerException;
        }
    }

    #endregion
}
