// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Reflection;
using System.Runtime.Loader;

namespace CoseSignTool.Abstractions;

/// <summary>
/// Custom AssemblyLoadContext for loading plugins with isolated dependencies.
/// Each plugin gets its own context to avoid dependency conflicts.
/// </summary>
public class PluginLoadContext : AssemblyLoadContext
{
    private readonly AssemblyDependencyResolver _resolver;
    private readonly string _pluginDirectory;

    /// <summary>
    /// Initializes a new instance of the PluginLoadContext class.
    /// </summary>
    /// <param name="pluginPath">The path to the main plugin assembly.</param>
    /// <param name="pluginDirectory">The directory containing the plugin and its dependencies.</param>
    public PluginLoadContext(string pluginPath, string pluginDirectory) : base(isCollectible: true)
    {
        _resolver = new AssemblyDependencyResolver(pluginPath);
        _pluginDirectory = pluginDirectory;
    }

    /// <summary>
    /// Loads an assembly with the specified name.
    /// First tries to resolve from the plugin directory, then falls back to default context.
    /// </summary>
    /// <param name="assemblyName">The name of the assembly to load.</param>
    /// <returns>The loaded assembly, or null if not found.</returns>
    protected override Assembly? Load(AssemblyName assemblyName)
    {
        // For shared dependencies (like Microsoft.Extensions.*, System.*, etc.),
        // let the default context handle them to avoid duplicating framework assemblies
        if (IsSharedFrameworkAssembly(assemblyName))
        {
            return null; // This will fall back to the default context
        }

        // Look for the assembly directly in the plugin directory first
        if (assemblyName.Name != null)
        {
            string expectedPath = Path.Join(_pluginDirectory, $"{assemblyName.Name}.dll");
            if (File.Exists(expectedPath))
            {
                try
                {
                    return LoadFromAssemblyPath(expectedPath);
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"Warning: Failed to load assembly '{assemblyName.Name}' from '{expectedPath}': {ex.Message}");
                }
            }
        }

        // Try to resolve the assembly from the plugin directory using the dependency resolver
        string? assemblyPath = _resolver.ResolveAssemblyToPath(assemblyName);
        if (assemblyPath != null && File.Exists(assemblyPath))
        {
            try
            {
                return LoadFromAssemblyPath(assemblyPath);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Warning: Failed to load assembly '{assemblyName.Name}' from resolver path '{assemblyPath}': {ex.Message}");
            }
        }

        // If we can't find the assembly, return null to allow default loading
        return null;
    }

    /// <summary>
    /// Determines if an assembly should be loaded from the shared framework rather than plugin-specific.
    /// </summary>
    /// <param name="assemblyName">The assembly name to check.</param>
    /// <returns>True if this is a shared framework assembly.</returns>
    private static bool IsSharedFrameworkAssembly(AssemblyName assemblyName)
    {
        if (assemblyName.Name == null)
        {
            return false;
        }

        // These should come from the main application context to avoid conflicts
        string[] sharedPrefixes =
        [
            "System.",
            "Microsoft.Extensions.",
            "Microsoft.NETCore.",
            "netstandard",
            "mscorlib",
            "System",
            "Newtonsoft.Json",
            "CoseSignTool.Abstractions", // Always use the main version
            "CoseHandler",               // Shared components
            "CoseSign1",
            "CoseIndirectSignature"
        ];

        return sharedPrefixes.Any(prefix => assemblyName.Name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Loads an unmanaged library with the specified name.
    /// </summary>
    /// <param name="unmanagedDllName">The name of the unmanaged library.</param>
    /// <returns>A handle to the loaded library, or IntPtr.Zero if not found.</returns>
    protected override IntPtr LoadUnmanagedDll(string unmanagedDllName)
    {
        string? libraryPath = _resolver.ResolveUnmanagedDllToPath(unmanagedDllName);
        if (libraryPath != null && File.Exists(libraryPath))
        {
            return LoadUnmanagedDllFromPath(libraryPath);
        }

        return IntPtr.Zero;
    }
}
