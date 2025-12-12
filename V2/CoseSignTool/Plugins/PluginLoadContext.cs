// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Reflection;
using System.Runtime.Loader;

namespace CoseSignTool.Plugins;

/// <summary>
/// Custom AssemblyLoadContext for loading plugins with isolated dependencies.
/// Each plugin gets its own context to avoid dependency conflicts (DLL hell).
/// Uses a fallback strategy: try shared context first, then plugin directory.
/// </summary>
public class PluginLoadContext : AssemblyLoadContext
{
    private readonly AssemblyDependencyResolver Resolver;
    private readonly string PluginDirectory;

    /// <summary>
    /// Initializes a new instance of the <see cref="PluginLoadContext"/> class.
    /// </summary>
    /// <param name="pluginPath">The path to the main plugin assembly.</param>
    /// <param name="pluginDirectory">The directory containing the plugin and its dependencies.</param>
    public PluginLoadContext(string pluginPath, string pluginDirectory) : base(isCollectible: true)
    {
        Resolver = new AssemblyDependencyResolver(pluginPath);
        PluginDirectory = pluginDirectory;

        // Hook the Resolving event to provide fallback when default context can't find assembly
        this.Resolving += OnResolving;
    }

    /// <summary>
    /// Loads an assembly with the specified name.
    /// Returns null to let the default context try first (shared assemblies, framework, etc.).
    /// If default context can't find it, the Resolving event will try plugin directory.
    /// </summary>
    /// <param name="assemblyName">The name of the assembly to load.</param>
    /// <returns>Always returns null to defer to default context first.</returns>
    protected override Assembly? Load(AssemblyName assemblyName)
    {
        // Strategy: Always return null to let default context try first.
        // If default context can't find it, our Resolving event handler will try plugin directory.
        // This ensures shared assemblies (CoseSignTool, System.*, etc.) come from host context
        // while plugin-specific assemblies (Azure.*, System.ClientModel, etc.) come from plugin directory.
        return null;
    }

    /// <summary>
    /// Fallback handler when default context can't resolve an assembly.
    /// Tries to load from plugin directory or dependency resolver.
    /// </summary>
    private Assembly? OnResolving(AssemblyLoadContext context, AssemblyName assemblyName)
    {
        // Try loading from plugin directory
        if (assemblyName.Name != null)
        {
            string expectedPath = Path.Combine(PluginDirectory, $"{assemblyName.Name}.dll");
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

        // Try dependency resolver
        string? assemblyPath = Resolver.ResolveAssemblyToPath(assemblyName);
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

        // Couldn't find it
        return null;
    }

    /// <summary>
    /// Loads an unmanaged library with the specified name.
    /// </summary>
    /// <param name="unmanagedDllName">The name of the unmanaged library.</param>
    /// <returns>A handle to the loaded library, or IntPtr.Zero if not found.</returns>
    protected override IntPtr LoadUnmanagedDll(string unmanagedDllName)
    {
        string? libraryPath = Resolver.ResolveUnmanagedDllToPath(unmanagedDllName);
        if (libraryPath != null && File.Exists(libraryPath))
        {
            return LoadUnmanagedDllFromPath(libraryPath);
        }

        return IntPtr.Zero;
    }
}