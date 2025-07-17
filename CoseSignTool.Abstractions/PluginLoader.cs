// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Reflection;

namespace CoseSignTool.Abstractions;

/// <summary>
/// Provides functionality to discover and load CoseSignTool plugins.
/// Plugins can only be loaded from the "plugins" subdirectory of the executable for security reasons.
/// </summary>
public static class PluginLoader
{
    /// <summary>
    /// Discovers plugins in the specified directory.
    /// For security reasons, only plugins in the "plugins" subdirectory are allowed.
    /// </summary>
    /// <param name="pluginDirectory">The directory to search for plugins.</param>
    /// <returns>A collection of discovered plugins.</returns>
    /// <exception cref="UnauthorizedAccessException">Thrown when attempting to load plugins from an unauthorized directory.</exception>
    public static IEnumerable<ICoseSignToolPlugin> DiscoverPlugins(string pluginDirectory)
    {
        if (!Directory.Exists(pluginDirectory))
        {
            yield break;
        }

        // Security check: Only allow plugins from the "plugins" subdirectory
        ValidatePluginDirectory(pluginDirectory);

        var pluginFiles = Directory.GetFiles(pluginDirectory, "*.Plugin.dll", SearchOption.TopDirectoryOnly);

        foreach (string pluginFile in pluginFiles)
        {
            ICoseSignToolPlugin? plugin = LoadPlugin(pluginFile);
            if (plugin != null)
            {
                yield return plugin;
            }
        }
    }

    /// <summary>
    /// Validates that the plugin directory is authorized for plugin loading.
    /// Only the "plugins" subdirectory of the executable is allowed.
    /// </summary>
    /// <param name="pluginDirectory">The directory to validate.</param>
    /// <exception cref="UnauthorizedAccessException">Thrown when the directory is not authorized for plugin loading.</exception>
    public static void ValidatePluginDirectory(string pluginDirectory)
    {
        // Check for null or empty directory path first
        if (string.IsNullOrWhiteSpace(pluginDirectory))
        {
            throw new UnauthorizedAccessException(
                "Plugin loading is only allowed from the 'plugins' subdirectory. " +
                "Attempted to load from an empty or null directory path.");
        }

        string executablePath = System.Reflection.Assembly.GetExecutingAssembly().Location;
        string executableDirectory;
        
        if (string.IsNullOrWhiteSpace(executablePath))
        {
            // Fallback for single-file deployments or when Location is not available
            executableDirectory = Directory.GetCurrentDirectory();
        }
        else
        {
            executableDirectory = Path.GetDirectoryName(executablePath);
            if (string.IsNullOrWhiteSpace(executableDirectory))
            {
                // Additional fallback if GetDirectoryName returns null/empty
                executableDirectory = Directory.GetCurrentDirectory();
            }
        }
        
        string authorizedPluginsDirectory = Path.Join(executableDirectory, "plugins");
        
        // Normalize paths for comparison (remove trailing directory separators)
        string normalizedPluginDirectory = Path.GetFullPath(pluginDirectory).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        string normalizedAuthorizedDirectory = Path.GetFullPath(authorizedPluginsDirectory).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        
        if (!string.Equals(normalizedPluginDirectory, normalizedAuthorizedDirectory, StringComparison.OrdinalIgnoreCase))
        {
            throw new UnauthorizedAccessException(
                $"Plugin loading is only allowed from the 'plugins' subdirectory. " +
                $"Attempted to load from: '{normalizedPluginDirectory}', " +
                $"but only '{normalizedAuthorizedDirectory}' is authorized.");
        }
    }

    /// <summary>
    /// Loads a plugin from the specified assembly file.
    /// </summary>
    /// <param name="assemblyPath">The path to the assembly file.</param>
    /// <returns>The loaded plugin, or null if the plugin could not be loaded.</returns>
    public static ICoseSignToolPlugin? LoadPlugin(string assemblyPath)
    {
        try
        {
            Assembly assembly = Assembly.LoadFrom(assemblyPath);
            return LoadPlugin(assembly);
        }
        catch (Exception ex) when (ex is FileNotFoundException or BadImageFormatException or FileLoadException)
        {
            // Log or handle plugin loading errors as needed
            Console.Error.WriteLine($"Warning: Could not load plugin from '{assemblyPath}': {ex.Message}");
            return null;
        }
    }

    /// <summary>
    /// Loads a plugin from the specified assembly.
    /// </summary>
    /// <param name="assembly">The assembly to search for plugins.</param>
    /// <returns>The loaded plugin, or null if no plugin was found.</returns>
    public static ICoseSignToolPlugin? LoadPlugin(Assembly assembly)
    {
        try
        {
            Type[] types = assembly.GetTypes();
            Type? pluginType = types.FirstOrDefault(t => 
                typeof(ICoseSignToolPlugin).IsAssignableFrom(t) && 
                !t.IsInterface && 
                !t.IsAbstract);

            if (pluginType != null)
            {
                return Activator.CreateInstance(pluginType) as ICoseSignToolPlugin;
            }
        }
        catch (Exception ex) when (ex is ReflectionTypeLoadException or TypeLoadException)
        {
            Console.Error.WriteLine($"Warning: Could not load plugin types from assembly '{assembly.FullName}': {ex.Message}");
        }

        return null;
    }
}
