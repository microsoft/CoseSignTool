// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Reflection;

namespace CoseSignTool.Plugins;

/// <summary>
/// Loads and manages plugins for CoseSignTool with isolated dependencies.
/// Plugins must be in subdirectories under the "plugins" folder for security and isolation.
/// </summary>
public class PluginLoader
{
    private readonly List<IPlugin> _plugins = [];

    /// <summary>
    /// Gets the loaded plugins.
    /// </summary>
    public IReadOnlyList<IPlugin> Plugins => _plugins.AsReadOnly();

    /// <summary>
    /// Loads plugins from the specified directory.
    /// For security, only plugins in the "plugins" subdirectory are allowed unless additionalDirectories are specified.
    /// Each plugin must be in its own subdirectory with its dependencies for isolation.
    /// </summary>
    /// <param name="pluginDirectory">The main plugins directory to search.</param>
    /// <param name="additionalDirectories">Additional trusted plugin directories.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    public async Task LoadPluginsAsync(string pluginDirectory, IEnumerable<string>? additionalDirectories = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pluginDirectory);

        // Load from main plugin directory
        await LoadPluginsFromDirectoryAsync(pluginDirectory, validateSecurity: true);

        // Load from additional directories if specified
        if (additionalDirectories != null)
        {
            foreach (var additionalDir in additionalDirectories)
            {
                if (!string.IsNullOrWhiteSpace(additionalDir))
                {
                    await LoadPluginsFromDirectoryAsync(additionalDir, validateSecurity: false);
                }
            }
        }
    }

    private async Task LoadPluginsFromDirectoryAsync(string pluginDirectory, bool validateSecurity)
    {
        // Security validation for main plugins directory
        if (validateSecurity)
        {
            ValidatePluginDirectory(pluginDirectory);
        }

        if (!Directory.Exists(pluginDirectory))
        {
            return;
        }

        // Each plugin must be in its own subdirectory for dependency isolation
        var subdirectories = Directory.GetDirectories(pluginDirectory);

        foreach (var subdirectory in subdirectories)
        {
            await LoadPluginFromSubdirectoryAsync(subdirectory);
        }
    }

    /// <summary>
    /// Registers a plugin directly (useful for built-in plugins).
    /// </summary>
    /// <param name="plugin">The plugin to register.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    public async Task RegisterPluginAsync(IPlugin plugin)
    {
        ArgumentNullException.ThrowIfNull(plugin);

        if (!_plugins.Any(p => p.Name == plugin.Name))
        {
            _plugins.Add(plugin);
            await plugin.InitializeAsync();
        }
    }

    /// <summary>
    /// Validates that the plugin directory is authorized for plugin loading.
    /// Only the "plugins" subdirectory of the executable is allowed.
    /// </summary>
    /// <param name="pluginDirectory">The directory to validate.</param>
    /// <exception cref="UnauthorizedAccessException">Thrown when the directory is not authorized.</exception>
    public static void ValidatePluginDirectory(string pluginDirectory)
    {
        if (string.IsNullOrWhiteSpace(pluginDirectory))
        {
            throw new UnauthorizedAccessException(
                "Plugin loading is only allowed from the 'plugins' subdirectory. " +
                "Attempted to load from an empty or null directory path.");
        }

        string executablePath = Assembly.GetExecutingAssembly().Location;
        string executableDirectory;

        if (string.IsNullOrWhiteSpace(executablePath))
        {
            // Fallback for single-file deployments
            executableDirectory = Directory.GetCurrentDirectory();
        }
        else
        {
            executableDirectory = Path.GetDirectoryName(executablePath) ?? Directory.GetCurrentDirectory();
        }

        string authorizedPluginsDirectory = Path.Combine(executableDirectory, "plugins");

        // Normalize paths for comparison
        string normalizedPluginDirectory = Path.GetFullPath(pluginDirectory)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        string normalizedAuthorizedDirectory = Path.GetFullPath(authorizedPluginsDirectory)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);

        if (!string.Equals(normalizedPluginDirectory, normalizedAuthorizedDirectory, StringComparison.OrdinalIgnoreCase))
        {
            throw new UnauthorizedAccessException(
                $"Plugin loading is only allowed from the 'plugins' subdirectory. " +
                $"Attempted to load from: '{normalizedPluginDirectory}', " +
                $"but only '{normalizedAuthorizedDirectory}' is authorized.");
        }
    }

    private async Task LoadPluginFromSubdirectoryAsync(string subdirectory)
    {
        // Look for plugin DLLs (*.Plugin.dll naming convention)
        var pluginFiles = Directory.GetFiles(subdirectory, "*.Plugin.dll", SearchOption.TopDirectoryOnly);

        foreach (var pluginFile in pluginFiles)
        {
            await LoadPluginWithContextAsync(pluginFile, subdirectory);
        }
    }

    private async Task LoadPluginWithContextAsync(string assemblyPath, string pluginDirectory)
    {
        // Create isolated AssemblyLoadContext for this plugin
        var loadContext = new PluginLoadContext(assemblyPath, pluginDirectory);
        var assembly = loadContext.LoadFromAssemblyPath(assemblyPath);
        Type[] types;
        try
        {
            types = assembly.GetTypes();
        }
        catch (ReflectionTypeLoadException ex)
        {
            Console.Error.WriteLine($"ERROR: Failed to load types from {assemblyPath}");
            Console.Error.WriteLine($"ERROR: {ex.Message}");
            if (ex.LoaderExceptions != null)
            {
                foreach (var loaderEx in ex.LoaderExceptions)
                {
                    Console.Error.WriteLine($"ERROR: Loader exception: {loaderEx?.Message}");
                }
            }
            throw;
        }

        // Load plugins
        var pluginTypes = types.Where(t => typeof(IPlugin).IsAssignableFrom(t) && !t.IsInterface && !t.IsAbstract);

        foreach (var pluginType in pluginTypes)
        {
            if (Activator.CreateInstance(pluginType) is IPlugin plugin)
            {
                await RegisterPluginAsync(plugin);
            }
        }
    }
}
