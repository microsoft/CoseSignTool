// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Reflection;
using CoseSignTool.Logging;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace CoseSignTool.Plugins;

/// <summary>
/// Loads and manages plugins for CoseSignTool with isolated dependencies.
/// Plugins must be in subdirectories under the "plugins" folder for security and isolation.
/// </summary>
public class PluginLoader
{
    private readonly List<IPlugin> _plugins = [];
    private readonly ILogger<PluginLoader> _logger;

    /// <summary>
    /// Gets the loaded plugins.
    /// </summary>
    public IReadOnlyList<IPlugin> Plugins => _plugins.AsReadOnly();

    /// <summary>
    /// Initializes a new instance of the <see cref="PluginLoader"/> class.
    /// </summary>
    /// <param name="logger">Optional logger for diagnostic output. If null, logging is disabled.</param>
    public PluginLoader(ILogger<PluginLoader>? logger = null)
    {
        _logger = logger ?? NullLogger<PluginLoader>.Instance;
    }

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

        _logger.LogDebug(
            new EventId(LogEvents.PluginDiscoveryStarted, nameof(LogEvents.PluginDiscoveryStarted)),
            "Starting plugin discovery in directory: {PluginDirectory}",
            pluginDirectory);

        // Load from main plugin directory
        await LoadPluginsFromDirectoryAsync(pluginDirectory, validateSecurity: true);

        // Load from additional directories if specified
        if (additionalDirectories != null)
        {
            foreach (var additionalDir in additionalDirectories)
            {
                if (!string.IsNullOrWhiteSpace(additionalDir))
                {
                    _logger.LogDebug(
                        new EventId(LogEvents.PluginDiscoveryStarted, nameof(LogEvents.PluginDiscoveryStarted)),
                        "Loading plugins from additional directory: {AdditionalDirectory}",
                        additionalDir);
                    await LoadPluginsFromDirectoryAsync(additionalDir, validateSecurity: false);
                }
            }
        }

        _logger.LogInformation(
            new EventId(LogEvents.PluginDiscoveryCompleted, nameof(LogEvents.PluginDiscoveryCompleted)),
            "Plugin discovery completed. Loaded {PluginCount} plugins",
            _plugins.Count);
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
            _logger.LogDebug(
                new EventId(LogEvents.PluginLoaded, nameof(LogEvents.PluginLoaded)),
                "Registering plugin: {PluginName} v{PluginVersion}",
                plugin.Name,
                plugin.Version);
            _plugins.Add(plugin);
            await plugin.InitializeAsync();
            _logger.LogInformation(
                new EventId(LogEvents.PluginInitialized, nameof(LogEvents.PluginInitialized)),
                "Plugin initialized successfully: {PluginName}",
                plugin.Name);
        }
        else
        {
            _logger.LogDebug(
                new EventId(LogEvents.PluginLoaded, nameof(LogEvents.PluginLoaded)),
                "Plugin already registered, skipping: {PluginName}",
                plugin.Name);
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
        _logger.LogDebug(
            new EventId(LogEvents.PluginLoaded, nameof(LogEvents.PluginLoaded)),
            "Loading plugin assembly: {AssemblyPath}",
            assemblyPath);

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
            _logger.LogError(
                new EventId(LogEvents.PluginLoadFailed, nameof(LogEvents.PluginLoadFailed)),
                ex,
                "Failed to load types from plugin assembly: {AssemblyPath}",
                assemblyPath);
            if (ex.LoaderExceptions != null)
            {
                foreach (var loaderEx in ex.LoaderExceptions)
                {
                    if (loaderEx != null)
                    {
                        _logger.LogError(
                            new EventId(LogEvents.PluginLoadFailed, nameof(LogEvents.PluginLoadFailed)),
                            loaderEx,
                            "Loader exception detail");
                    }
                }
            }
            throw;
        }

        // Load plugins
        var pluginTypes = types.Where(t => typeof(IPlugin).IsAssignableFrom(t) && !t.IsInterface && !t.IsAbstract);

        foreach (var pluginType in pluginTypes)
        {
            _logger.LogTrace(
                new EventId(LogEvents.PluginLoaded, nameof(LogEvents.PluginLoaded)),
                "Found plugin type: {PluginType}",
                pluginType.FullName);

            if (Activator.CreateInstance(pluginType) is IPlugin plugin)
            {
                await RegisterPluginAsync(plugin);
            }
        }
    }
}