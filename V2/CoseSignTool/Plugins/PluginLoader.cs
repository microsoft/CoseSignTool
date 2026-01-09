// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Plugins;

using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using CoseSignTool.Abstractions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Loads and manages plugins for CoseSignTool with isolated dependencies.
/// Plugins must be in subdirectories under the "plugins" folder for security and isolation.
/// </summary>
public partial class PluginLoader
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public static readonly string PluginsDirectoryName = "plugins";
        public static readonly string PluginFileSuffix = "*.Plugin.dll";

        // Error messages
        public static readonly string ErrorEmptyPluginDirectory = string.Concat(
            "Plugin loading is only allowed from the 'plugins' subdirectory. ",
            "Attempted to load from an empty or null directory path.");
        public static readonly string ErrorUnauthorizedPluginDirectory = string.Concat(
            "Plugin loading is only allowed from the 'plugins' subdirectory. ",
            "Attempted to load from: '{0}', but only '{1}' is authorized.");
    }

    #region LoggerMessage methods

    [LoggerMessage(
        EventId = 5001,
        Level = LogLevel.Debug,
        Message = "Starting plugin discovery in directory: {PluginDirectory}")]
    private partial void LogDiscoveryStarted(string pluginDirectory);

    [LoggerMessage(
        EventId = 5002,
        Level = LogLevel.Debug,
        Message = "Loading plugins from additional directory: {AdditionalDirectory}")]
    private partial void LogAdditionalDirectory(string additionalDirectory);

    [LoggerMessage(
        EventId = 5003,
        Level = LogLevel.Information,
        Message = "Plugin discovery completed. Loaded {PluginCount} plugins")]
    private partial void LogDiscoveryCompleted(int pluginCount);

    [LoggerMessage(
        EventId = 5004,
        Level = LogLevel.Debug,
        Message = "Registering plugin: {PluginName} v{PluginVersion}")]
    private partial void LogRegisteringPlugin(string pluginName, string pluginVersion);

    [LoggerMessage(
        EventId = 5005,
        Level = LogLevel.Information,
        Message = "Plugin initialized successfully: {PluginName}")]
    private partial void LogPluginInitialized(string pluginName);

    [LoggerMessage(
        EventId = 5006,
        Level = LogLevel.Debug,
        Message = "Plugin already registered, skipping: {PluginName}")]
    private partial void LogPluginAlreadyRegistered(string pluginName);

    [LoggerMessage(
        EventId = 5007,
        Level = LogLevel.Debug,
        Message = "Loading plugin assembly: {AssemblyPath}")]
    private partial void LogLoadingAssembly(string assemblyPath);

    [LoggerMessage(
        EventId = 5008,
        Level = LogLevel.Error,
        Message = "Failed to load types from plugin assembly: {AssemblyPath}")]
    private partial void LogTypeLoadFailed(Exception ex, string assemblyPath);

    [LoggerMessage(
        EventId = 5009,
        Level = LogLevel.Error,
        Message = "Loader exception detail")]
    private partial void LogLoaderException(Exception ex);

    [LoggerMessage(
        EventId = 5010,
        Level = LogLevel.Trace,
        Message = "Found plugin type: {PluginType}")]
    private partial void LogFoundPluginType(string? pluginType);

    #endregion

    private readonly List<IPlugin> PluginsList = [];
    private readonly ILogger<PluginLoader> Logger;

    /// <summary>
    /// Gets or sets the writer used for warning output during plugin loading.
    /// Defaults to <see cref="Console.Error"/>.
    /// </summary>
    public TextWriter StandardError { get; set; } = Console.Error;

    /// <summary>
    /// Gets the loaded plugins.
    /// </summary>
    public IReadOnlyList<IPlugin> Plugins => PluginsList.AsReadOnly();

    /// <summary>
    /// Initializes a new instance of the <see cref="PluginLoader"/> class.
    /// </summary>
    /// <param name="logger">Optional logger for diagnostic output. If null, logging is disabled.</param>
    public PluginLoader(ILogger<PluginLoader>? logger = null)
    {
        Logger = logger ?? NullLogger<PluginLoader>.Instance;
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

        LogDiscoveryStarted(pluginDirectory);

        // Load from main plugin directory
        await LoadPluginsFromDirectoryAsync(pluginDirectory, validateSecurity: true);

        // Load from additional directories if specified
        if (additionalDirectories != null)
        {
            foreach (var additionalDir in additionalDirectories)
            {
                if (!string.IsNullOrWhiteSpace(additionalDir))
                {
                    LogAdditionalDirectory(additionalDir);
                    await LoadPluginsFromDirectoryAsync(additionalDir, validateSecurity: false);
                }
            }
        }

        LogDiscoveryCompleted(PluginsList.Count);
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

        if (!PluginsList.Any(p => p.Name == plugin.Name))
        {
            LogRegisteringPlugin(plugin.Name, plugin.Version);
            PluginsList.Add(plugin);
            await plugin.InitializeAsync();
            LogPluginInitialized(plugin.Name);
        }
        else
        {
            LogPluginAlreadyRegistered(plugin.Name);
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
            throw new UnauthorizedAccessException(ClassStrings.ErrorEmptyPluginDirectory);
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

        string authorizedPluginsDirectory = Path.Combine(executableDirectory, ClassStrings.PluginsDirectoryName);

        // Normalize paths for comparison
        string normalizedPluginDirectory = Path.GetFullPath(pluginDirectory)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        string normalizedAuthorizedDirectory = Path.GetFullPath(authorizedPluginsDirectory)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);

        if (!string.Equals(normalizedPluginDirectory, normalizedAuthorizedDirectory, StringComparison.OrdinalIgnoreCase))
        {
            throw new UnauthorizedAccessException(
                string.Format(ClassStrings.ErrorUnauthorizedPluginDirectory, normalizedPluginDirectory, normalizedAuthorizedDirectory));
        }
    }

    private async Task LoadPluginFromSubdirectoryAsync(string subdirectory)
    {
        // Look for plugin DLLs (*.Plugin.dll naming convention)
        var pluginFiles = Directory.GetFiles(subdirectory, ClassStrings.PluginFileSuffix, SearchOption.TopDirectoryOnly);

        foreach (var pluginFile in pluginFiles)
        {
            await LoadPluginWithContextAsync(pluginFile, subdirectory);
        }
    }

    private async Task LoadPluginWithContextAsync(string assemblyPath, string pluginDirectory)
    {
        LogLoadingAssembly(assemblyPath);

        // Create isolated AssemblyLoadContext for this plugin
        var loadContext = new PluginLoadContext(assemblyPath, pluginDirectory, StandardError);
        var assembly = loadContext.LoadFromAssemblyPath(assemblyPath);
        Type[] types;
        try
        {
            types = GetAssemblyTypes(assembly);
        }
        catch (ReflectionTypeLoadException ex)
        {
            LogTypeLoadFailed(ex, assemblyPath);
            if (ex.LoaderExceptions != null)
            {
                foreach (var loaderEx in ex.LoaderExceptions)
                {
                    if (loaderEx != null)
                    {
                        LogLoaderException(loaderEx);
                    }
                }
            }
            throw;
        }

        // Load plugins
        var pluginTypes = types.Where(t => typeof(IPlugin).IsAssignableFrom(t) && !t.IsInterface && !t.IsAbstract);

        foreach (var pluginType in pluginTypes)
        {
            LogFoundPluginType(pluginType.FullName);

            if (Activator.CreateInstance(pluginType) is IPlugin plugin)
            {
                await RegisterPluginAsync(plugin);
            }
        }
    }

    /// <summary>
    /// Gets all types from the specified assembly.
    /// </summary>
    /// <param name="assembly">The assembly to inspect.</param>
    /// <returns>All types in the assembly.</returns>
    protected virtual Type[] GetAssemblyTypes(Assembly assembly)
    {
        return assembly.GetTypes();
    }
}