// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using CoseSignTool.Abstractions;
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

        // Log message templates
        public static readonly string LogDiscoveryStarted = "Starting plugin discovery in directory: {PluginDirectory}";
        public static readonly string LogAdditionalDirectory = "Loading plugins from additional directory: {AdditionalDirectory}";
        public static readonly string LogDiscoveryCompleted = "Plugin discovery completed. Loaded {PluginCount} plugins";
        public static readonly string LogRegisteringPlugin = "Registering plugin: {PluginName} v{PluginVersion}";
        public static readonly string LogPluginInitialized = "Plugin initialized successfully: {PluginName}";
        public static readonly string LogPluginAlreadyRegistered = "Plugin already registered, skipping: {PluginName}";
        public static readonly string LogLoadingAssembly = "Loading plugin assembly: {AssemblyPath}";
        public static readonly string LogTypeLoadFailed = "Failed to load types from plugin assembly: {AssemblyPath}";
        public static readonly string LogLoaderException = "Loader exception detail";
        public static readonly string LogFoundPluginType = "Found plugin type: {PluginType}";
    }

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

        Logger.LogDebug(
            LogEvents.PluginDiscoveryStartedEvent,
            ClassStrings.LogDiscoveryStarted,
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
                    Logger.LogDebug(
                        LogEvents.PluginDiscoveryStartedEvent,
                        ClassStrings.LogAdditionalDirectory,
                        additionalDir);
                    await LoadPluginsFromDirectoryAsync(additionalDir, validateSecurity: false);
                }
            }
        }

        Logger.LogInformation(
            LogEvents.PluginDiscoveryCompletedEvent,
            ClassStrings.LogDiscoveryCompleted,
            PluginsList.Count);
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
            Logger.LogDebug(
                LogEvents.PluginLoadedEvent,
                ClassStrings.LogRegisteringPlugin,
                plugin.Name,
                plugin.Version);
            PluginsList.Add(plugin);
            await plugin.InitializeAsync();
            Logger.LogInformation(
                LogEvents.PluginInitializedEvent,
                ClassStrings.LogPluginInitialized,
                plugin.Name);
        }
        else
        {
            Logger.LogDebug(
                LogEvents.PluginLoadedEvent,
                ClassStrings.LogPluginAlreadyRegistered,
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
        Logger.LogDebug(
            LogEvents.PluginLoadedEvent,
            ClassStrings.LogLoadingAssembly,
            assemblyPath);

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
            Logger.LogError(
                LogEvents.PluginLoadFailedEvent,
                ex,
                ClassStrings.LogTypeLoadFailed,
                assemblyPath);
            if (ex.LoaderExceptions != null)
            {
                foreach (var loaderEx in ex.LoaderExceptions)
                {
                    if (loaderEx != null)
                    {
                        Logger.LogError(
                            LogEvents.PluginLoadFailedEvent,
                            loaderEx,
                            ClassStrings.LogLoaderException);
                    }
                }
            }
            throw;
        }

        // Load plugins
        var pluginTypes = types.Where(t => typeof(IPlugin).IsAssignableFrom(t) && !t.IsInterface && !t.IsAbstract);

        foreach (var pluginType in pluginTypes)
        {
            Logger.LogTrace(
                LogEvents.PluginLoadedEvent,
                ClassStrings.LogFoundPluginType,
                pluginType.FullName);

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