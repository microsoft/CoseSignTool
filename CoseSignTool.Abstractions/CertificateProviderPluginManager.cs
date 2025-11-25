// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Abstractions;

using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;

/// <summary>
/// Manages discovery, loading, and lifecycle of certificate provider plugins.
/// </summary>
public class CertificateProviderPluginManager
{
    private readonly Dictionary<string, ICertificateProviderPlugin> _providers = new();
    private readonly IPluginLogger? _logger;

    /// <summary>
    /// Gets the collection of loaded certificate provider plugins.
    /// </summary>
    public IReadOnlyDictionary<string, ICertificateProviderPlugin> Providers => _providers;

    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateProviderPluginManager"/> class.
    /// </summary>
    /// <param name="logger">Optional logger for diagnostic output.</param>
    public CertificateProviderPluginManager(IPluginLogger? logger = null)
    {
        _logger = logger;
    }

    /// <summary>
    /// Discovers and loads certificate provider plugins from the specified directory.
    /// </summary>
    /// <param name="pluginsDirectory">The directory to search for plugin assemblies.</param>
    /// <remarks>
    /// Searches for assemblies matching the pattern *.Plugin.dll and attempts to load
    /// any types implementing <see cref="ICertificateProviderPlugin"/>.
    /// </remarks>
    public void DiscoverAndLoadPlugins(string pluginsDirectory)
    {
        if (string.IsNullOrWhiteSpace(pluginsDirectory))
        {
            _logger?.LogVerbose("No plugins directory specified.");
            return;
        }

        if (!Directory.Exists(pluginsDirectory))
        {
            _logger?.LogVerbose($"Plugins directory does not exist: {pluginsDirectory}");
            return;
        }

        _logger?.LogVerbose($"Discovering certificate provider plugins in: {pluginsDirectory}");

        // Find all assemblies matching the plugin pattern
        string[] pluginFiles = Directory.GetFiles(pluginsDirectory, "*.Plugin.dll", SearchOption.AllDirectories);
        
        _logger?.LogVerbose($"Found {pluginFiles.Length} potential plugin assemblies.");

        foreach (string pluginFile in pluginFiles)
        {
            try
            {
                LoadPluginFromAssembly(pluginFile);
            }
            catch (Exception ex)
            {
                _logger?.LogWarning($"Failed to load plugin from {Path.GetFileName(pluginFile)}: {ex.Message}");
                _logger?.LogException(ex);
            }
        }

        _logger?.LogInformation($"Loaded {_providers.Count} certificate provider plugin(s).");
    }

    /// <summary>
    /// Loads certificate provider plugins from the specified assembly file.
    /// </summary>
    /// <param name="assemblyPath">Path to the assembly file to load plugins from.</param>
    public void LoadPluginFromAssembly(string assemblyPath)
    {
        if (!File.Exists(assemblyPath))
        {
            throw new FileNotFoundException($"Plugin assembly not found: {assemblyPath}", assemblyPath);
        }

        _logger?.LogVerbose($"Loading plugins from: {Path.GetFileName(assemblyPath)}");

        Assembly assembly = Assembly.LoadFrom(assemblyPath);
        
        // Find all types implementing ICertificateProviderPlugin
        Type[] types = assembly.GetTypes()
            .Where(t => typeof(ICertificateProviderPlugin).IsAssignableFrom(t) 
                        && !t.IsInterface 
                        && !t.IsAbstract)
            .ToArray();

        foreach (Type type in types)
        {
            try
            {
                ICertificateProviderPlugin? plugin = Activator.CreateInstance(type) as ICertificateProviderPlugin;
                if (plugin != null)
                {
                    RegisterPlugin(plugin);
                }
            }
            catch (Exception ex)
            {
                _logger?.LogWarning($"Failed to instantiate plugin {type.Name}: {ex.Message}");
                _logger?.LogException(ex);
            }
        }
    }

    /// <summary>
    /// Registers a certificate provider plugin instance.
    /// </summary>
    /// <param name="plugin">The plugin instance to register.</param>
    /// <exception cref="ArgumentException">Thrown when a plugin with the same name is already registered.</exception>
    public void RegisterPlugin(ICertificateProviderPlugin plugin)
    {
        if (plugin == null)
        {
            throw new ArgumentNullException(nameof(plugin));
        }

        string providerName = plugin.ProviderName?.ToLowerInvariant() ?? 
            throw new ArgumentException("Plugin provider name cannot be null or empty.", nameof(plugin));

        if (_providers.ContainsKey(providerName))
        {
            throw new ArgumentException($"A certificate provider plugin with name '{providerName}' is already registered.", nameof(plugin));
        }

        _providers[providerName] = plugin;
        _logger?.LogVerbose($"Registered certificate provider plugin: {providerName} - {plugin.Description}");
    }

    /// <summary>
    /// Gets a certificate provider plugin by name.
    /// </summary>
    /// <param name="providerName">The name of the provider to retrieve (case-insensitive).</param>
    /// <returns>The plugin instance, or null if not found.</returns>
    public ICertificateProviderPlugin? GetProvider(string providerName)
    {
        if (string.IsNullOrWhiteSpace(providerName))
        {
            return null;
        }

        string normalizedName = providerName.ToLowerInvariant();
        return _providers.TryGetValue(normalizedName, out ICertificateProviderPlugin? plugin) ? plugin : null;
    }

    /// <summary>
    /// Merges certificate provider options into a base options dictionary.
    /// </summary>
    /// <param name="baseOptions">The base options dictionary to merge into.</param>
    /// <param name="provider">The certificate provider plugin whose options should be merged.</param>
    /// <returns>A new dictionary containing both base options and provider options.</returns>
    public static Dictionary<string, string> MergeProviderOptions(
        Dictionary<string, string> baseOptions,
        ICertificateProviderPlugin provider)
    {
        if (baseOptions == null)
        {
            throw new ArgumentNullException(nameof(baseOptions));
        }

        if (provider == null)
        {
            throw new ArgumentNullException(nameof(provider));
        }

        Dictionary<string, string> merged = new Dictionary<string, string>(baseOptions);
        
        // Add the cert-provider option
        merged["--cert-provider"] = "cert-provider";
        merged["-cp"] = "cert-provider";

        // Merge provider-specific options
        IDictionary<string, string> providerOptions = provider.GetProviderOptions();
        foreach (KeyValuePair<string, string> kvp in providerOptions)
        {
            if (merged.ContainsKey(kvp.Key))
            {
                throw new InvalidOperationException(
                    $"Certificate provider plugin '{provider.ProviderName}' defines option '{kvp.Key}' " +
                    $"which conflicts with an existing command option.");
            }
            
            merged[kvp.Key] = kvp.Value;
        }

        return merged;
    }

    /// <summary>
    /// Gets the combined options from all registered providers for help text.
    /// </summary>
    /// <param name="baseOptions">The base command options.</param>
    /// <returns>A dictionary with all options including the cert-provider option.</returns>
    public Dictionary<string, string> GetAllOptions(Dictionary<string, string> baseOptions)
    {
        Dictionary<string, string> allOptions = new Dictionary<string, string>(baseOptions);
        
        // Add the cert-provider option
        allOptions["--cert-provider"] = "cert-provider";
        allOptions["-cp"] = "cert-provider";

        return allOptions;
    }

    /// <summary>
    /// Gets usage documentation for all registered certificate provider plugins.
    /// </summary>
    /// <returns>A formatted string containing usage information for all providers.</returns>
    public string GetProvidersUsageDocumentation()
    {
        if (_providers.Count == 0)
        {
            return "No certificate provider plugins are currently loaded.";
        }

        System.Text.StringBuilder sb = new System.Text.StringBuilder();
        sb.AppendLine("Certificate Providers:");
        sb.AppendLine("======================");
        sb.AppendLine();
        sb.AppendLine("Available certificate provider plugins:");
        
        foreach (KeyValuePair<string, ICertificateProviderPlugin> kvp in _providers.OrderBy(p => p.Key))
        {
            sb.AppendLine($"  {kvp.Key,-30} {kvp.Value.Description}");
        }

        sb.AppendLine();
        sb.AppendLine("To use a certificate provider, specify the --cert-provider option:");
        sb.AppendLine("  --cert-provider <provider-name>");
        sb.AppendLine("  -cp <provider-name>");
        sb.AppendLine();
        sb.AppendLine("For detailed information about a specific provider, use:");
        sb.AppendLine("  CoseSignTool help <provider-name>");
        sb.AppendLine();

        foreach (KeyValuePair<string, ICertificateProviderPlugin> kvp in _providers.OrderBy(p => p.Key))
        {
            sb.AppendLine(kvp.Value.GetUsageDocumentation());
            sb.AppendLine();
        }

        return sb.ToString();
    }
}
