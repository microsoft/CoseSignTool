// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Configuration;

using Microsoft.Extensions.Configuration;

/// <summary>
/// Provides a fluent API for building application configuration from multiple sources.
/// </summary>
public class ConfigurationLoader
{
    private readonly List<Action<IConfigurationBuilder>> BuilderActions = [];

    /// <summary>
    /// Adds environment variables to the configuration with an optional prefix.
    /// </summary>
    /// <param name="prefix">Optional prefix to filter environment variables.</param>
    /// <returns>The configuration loader for chaining.</returns>
    public ConfigurationLoader AddEnvironmentVariables(string? prefix = null)
    {
        BuilderActions.Add(builder =>
        {
            if (string.IsNullOrEmpty(prefix))
            {
                builder.AddEnvironmentVariables();
            }
            else
            {
                builder.AddEnvironmentVariables(prefix);
            }
        });
        return this;
    }

    /// <summary>
    /// Adds an in-memory collection of key-value pairs to the configuration.
    /// </summary>
    /// <param name="initialData">The key-value pairs to add.</param>
    /// <returns>The configuration loader for chaining.</returns>
    public ConfigurationLoader AddInMemoryCollection(IEnumerable<KeyValuePair<string, string?>> initialData)
    {
        BuilderActions.Add(builder => builder.AddInMemoryCollection(initialData));
        return this;
    }

    /// <summary>
    /// Builds the configuration from all registered sources.
    /// </summary>
    /// <returns>The built configuration root.</returns>
    public IConfigurationRoot Build()
    {
        var builder = new ConfigurationBuilder();

        foreach (var action in BuilderActions)
        {
            action(builder);
        }

        return builder.Build();
    }
}