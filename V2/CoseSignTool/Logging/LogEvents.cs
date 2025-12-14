// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.Extensions.Logging;

namespace CoseSignTool.Logging;

/// <summary>
/// Defines event IDs for structured logging in the CoseSignTool application.
/// </summary>
/// <remarks>
/// Event ID ranges for CoseSignTool:
/// - 5000-5099: Plugin operations
/// </remarks>
public static class LogEvents
{
    // Plugin Operations (5000-5099)
    /// <summary>Plugin discovery started.</summary>
    public const int PluginDiscoveryStarted = 5000;
    /// <summary>Plugin discovery completed.</summary>
    public const int PluginDiscoveryCompleted = 5001;
    /// <summary>Plugin loaded successfully.</summary>
    public const int PluginLoaded = 5010;
    /// <summary>Plugin load failed.</summary>
    public const int PluginLoadFailed = 5011;
    /// <summary>Plugin initialized.</summary>
    public const int PluginInitialized = 5020;

    // Static EventId instances to avoid allocations on each log call
    /// <summary>EventId for plugin discovery started.</summary>
    public static readonly EventId PluginDiscoveryStartedEvent = new(PluginDiscoveryStarted, nameof(PluginDiscoveryStarted));
    /// <summary>EventId for plugin discovery completed.</summary>
    public static readonly EventId PluginDiscoveryCompletedEvent = new(PluginDiscoveryCompleted, nameof(PluginDiscoveryCompleted));
    /// <summary>EventId for plugin loaded.</summary>
    public static readonly EventId PluginLoadedEvent = new(PluginLoaded, nameof(PluginLoaded));
    /// <summary>EventId for plugin load failed.</summary>
    public static readonly EventId PluginLoadFailedEvent = new(PluginLoadFailed, nameof(PluginLoadFailed));
    /// <summary>EventId for plugin initialized.</summary>
    public static readonly EventId PluginInitializedEvent = new(PluginInitialized, nameof(PluginInitialized));
}