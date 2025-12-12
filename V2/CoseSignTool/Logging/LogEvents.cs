// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

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
}