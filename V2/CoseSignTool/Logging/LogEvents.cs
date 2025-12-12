// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Logging;

/// <summary>
/// Defines event IDs for structured logging in the CoseSignTool application.
/// </summary>
/// <remarks>
/// Event ID ranges for CoseSignTool:
/// - 5000-5099: Plugin operations
/// - 6000-6099: Configuration operations
/// - 9000-9999: General/Infrastructure
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
    /// <summary>Plugin initialization failed.</summary>
    public const int PluginInitializationFailed = 5021;
    /// <summary>Plugin registered command provider.</summary>
    public const int PluginCommandProviderRegistered = 5030;
    /// <summary>Plugin assembly resolution.</summary>
    public const int PluginAssemblyResolution = 5040;

    // Configuration Operations (6000-6099)
    /// <summary>Configuration loaded.</summary>
    public const int ConfigurationLoaded = 6000;
    /// <summary>Configuration validation failed.</summary>
    public const int ConfigurationValidationFailed = 6001;
    /// <summary>Configuration value applied.</summary>
    public const int ConfigurationApplied = 6010;

    // General/Infrastructure (9000-9999)
    /// <summary>Operation started.</summary>
    public const int OperationStarted = 9000;
    /// <summary>Operation completed.</summary>
    public const int OperationCompleted = 9001;
    /// <summary>Unexpected exception.</summary>
    public const int UnexpectedException = 9900;
    /// <summary>Performance measurement.</summary>
    public const int PerformanceMetric = 9910;
}