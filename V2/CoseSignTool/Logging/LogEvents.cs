// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Logging;

using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.Logging;

/// <summary>
/// Defines event IDs for structured logging in the CoseSignTool application.
/// </summary>
/// <remarks>
/// Event ID ranges for CoseSignTool:
/// - 5000-5099: Plugin operations
/// - 5100-5199: Command operations (sign, verify, inspect)
/// - 5200-5299: I/O operations
/// </remarks>
[ExcludeFromCodeCoverage]
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

    // Command Operations (5100-5199)
    /// <summary>Sign command started.</summary>
    public const int SignCommandStarted = 5100;
    /// <summary>Sign command completed.</summary>
    public const int SignCommandCompleted = 5101;
    /// <summary>Sign command failed.</summary>
    public const int SignCommandFailed = 5102;
    /// <summary>Verify command started.</summary>
    public const int VerifyCommandStarted = 5110;
    /// <summary>Verify command completed.</summary>
    public const int VerifyCommandCompleted = 5111;
    /// <summary>Verify command failed.</summary>
    public const int VerifyCommandFailed = 5112;
    /// <summary>Inspect command started.</summary>
    public const int InspectCommandStarted = 5120;
    /// <summary>Inspect command completed.</summary>
    public const int InspectCommandCompleted = 5121;
    /// <summary>Inspect command failed.</summary>
    public const int InspectCommandFailed = 5122;

    // I/O Operations (5200-5299)
    /// <summary>Reading from stdin.</summary>
    public const int ReadingFromStdin = 5200;
    /// <summary>Reading from file.</summary>
    public const int ReadingFromFile = 5201;
    /// <summary>Writing to stdout.</summary>
    public const int WritingToStdout = 5210;
    /// <summary>Writing to file.</summary>
    public const int WritingToFile = 5211;
    /// <summary>Stdin timeout.</summary>
    public const int StdinTimeout = 5220;

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

    // Command Operation EventIds
    /// <summary>EventId for sign command started.</summary>
    public static readonly EventId SignCommandStartedEvent = new(SignCommandStarted, nameof(SignCommandStarted));
    /// <summary>EventId for sign command completed.</summary>
    public static readonly EventId SignCommandCompletedEvent = new(SignCommandCompleted, nameof(SignCommandCompleted));
    /// <summary>EventId for sign command failed.</summary>
    public static readonly EventId SignCommandFailedEvent = new(SignCommandFailed, nameof(SignCommandFailed));
    /// <summary>EventId for verify command started.</summary>
    public static readonly EventId VerifyCommandStartedEvent = new(VerifyCommandStarted, nameof(VerifyCommandStarted));
    /// <summary>EventId for verify command completed.</summary>
    public static readonly EventId VerifyCommandCompletedEvent = new(VerifyCommandCompleted, nameof(VerifyCommandCompleted));
    /// <summary>EventId for verify command failed.</summary>
    public static readonly EventId VerifyCommandFailedEvent = new(VerifyCommandFailed, nameof(VerifyCommandFailed));
    /// <summary>EventId for inspect command started.</summary>
    public static readonly EventId InspectCommandStartedEvent = new(InspectCommandStarted, nameof(InspectCommandStarted));
    /// <summary>EventId for inspect command completed.</summary>
    public static readonly EventId InspectCommandCompletedEvent = new(InspectCommandCompleted, nameof(InspectCommandCompleted));
    /// <summary>EventId for inspect command failed.</summary>
    public static readonly EventId InspectCommandFailedEvent = new(InspectCommandFailed, nameof(InspectCommandFailed));

    // I/O Operation EventIds
    /// <summary>EventId for reading from stdin.</summary>
    public static readonly EventId ReadingFromStdinEvent = new(ReadingFromStdin, nameof(ReadingFromStdin));
    /// <summary>EventId for reading from file.</summary>
    public static readonly EventId ReadingFromFileEvent = new(ReadingFromFile, nameof(ReadingFromFile));
    /// <summary>EventId for writing to stdout.</summary>
    public static readonly EventId WritingToStdoutEvent = new(WritingToStdout, nameof(WritingToStdout));
    /// <summary>EventId for writing to file.</summary>
    public static readonly EventId WritingToFileEvent = new(WritingToFile, nameof(WritingToFile));
    /// <summary>EventId for stdin timeout.</summary>
    public static readonly EventId StdinTimeoutEvent = new(StdinTimeout, nameof(StdinTimeout));
}