// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Output;

/// <summary>
/// Defines the output format for command results.
/// </summary>
public enum OutputFormat
{
    /// <summary>
    /// Human-readable text output (default).
    /// </summary>
    Text,

    /// <summary>
    /// JSON formatted output.
    /// </summary>
    Json,

    /// <summary>
    /// XML formatted output.
    /// </summary>
    Xml,

    /// <summary>
    /// Minimal output (exit code only).
    /// </summary>
    Quiet
}
