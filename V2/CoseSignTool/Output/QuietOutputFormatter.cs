// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Output;

/// <summary>
/// Quiet output formatter that suppresses all output.
/// </summary>
public class QuietOutputFormatter : IOutputFormatter
{
    /// <inheritdoc/>
    public void WriteSuccess(string message)
    {
        // Suppress output
    }

    /// <inheritdoc/>
    public void WriteError(string message)
    {
        // Suppress output
    }

    /// <inheritdoc/>
    public void WriteInfo(string message)
    {
        // Suppress output
    }

    /// <inheritdoc/>
    public void WriteWarning(string message)
    {
        // Suppress output
    }

    /// <inheritdoc/>
    public void WriteKeyValue(string key, string value)
    {
        // Suppress output
    }

    /// <inheritdoc/>
    public void BeginSection(string title)
    {
        // Suppress output
    }

    /// <inheritdoc/>
    public void EndSection()
    {
        // Suppress output
    }

    /// <inheritdoc/>
    public void Flush()
    {
        // No output
    }
}
