// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Output;

/// <summary>
/// Interface for formatting command output.
/// </summary>
public interface IOutputFormatter
{
    /// <summary>
    /// Writes a success message to the console.
    /// </summary>
    /// <param name="message">The message to write.</param>
    void WriteSuccess(string message);

    /// <summary>
    /// Writes an error message to the console.
    /// </summary>
    /// <param name="message">The error message to write.</param>
    void WriteError(string message);

    /// <summary>
    /// Writes an informational message to the console.
    /// </summary>
    /// <param name="message">The message to write.</param>
    void WriteInfo(string message);

    /// <summary>
    /// Writes a warning message to the console.
    /// </summary>
    /// <param name="message">The warning message to write.</param>
    void WriteWarning(string message);

    /// <summary>
    /// Writes a key-value pair to the output.
    /// </summary>
    /// <param name="key">The key.</param>
    /// <param name="value">The value.</param>
    void WriteKeyValue(string key, string value);

    /// <summary>
    /// Begins a new output section.
    /// </summary>
    /// <param name="title">The section title.</param>
    void BeginSection(string title);

    /// <summary>
    /// Ends the current output section.
    /// </summary>
    void EndSection();

    /// <summary>
    /// Flushes any buffered output.
    /// </summary>
    void Flush();
}
