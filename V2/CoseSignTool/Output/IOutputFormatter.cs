// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Output;

/// <summary>
/// Interface for formatting command output in CoseSignTool.
/// This is an internal interface - plugins should not depend on it.
/// </summary>
public interface IOutputFormatter
{
    /// <summary>
    /// Writes an informational message.
    /// </summary>
    void WriteInfo(string message);

    /// <summary>
    /// Writes a success message.
    /// </summary>
    void WriteSuccess(string message);

    /// <summary>
    /// Writes a warning message.
    /// </summary>
    void WriteWarning(string message);

    /// <summary>
    /// Writes an error message.
    /// </summary>
    void WriteError(string message);

    /// <summary>
    /// Writes a key-value pair.
    /// </summary>
    void WriteKeyValue(string key, string value);

    /// <summary>
    /// Begins a named section in the output.
    /// </summary>
    void BeginSection(string title);

    /// <summary>
    /// Ends the current section.
    /// </summary>
    void EndSection();

    /// <summary>
    /// Flushes any buffered output.
    /// </summary>
    void Flush();
}