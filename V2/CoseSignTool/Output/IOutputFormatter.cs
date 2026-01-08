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
    /// <param name="message">The message to write.</param>
    void WriteInfo(string message);

    /// <summary>
    /// Writes a success message.
    /// </summary>
    /// <param name="message">The message to write.</param>
    void WriteSuccess(string message);

    /// <summary>
    /// Writes a warning message.
    /// </summary>
    /// <param name="message">The message to write.</param>
    void WriteWarning(string message);

    /// <summary>
    /// Writes an error message.
    /// </summary>
    /// <param name="message">The message to write.</param>
    void WriteError(string message);

    /// <summary>
    /// Writes a key-value pair.
    /// </summary>
    /// <param name="key">The key.</param>
    /// <param name="value">The value.</param>
    void WriteKeyValue(string key, string value);

    /// <summary>
    /// Begins a named section in the output.
    /// </summary>
    /// <param name="title">The section title.</param>
    void BeginSection(string title);

    /// <summary>
    /// Ends the current section.
    /// </summary>
    void EndSection();

    /// <summary>
    /// Writes a structured object as the primary output.
    /// Used for structured output formats like JSON to provide rich data.
    /// Text formatters may ignore this and rely on key-value pairs instead.
    /// </summary>
    /// <typeparam name="T">The type of the structured data.</typeparam>
    /// <param name="data">The structured data object.</param>
    void WriteStructuredData<T>(T data) where T : class;

    /// <summary>
    /// Flushes any buffered output.
    /// </summary>
    void Flush();
}