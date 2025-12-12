// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Output;

/// <summary>
/// Factory for creating output formatters.
/// </summary>
public static class OutputFormatterFactory
{
    /// <summary>
    /// Creates an output formatter based on the specified format.
    /// </summary>
    /// <param name="format">The output format.</param>
    /// <param name="output">Optional output writer.</param>
    /// <param name="error">Optional error writer.</param>
    /// <returns>An instance of <see cref="IOutputFormatter"/>.</returns>
    public static IOutputFormatter Create(OutputFormat format, TextWriter? output = null, TextWriter? error = null)
    {
        return format switch
        {
            OutputFormat.Json => new JsonOutputFormatter(output),
            OutputFormat.Xml => new XmlOutputFormatter(output),
            OutputFormat.Text => new TextOutputFormatter(output, error),
            OutputFormat.Quiet => new QuietOutputFormatter(),
            _ => throw new ArgumentException($"Unknown output format: {format}", nameof(format))
        };
    }
}