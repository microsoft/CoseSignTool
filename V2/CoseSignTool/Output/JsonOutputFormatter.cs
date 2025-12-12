// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Text.Json;

namespace CoseSignTool.Output;

/// <summary>
/// JSON-based output formatter.
/// </summary>
public class JsonOutputFormatter : IOutputFormatter
{
    private readonly TextWriter _output;
    private readonly List<object> _messages = [];

    /// <summary>
    /// Initializes a new instance of the <see cref="JsonOutputFormatter"/> class.
    /// </summary>
    /// <param name="output">The output writer (defaults to Console.Out).</param>
    public JsonOutputFormatter(TextWriter? output = null)
    {
        _output = output ?? Console.Out;
    }

    /// <inheritdoc/>
    public void WriteSuccess(string message)
    {
        _messages.Add(new { type = "success", message });
    }

    /// <inheritdoc/>
    public void WriteError(string message)
    {
        _messages.Add(new { type = "error", message });
    }

    /// <inheritdoc/>
    public void WriteInfo(string message)
    {
        _messages.Add(new { type = "info", message });
    }

    /// <inheritdoc/>
    public void WriteWarning(string message)
    {
        _messages.Add(new { type = "warning", message });
    }

    /// <inheritdoc/>
    public void WriteKeyValue(string key, string value)
    {
        _messages.Add(new { type = "keyvalue", key, value });
    }

    /// <inheritdoc/>
    public void BeginSection(string title)
    {
        _messages.Add(new { type = "section_start", title });
    }

    /// <inheritdoc/>
    public void EndSection()
    {
        _messages.Add(new { type = "section_end" });
    }

    /// <inheritdoc/>
    public void Flush()
    {
        var json = JsonSerializer.Serialize(_messages, new JsonSerializerOptions
        {
            WriteIndented = true
        });
        _output.WriteLine(json);
    }
}
