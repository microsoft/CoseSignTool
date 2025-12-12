// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Text.Json;

namespace CoseSignTool.Output;

/// <summary>
/// JSON-based output formatter.
/// </summary>
public class JsonOutputFormatter : IOutputFormatter
{
    private readonly TextWriter Output;
    private readonly List<object> Messages = [];

    /// <summary>
    /// Initializes a new instance of the <see cref="JsonOutputFormatter"/> class.
    /// </summary>
    /// <param name="output">The output writer (defaults to Console.Out).</param>
    public JsonOutputFormatter(TextWriter? output = null)
    {
        Output = output ?? Console.Out;
    }

    /// <inheritdoc/>
    public void WriteSuccess(string message)
    {
        Messages.Add(new { type = "success", message });
    }

    /// <inheritdoc/>
    public void WriteError(string message)
    {
        Messages.Add(new { type = "error", message });
    }

    /// <inheritdoc/>
    public void WriteInfo(string message)
    {
        Messages.Add(new { type = "info", message });
    }

    /// <inheritdoc/>
    public void WriteWarning(string message)
    {
        Messages.Add(new { type = "warning", message });
    }

    /// <inheritdoc/>
    public void WriteKeyValue(string key, string value)
    {
        Messages.Add(new { type = "keyvalue", key, value });
    }

    /// <inheritdoc/>
    public void BeginSection(string title)
    {
        Messages.Add(new { type = "section_start", title });
    }

    /// <inheritdoc/>
    public void EndSection()
    {
        Messages.Add(new { type = "section_end" });
    }

    /// <inheritdoc/>
    public void Flush()
    {
        var json = JsonSerializer.Serialize(Messages, new JsonSerializerOptions
        {
            WriteIndented = true
        });
        Output.WriteLine(json);
    }
}