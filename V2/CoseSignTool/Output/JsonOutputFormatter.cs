// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Text.Json;
using System.Diagnostics.CodeAnalysis;

namespace CoseSignTool.Output;

/// <summary>
/// JSON-based output formatter.
/// </summary>
public class JsonOutputFormatter : IOutputFormatter
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public static readonly string TypeSuccess = "success";
        public static readonly string TypeError = "error";
        public static readonly string TypeInfo = "info";
        public static readonly string TypeWarning = "warning";
        public static readonly string TypeKeyValue = "keyvalue";
        public static readonly string TypeSectionStart = "section_start";
        public static readonly string TypeSectionEnd = "section_end";
    }

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
        Messages.Add(new { type = ClassStrings.TypeSuccess, message });
    }

    /// <inheritdoc/>
    public void WriteError(string message)
    {
        Messages.Add(new { type = ClassStrings.TypeError, message });
    }

    /// <inheritdoc/>
    public void WriteInfo(string message)
    {
        Messages.Add(new { type = ClassStrings.TypeInfo, message });
    }

    /// <inheritdoc/>
    public void WriteWarning(string message)
    {
        Messages.Add(new { type = ClassStrings.TypeWarning, message });
    }

    /// <inheritdoc/>
    public void WriteKeyValue(string key, string value)
    {
        Messages.Add(new { type = ClassStrings.TypeKeyValue, key, value });
    }

    /// <inheritdoc/>
    public void BeginSection(string title)
    {
        Messages.Add(new { type = ClassStrings.TypeSectionStart, title });
    }

    /// <inheritdoc/>
    public void EndSection()
    {
        Messages.Add(new { type = ClassStrings.TypeSectionEnd });
    }

    /// <inheritdoc/>
    public void WriteStructuredData<T>(T data) where T : class
    {
        // When structured data is provided, use it as the primary output
        StructuredData = data;
    }

    private object? StructuredData { get; set; }

    /// <inheritdoc/>
    public void Flush()
    {
        // If structured data was provided, output that instead of messages
        var outputObject = StructuredData ?? Messages;
        var json = JsonSerializer.Serialize(outputObject, new JsonSerializerOptions
        {
            WriteIndented = true,
            DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
        });
        Output.WriteLine(json);
    }
}