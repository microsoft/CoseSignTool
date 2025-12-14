// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Output;

/// <summary>
/// Text-based output formatter for console output.
/// </summary>
public class TextOutputFormatter : IOutputFormatter
{
    /// <summary>
    /// String constants specific to this class.
    /// </summary>
    internal static class ClassStrings
    {
        public static readonly string SuccessPrefix = "✓ ";
        public static readonly string ErrorPrefix = "✗ ";
        public static readonly string InfoPrefix = "ℹ ";
        public static readonly string WarningPrefix = "⚠ ";
        public static readonly string KeyValueFormat = "  {0}: {1}";
    }

    private readonly TextWriter Output;
    private readonly TextWriter Error;

    /// <summary>
    /// Initializes a new instance of the <see cref="TextOutputFormatter"/> class.
    /// </summary>
    /// <param name="output">The output writer (defaults to Console.Out).</param>
    /// <param name="error">The error writer (defaults to Console.Error).</param>
    public TextOutputFormatter(TextWriter? output = null, TextWriter? error = null)
    {
        Output = output ?? Console.Out;
        Error = error ?? Console.Error;
    }

    /// <inheritdoc/>
    public void WriteSuccess(string message)
    {
        Output.WriteLine(ClassStrings.SuccessPrefix + message);
    }

    /// <inheritdoc/>
    public void WriteError(string message)
    {
        Error.WriteLine(ClassStrings.ErrorPrefix + message);
    }

    /// <inheritdoc/>
    public void WriteInfo(string message)
    {
        Output.WriteLine(ClassStrings.InfoPrefix + message);
    }

    /// <inheritdoc/>
    public void WriteWarning(string message)
    {
        Output.WriteLine(ClassStrings.WarningPrefix + message);
    }

    /// <inheritdoc/>
    public void WriteKeyValue(string key, string value)
    {
        Output.WriteLine(string.Format(ClassStrings.KeyValueFormat, key, value));
    }

    /// <inheritdoc/>
    public void BeginSection(string title)
    {
        Output.WriteLine();
        Output.WriteLine(title);
        Output.WriteLine(new string('-', title.Length));
    }

    /// <inheritdoc/>
    public void EndSection()
    {
        Output.WriteLine();
    }

    /// <inheritdoc/>
    public void WriteStructuredData<T>(T data) where T : class
    {
        // Text formatter ignores structured data - uses key-value output instead
    }

    /// <inheritdoc/>
    public void Flush()
    {
        Output.Flush();
    }
}