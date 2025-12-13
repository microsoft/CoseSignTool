// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Output;

/// <summary>
/// Text-based output formatter for console output.
/// </summary>
public class TextOutputFormatter : IOutputFormatter
{
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
        Output.WriteLine($"✓ {message}");
    }

    /// <inheritdoc/>
    public void WriteError(string message)
    {
        Error.WriteLine($"✗ {message}");
    }

    /// <inheritdoc/>
    public void WriteInfo(string message)
    {
        Output.WriteLine($"ℹ {message}");
    }

    /// <inheritdoc/>
    public void WriteWarning(string message)
    {
        Output.WriteLine($"⚠ {message}");
    }

    /// <inheritdoc/>
    public void WriteKeyValue(string key, string value)
    {
        Output.WriteLine($"  {key}: {value}");
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