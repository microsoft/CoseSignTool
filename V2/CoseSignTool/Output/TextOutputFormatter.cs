// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Output;

/// <summary>
/// Text-based output formatter for console output.
/// </summary>
public class TextOutputFormatter : IOutputFormatter
{
    private readonly TextWriter _output;
    private readonly TextWriter _error;

    /// <summary>
    /// Initializes a new instance of the <see cref="TextOutputFormatter"/> class.
    /// </summary>
    /// <param name="output">The output writer (defaults to Console.Out).</param>
    /// <param name="error">The error writer (defaults to Console.Error).</param>
    public TextOutputFormatter(TextWriter? output = null, TextWriter? error = null)
    {
        _output = output ?? Console.Out;
        _error = error ?? Console.Error;
    }

    /// <inheritdoc/>
    public void WriteSuccess(string message)
    {
        _output.WriteLine($"✓ {message}");
    }

    /// <inheritdoc/>
    public void WriteError(string message)
    {
        _error.WriteLine($"✗ {message}");
    }

    /// <inheritdoc/>
    public void WriteInfo(string message)
    {
        _output.WriteLine($"ℹ {message}");
    }

    /// <inheritdoc/>
    public void WriteWarning(string message)
    {
        _output.WriteLine($"⚠ {message}");
    }

    /// <inheritdoc/>
    public void WriteKeyValue(string key, string value)
    {
        _output.WriteLine($"  {key}: {value}");
    }

    /// <inheritdoc/>
    public void BeginSection(string title)
    {
        _output.WriteLine();
        _output.WriteLine(title);
        _output.WriteLine(new string('-', title.Length));
    }

    /// <inheritdoc/>
    public void EndSection()
    {
        _output.WriteLine();
    }

    /// <inheritdoc/>
    public void Flush()
    {
        _output.Flush();
    }
}