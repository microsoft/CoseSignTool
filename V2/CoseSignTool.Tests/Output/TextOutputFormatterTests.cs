// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSignTool.Output;

namespace CoseSignTool.Tests.Output;

/// <summary>
/// Tests for the TextOutputFormatter class.
/// </summary>
public class TextOutputFormatterTests
{
    [Fact]
    public void WriteSuccess_WritesToOutput()
    {
        // Arrange
        using var output = new StringWriter();
        var formatter = new TextOutputFormatter(output);

        // Act
        formatter.WriteSuccess("Test message");

        // Assert
        Assert.Contains("Test message", output.ToString());
        Assert.Contains("✓", output.ToString());
    }

    [Fact]
    public void WriteError_WritesToError()
    {
        // Arrange
        using var error = new StringWriter();
        var formatter = new TextOutputFormatter(error: error);

        // Act
        formatter.WriteError("Error message");

        // Assert
        Assert.Contains("Error message", error.ToString());
        Assert.Contains("✗", error.ToString());
    }

    [Fact]
    public void WriteInfo_WritesToOutput()
    {
        // Arrange
        using var output = new StringWriter();
        var formatter = new TextOutputFormatter(output);

        // Act
        formatter.WriteInfo("Info message");

        // Assert
        Assert.Contains("Info message", output.ToString());
        Assert.Contains("ℹ", output.ToString());
    }

    [Fact]
    public void WriteWarning_WritesToOutput()
    {
        // Arrange
        using var output = new StringWriter();
        var formatter = new TextOutputFormatter(output);

        // Act
        formatter.WriteWarning("Warning message");

        // Assert
        Assert.Contains("Warning message", output.ToString());
        Assert.Contains("⚠", output.ToString());
    }

    [Fact]
    public void WriteKeyValue_FormatsCorrectly()
    {
        // Arrange
        using var output = new StringWriter();
        var formatter = new TextOutputFormatter(output);

        // Act
        formatter.WriteKeyValue("Key", "Value");

        // Assert
        var result = output.ToString();
        Assert.Contains("Key", result);
        Assert.Contains("Value", result);
        Assert.Contains(":", result);
    }

    [Fact]
    public void BeginSection_WritesTitle()
    {
        // Arrange
        using var output = new StringWriter();
        var formatter = new TextOutputFormatter(output);

        // Act
        formatter.BeginSection("Test Section");

        // Assert
        var result = output.ToString();
        Assert.Contains("Test Section", result);
        Assert.Contains("---", result);
    }

    [Fact]
    public void EndSection_WritesNewLine()
    {
        // Arrange
        using var output = new StringWriter();
        var formatter = new TextOutputFormatter(output);

        // Act
        formatter.EndSection();

        // Assert
        Assert.Contains(Environment.NewLine, output.ToString());
    }

    [Fact]
    public void Constructor_WithNullWriters_UsesConsole()
    {
        // Act
        var formatter = new TextOutputFormatter();

        // Assert - should not throw
        Assert.NotNull(formatter);
    }

    [Fact]
    public void MultipleWrites_ProduceMultipleLines()
    {
        // Arrange
        using var output = new StringWriter();
        var formatter = new TextOutputFormatter(output);

        // Act
        formatter.WriteSuccess("Line 1");
        formatter.WriteInfo("Line 2");
        formatter.WriteWarning("Line 3");

        // Assert
        var lines = output.ToString().Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries);
        Assert.Equal(3, lines.Count());
    }
}
