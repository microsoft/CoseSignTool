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
        output.ToString().Should().Contain("Test message");
        output.ToString().Should().Contain("✓");
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
        error.ToString().Should().Contain("Error message");
        error.ToString().Should().Contain("✗");
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
        output.ToString().Should().Contain("Info message");
        output.ToString().Should().Contain("ℹ");
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
        output.ToString().Should().Contain("Warning message");
        output.ToString().Should().Contain("⚠");
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
        result.Should().Contain("Key");
        result.Should().Contain("Value");
        result.Should().Contain(":");
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
        result.Should().Contain("Test Section");
        result.Should().Contain("---");
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
        output.ToString().Should().Contain(Environment.NewLine);
    }

    [Fact]
    public void Constructor_WithNullWriters_UsesConsole()
    {
        // Act
        var formatter = new TextOutputFormatter();

        // Assert - should not throw
        formatter.Should().NotBeNull();
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
        lines.Should().HaveCount(3);
    }
}
