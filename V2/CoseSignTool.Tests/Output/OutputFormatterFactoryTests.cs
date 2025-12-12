// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSignTool.Output;

namespace CoseSignTool.Tests.Output;

/// <summary>
/// Tests for the OutputFormatterFactory class.
/// </summary>
public class OutputFormatterFactoryTests
{
    [Fact]
    public void Create_WithTextFormat_ReturnsTextFormatter()
    {
        // Act
        var formatter = OutputFormatterFactory.Create(OutputFormat.Text);

        // Assert
        Assert.IsType<TextOutputFormatter>(formatter);
    }

    [Fact]
    public void Create_WithJsonFormat_ReturnsJsonFormatter()
    {
        // Act
        var formatter = OutputFormatterFactory.Create(OutputFormat.Json);

        // Assert
        Assert.IsType<JsonOutputFormatter>(formatter);
    }

    [Fact]
    public void Create_WithQuietFormat_ReturnsQuietFormatter()
    {
        // Act
        var formatter = OutputFormatterFactory.Create(OutputFormat.Quiet);

        // Assert
        Assert.IsType<QuietOutputFormatter>(formatter);
    }

    [Fact]
    public void Create_WithInvalidFormat_ThrowsArgumentException()
    {
        // Act
        var act = () => OutputFormatterFactory.Create((OutputFormat)999);

        // Assert
        Assert.Throws<ArgumentException>(act)
            ;
    }

    [Fact]
    public void Create_WithCustomWriters_PassesThemThrough()
    {
        // Arrange
        using var output = new StringWriter();
        using var error = new StringWriter();

        // Act
        var formatter = OutputFormatterFactory.Create(OutputFormat.Text, output, error);

        // Assert
        Assert.IsType<TextOutputFormatter>(formatter);
    }
}
