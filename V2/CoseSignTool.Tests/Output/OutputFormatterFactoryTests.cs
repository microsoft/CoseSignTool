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
        formatter.Should().BeOfType<TextOutputFormatter>();
    }

    [Fact]
    public void Create_WithJsonFormat_ReturnsJsonFormatter()
    {
        // Act
        var formatter = OutputFormatterFactory.Create(OutputFormat.Json);

        // Assert
        formatter.Should().BeOfType<JsonOutputFormatter>();
    }

    [Fact]
    public void Create_WithQuietFormat_ReturnsQuietFormatter()
    {
        // Act
        var formatter = OutputFormatterFactory.Create(OutputFormat.Quiet);

        // Assert
        formatter.Should().BeOfType<QuietOutputFormatter>();
    }

    [Fact]
    public void Create_WithInvalidFormat_ThrowsArgumentException()
    {
        // Act
        var act = () => OutputFormatterFactory.Create((OutputFormat)999);

        // Assert
        act.Should().Throw<ArgumentException>()
            .WithMessage("*Unknown output format*");
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
        formatter.Should().BeOfType<TextOutputFormatter>();
    }
}
