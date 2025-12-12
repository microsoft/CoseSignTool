// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSignTool.Output;

namespace CoseSignTool.Tests.Output;

/// <summary>
/// Tests for the OutputFormatterFactory class.
/// </summary>
[TestFixture]
public class OutputFormatterFactoryTests
{
    [Test]
    public void Create_WithTextFormat_ReturnsTextFormatter()
    {
        // Act
        var formatter = OutputFormatterFactory.Create(OutputFormat.Text);

        // Assert
        Assert.That(formatter, Is.InstanceOf<TextOutputFormatter>());
    }

    [Test]
    public void Create_WithJsonFormat_ReturnsJsonFormatter()
    {
        // Act
        var formatter = OutputFormatterFactory.Create(OutputFormat.Json);

        // Assert
        Assert.That(formatter, Is.InstanceOf<JsonOutputFormatter>());
    }

    [Test]
    public void Create_WithQuietFormat_ReturnsQuietFormatter()
    {
        // Act
        var formatter = OutputFormatterFactory.Create(OutputFormat.Quiet);

        // Assert
        Assert.That(formatter, Is.InstanceOf<QuietOutputFormatter>());
    }

    [Test]
    public void Create_WithInvalidFormat_ThrowsArgumentException()
    {
        // Act & Assert
        Assert.Throws<ArgumentException>(() => OutputFormatterFactory.Create((OutputFormat)999));
    }

    [Test]
    public void Create_WithCustomWriters_PassesThemThrough()
    {
        // Arrange
        using var output = new StringWriter();
        using var error = new StringWriter();

        // Act
        var formatter = OutputFormatterFactory.Create(OutputFormat.Text, output, error);

        // Assert
        Assert.That(formatter, Is.InstanceOf<TextOutputFormatter>());
    }
}