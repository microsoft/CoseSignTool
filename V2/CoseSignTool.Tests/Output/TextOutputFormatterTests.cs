// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Tests.Output;

using CoseSignTool.Output;

/// <summary>
/// Tests for the TextOutputFormatter class.
/// </summary>
[TestFixture]
public class TextOutputFormatterTests
{
    [Test]
    public void WriteSuccess_WritesToOutput()
    {
        // Arrange
        using var output = new StringWriter();
        var formatter = new TextOutputFormatter(output);

        // Act
        formatter.WriteSuccess("Test message");

        // Assert
        Assert.That(output.ToString(), Does.Contain("Test message"));
        Assert.That(output.ToString(), Does.Contain("[OK]"));
    }

    [Test]
    public void WriteError_WritesToError()
    {
        // Arrange
        using var error = new StringWriter();
        var formatter = new TextOutputFormatter(error: error);

        // Act
        formatter.WriteError("Error message");

        // Assert
        Assert.That(error.ToString(), Does.Contain("Error message"));
        Assert.That(error.ToString(), Does.Contain("[ERROR]"));
    }

    [Test]
    public void WriteInfo_WritesToOutput()
    {
        // Arrange
        using var output = new StringWriter();
        var formatter = new TextOutputFormatter(output);

        // Act
        formatter.WriteInfo("Info message");

        // Assert
        Assert.That(output.ToString(), Does.Contain("Info message"));
        Assert.That(output.ToString(), Does.Contain("[INFO]"));
    }

    [Test]
    public void WriteWarning_WritesToOutput()
    {
        // Arrange
        using var output = new StringWriter();
        var formatter = new TextOutputFormatter(output);

        // Act
        formatter.WriteWarning("Warning message");

        // Assert
        Assert.That(output.ToString(), Does.Contain("Warning message"));
        Assert.That(output.ToString(), Does.Contain("[WARN]"));
    }

    [Test]
    public void WriteKeyValue_FormatsCorrectly()
    {
        // Arrange
        using var output = new StringWriter();
        var formatter = new TextOutputFormatter(output);

        // Act
        formatter.WriteKeyValue("Key", "Value");

        // Assert
        var result = output.ToString();
        Assert.That(result, Does.Contain("Key"));
        Assert.That(result, Does.Contain("Value"));
        Assert.That(result, Does.Contain(":"));
    }

    [Test]
    public void BeginSection_WritesTitle()
    {
        // Arrange
        using var output = new StringWriter();
        var formatter = new TextOutputFormatter(output);

        // Act
        formatter.BeginSection("Test Section");

        // Assert
        var result = output.ToString();
        Assert.That(result, Does.Contain("Test Section"));
        Assert.That(result, Does.Contain("---"));
    }

    [Test]
    public void EndSection_WritesNewLine()
    {
        // Arrange
        using var output = new StringWriter();
        var formatter = new TextOutputFormatter(output);

        // Act
        formatter.EndSection();

        // Assert
        Assert.That(output.ToString(), Does.Contain(Environment.NewLine));
    }

    [Test]
    public void Constructor_WithNullWriters_UsesConsole()
    {
        // Act
        var formatter = new TextOutputFormatter();

        // Assert - should not throw
        Assert.That(formatter, Is.Not.Null);
    }

    [Test]
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
        Assert.That(lines.Count(), Is.EqualTo(3));
    }

    [Test]
    public void WriteStructuredData_IsIgnored()
    {
        // Arrange
        using var output = new StringWriter();
        var formatter = new TextOutputFormatter(output);
        var structuredData = new { name = "Test", value = 42 };

        // Act
        formatter.WriteStructuredData(structuredData);
        formatter.Flush();

        // Assert - TextOutputFormatter ignores structured data
        Assert.That(output.ToString(), Is.Empty);
    }
}
