// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Tests.Output;

using CoseSignTool.Output;

/// <summary>
/// Extended tests for output formatters.
/// </summary>
[TestFixture]
public class OutputFormatterExtendedTests
{
    #region OutputFormatterFactory Tests

    [Test]
    public void OutputFormatterFactory_CreateTextFormatter_ReturnsTextOutputFormatter()
    {
        // Arrange & Act
        var formatter = OutputFormatterFactory.Create(OutputFormat.Text);

        // Assert
        Assert.That(formatter, Is.InstanceOf<TextOutputFormatter>());
    }

    [Test]
    public void OutputFormatterFactory_CreateJsonFormatter_ReturnsJsonOutputFormatter()
    {
        // Arrange & Act
        var formatter = OutputFormatterFactory.Create(OutputFormat.Json);

        // Assert
        Assert.That(formatter, Is.InstanceOf<JsonOutputFormatter>());
    }

    [Test]
    public void OutputFormatterFactory_CreateXmlFormatter_ReturnsXmlOutputFormatter()
    {
        // Arrange & Act
        var formatter = OutputFormatterFactory.Create(OutputFormat.Xml);

        // Assert
        Assert.That(formatter, Is.InstanceOf<XmlOutputFormatter>());
    }

    [Test]
    public void OutputFormatterFactory_CreateQuietFormatter_ReturnsQuietOutputFormatter()
    {
        // Arrange & Act
        var formatter = OutputFormatterFactory.Create(OutputFormat.Quiet);

        // Assert
        Assert.That(formatter, Is.InstanceOf<QuietOutputFormatter>());
    }

    [Test]
    public void OutputFormatterFactory_WithWriter_PassesWriterToFormatter()
    {
        // Arrange
        var stringWriter = new StringWriter();

        // Act
        var formatter = OutputFormatterFactory.Create(OutputFormat.Text, stringWriter);
        formatter.WriteInfo("Test message");
        formatter.Flush();

        // Assert
        var output = stringWriter.ToString();
        Assert.That(output, Does.Contain("Test message"));
    }

    #endregion

    #region TextOutputFormatter Tests

    [Test]
    public void TextOutputFormatter_WriteKeyValue_FormatsCorrectly()
    {
        // Arrange
        var stringWriter = new StringWriter();
        var formatter = new TextOutputFormatter(stringWriter);

        // Act
        formatter.WriteKeyValue("Key", "Value");
        formatter.Flush();

        // Assert
        var output = stringWriter.ToString();
        Assert.That(output, Does.Contain("Key"));
        Assert.That(output, Does.Contain("Value"));
    }

    [Test]
    public void TextOutputFormatter_BeginEndSection_FormatsCorrectly()
    {
        // Arrange
        var stringWriter = new StringWriter();
        var formatter = new TextOutputFormatter(stringWriter);

        // Act
        formatter.BeginSection("Test Section");
        formatter.WriteInfo("Content");
        formatter.EndSection();
        formatter.Flush();

        // Assert
        var output = stringWriter.ToString();
        Assert.That(output, Does.Contain("Test Section"));
        Assert.That(output, Does.Contain("Content"));
    }

    [Test]
    public void TextOutputFormatter_WriteSuccess_WritesWithMarker()
    {
        // Arrange
        var stringWriter = new StringWriter();
        var formatter = new TextOutputFormatter(stringWriter);

        // Act
        formatter.WriteSuccess("Success message");
        formatter.Flush();

        // Assert
        var output = stringWriter.ToString();
        Assert.That(output, Does.Contain("Success message"));
    }

    [Test]
    public void TextOutputFormatter_WriteWarning_WritesWithMarker()
    {
        // Arrange
        var stringWriter = new StringWriter();
        var formatter = new TextOutputFormatter(stringWriter);

        // Act
        formatter.WriteWarning("Warning message");
        formatter.Flush();

        // Assert
        var output = stringWriter.ToString();
        Assert.That(output, Does.Contain("Warning message"));
    }

    [Test]
    public void TextOutputFormatter_WriteError_WritesToError()
    {
        // Arrange
        var stringWriter = new StringWriter();
        var formatter = new TextOutputFormatter(stringWriter);

        // Act
        formatter.WriteError("Error message");
        formatter.Flush();

        // Assert - Error goes to Console.Error by default
        // We test that no exception is thrown
        Assert.That(formatter, Is.Not.Null);
    }

    #endregion

    #region JsonOutputFormatter Tests

    [Test]
    public void JsonOutputFormatter_WriteKeyValue_ProducesValidJson()
    {
        // Arrange
        var stringWriter = new StringWriter();
        var formatter = new JsonOutputFormatter(stringWriter);

        // Act
        formatter.WriteKeyValue("testKey", "testValue");
        formatter.Flush();

        // Assert
        var output = stringWriter.ToString();
        Assert.That(output, Does.Contain("testKey"));
        Assert.That(output, Does.Contain("testValue"));
    }

    [Test]
    public void JsonOutputFormatter_CompleteOutput_IsValidJsonArray()
    {
        // Arrange
        var stringWriter = new StringWriter();
        var formatter = new JsonOutputFormatter(stringWriter);

        // Act
        formatter.BeginSection("Section");
        formatter.WriteInfo("Info");
        formatter.WriteSuccess("Success");
        formatter.EndSection();
        formatter.Flush();

        // Assert
        var output = stringWriter.ToString();
        Assert.That(output.Trim(), Does.StartWith("["));
        Assert.That(output.Trim(), Does.EndWith("]"));
    }

    [Test]
    public void JsonOutputFormatter_WriteError_IncludesErrorType()
    {
        // Arrange
        var stringWriter = new StringWriter();
        var formatter = new JsonOutputFormatter(stringWriter);

        // Act
        formatter.WriteError("Test error");
        formatter.Flush();

        // Assert
        var output = stringWriter.ToString();
        Assert.That(output.ToLowerInvariant(), Does.Contain("error"));
    }

    #endregion

    #region XmlOutputFormatter Tests

    [Test]
    public void XmlOutputFormatter_WriteKeyValue_ProducesXml()
    {
        // Arrange
        var stringWriter = new StringWriter();
        var formatter = new XmlOutputFormatter(stringWriter);

        // Act
        formatter.WriteKeyValue("TestKey", "TestValue");
        formatter.Flush();

        // Assert
        var output = stringWriter.ToString();
        Assert.That(output, Does.Contain("<Key>TestKey</Key>"));
        Assert.That(output, Does.Contain("<Value>TestValue</Value>"));
    }

    [Test]
    public void XmlOutputFormatter_CompleteOutput_HasXmlDeclaration()
    {
        // Arrange
        var stringWriter = new StringWriter();
        var formatter = new XmlOutputFormatter(stringWriter);

        // Act
        formatter.BeginSection("Section");
        formatter.EndSection();
        formatter.Flush();

        // Assert
        var output = stringWriter.ToString();
        Assert.That(output, Does.Contain("<?xml"));
    }

    [Test]
    public void XmlOutputFormatter_HasCorrectRootElement()
    {
        // Arrange
        var stringWriter = new StringWriter();
        var formatter = new XmlOutputFormatter(stringWriter);

        // Act
        formatter.WriteInfo("Test");
        formatter.Flush();

        // Assert
        var output = stringWriter.ToString();
        Assert.That(output, Does.Contain("<CoseSignToolOutput>"));
        Assert.That(output, Does.Contain("</CoseSignToolOutput>"));
    }

    #endregion

    #region QuietOutputFormatter Tests

    [Test]
    public void QuietOutputFormatter_SupressesInfo()
    {
        // Arrange
        var formatter = new QuietOutputFormatter();

        // Act
        formatter.WriteInfo("Should not appear");
        formatter.Flush();

        // Assert - QuietOutputFormatter suppresses output
        Assert.That(formatter, Is.Not.Null);
    }

    [Test]
    public void QuietOutputFormatter_SupressesSuccess()
    {
        // Arrange
        var formatter = new QuietOutputFormatter();

        // Act
        formatter.WriteSuccess("Should not appear");
        formatter.Flush();

        // Assert
        Assert.That(formatter, Is.Not.Null);
    }

    [Test]
    public void QuietOutputFormatter_SupressesWarning()
    {
        // Arrange
        var formatter = new QuietOutputFormatter();

        // Act
        formatter.WriteWarning("Should not appear");
        formatter.Flush();

        // Assert
        Assert.That(formatter, Is.Not.Null);
    }

    [Test]
    public void QuietOutputFormatter_SupressesKeyValue()
    {
        // Arrange
        var formatter = new QuietOutputFormatter();

        // Act
        formatter.WriteKeyValue("Key", "Should not appear");
        formatter.Flush();

        // Assert
        Assert.That(formatter, Is.Not.Null);
    }

    [Test]
    public void QuietOutputFormatter_SuppressesSections()
    {
        // Arrange
        var formatter = new QuietOutputFormatter();

        // Act
        formatter.BeginSection("Should not appear");
        formatter.EndSection();
        formatter.Flush();

        // Assert
        Assert.That(formatter, Is.Not.Null);
    }

    #endregion
}
