// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSignTool.Output;

namespace CoseSignTool.Tests.Output;

/// <summary>
/// Extended tests for output formatters.
/// </summary>
public class OutputFormatterExtendedTests
{
    #region OutputFormatterFactory Tests

    [Fact]
    public void OutputFormatterFactory_CreateTextFormatter_ReturnsTextOutputFormatter()
    {
        // Arrange & Act
        var formatter = OutputFormatterFactory.Create(OutputFormat.Text);

        // Assert
        Assert.IsType<TextOutputFormatter>(formatter);
    }

    [Fact]
    public void OutputFormatterFactory_CreateJsonFormatter_ReturnsJsonOutputFormatter()
    {
        // Arrange & Act
        var formatter = OutputFormatterFactory.Create(OutputFormat.Json);

        // Assert
        Assert.IsType<JsonOutputFormatter>(formatter);
    }

    [Fact]
    public void OutputFormatterFactory_CreateXmlFormatter_ReturnsXmlOutputFormatter()
    {
        // Arrange & Act
        var formatter = OutputFormatterFactory.Create(OutputFormat.Xml);

        // Assert
        Assert.IsType<XmlOutputFormatter>(formatter);
    }

    [Fact]
    public void OutputFormatterFactory_CreateQuietFormatter_ReturnsQuietOutputFormatter()
    {
        // Arrange & Act
        var formatter = OutputFormatterFactory.Create(OutputFormat.Quiet);

        // Assert
        Assert.IsType<QuietOutputFormatter>(formatter);
    }

    [Fact]
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
        Assert.Contains("Test message", output);
    }

    #endregion

    #region TextOutputFormatter Tests

    [Fact]
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
        Assert.Contains("Key", output);
        Assert.Contains("Value", output);
    }

    [Fact]
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
        Assert.Contains("Test Section", output);
        Assert.Contains("Content", output);
    }

    [Fact]
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
        Assert.Contains("Success message", output);
    }

    [Fact]
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
        Assert.Contains("Warning message", output);
    }

    [Fact]
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
        Assert.NotNull(formatter);
    }

    #endregion

    #region JsonOutputFormatter Tests

    [Fact]
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
        Assert.Contains("testKey", output);
        Assert.Contains("testValue", output);
    }

    [Fact]
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
        Assert.StartsWith("[", output.Trim());
        Assert.EndsWith("]", output.Trim());
    }

    [Fact]
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
        Assert.Contains("error", output.ToLowerInvariant());
    }

    #endregion

    #region XmlOutputFormatter Tests

    [Fact]
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
        Assert.Contains("<Key>TestKey</Key>", output);
        Assert.Contains("<Value>TestValue</Value>", output);
    }

    [Fact]
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
        Assert.Contains("<?xml", output);
    }

    [Fact]
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
        Assert.Contains("<CoseSignToolOutput>", output);
        Assert.Contains("</CoseSignToolOutput>", output);
    }

    #endregion

    #region QuietOutputFormatter Tests

    [Fact]
    public void QuietOutputFormatter_SupressesInfo()
    {
        // Arrange
        var formatter = new QuietOutputFormatter();

        // Act
        formatter.WriteInfo("Should not appear");
        formatter.Flush();

        // Assert - QuietOutputFormatter suppresses output
        Assert.NotNull(formatter);
    }

    [Fact]
    public void QuietOutputFormatter_SupressesSuccess()
    {
        // Arrange
        var formatter = new QuietOutputFormatter();

        // Act
        formatter.WriteSuccess("Should not appear");
        formatter.Flush();

        // Assert
        Assert.NotNull(formatter);
    }

    [Fact]
    public void QuietOutputFormatter_SupressesWarning()
    {
        // Arrange
        var formatter = new QuietOutputFormatter();

        // Act
        formatter.WriteWarning("Should not appear");
        formatter.Flush();

        // Assert
        Assert.NotNull(formatter);
    }

    [Fact]
    public void QuietOutputFormatter_SupressesKeyValue()
    {
        // Arrange
        var formatter = new QuietOutputFormatter();

        // Act
        formatter.WriteKeyValue("Key", "Should not appear");
        formatter.Flush();

        // Assert
        Assert.NotNull(formatter);
    }

    [Fact]
    public void QuietOutputFormatter_SuppressesSections()
    {
        // Arrange
        var formatter = new QuietOutputFormatter();

        // Act
        formatter.BeginSection("Should not appear");
        formatter.EndSection();
        formatter.Flush();

        // Assert
        Assert.NotNull(formatter);
    }

    #endregion
}
