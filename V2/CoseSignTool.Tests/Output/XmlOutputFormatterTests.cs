// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSignTool.Output;
using System.Xml.Linq;

namespace CoseSignTool.Tests.Output;

/// <summary>
/// Tests for the XmlOutputFormatter class.
/// </summary>
public class XmlOutputFormatterTests
{
    [Fact]
    public void WriteSuccess_AddsSuccessMessage()
    {
        // Arrange
        using var output = new StringWriter();
        var formatter = new XmlOutputFormatter(output);

        // Act
        formatter.WriteSuccess("Test success");
        formatter.Flush();

        // Assert
        var xml = output.ToString();
        Assert.Contains("<Success>Test success</Success>", xml);
    }

    [Fact]
    public void WriteError_AddsErrorMessage()
    {
        // Arrange
        using var output = new StringWriter();
        var formatter = new XmlOutputFormatter(output);

        // Act
        formatter.WriteError("Test error");
        formatter.Flush();

        // Assert
        var xml = output.ToString();
        Assert.Contains("<Error>Test error</Error>", xml);
    }

    [Fact]
    public void WriteInfo_AddsInfoMessage()
    {
        // Arrange
        using var output = new StringWriter();
        var formatter = new XmlOutputFormatter(output);

        // Act
        formatter.WriteInfo("Test info");
        formatter.Flush();

        // Assert
        var xml = output.ToString();
        Assert.Contains("<Info>Test info</Info>", xml);
    }

    [Fact]
    public void WriteWarning_AddsWarningMessage()
    {
        // Arrange
        using var output = new StringWriter();
        var formatter = new XmlOutputFormatter(output);

        // Act
        formatter.WriteWarning("Test warning");
        formatter.Flush();

        // Assert
        var xml = output.ToString();
        Assert.Contains("<Warning>Test warning</Warning>", xml);
    }

    [Fact]
    public void WriteKeyValue_AddsKeyValuePair()
    {
        // Arrange
        using var output = new StringWriter();
        var formatter = new XmlOutputFormatter(output);

        // Act
        formatter.WriteKeyValue("TestKey", "TestValue");
        formatter.Flush();

        // Assert
        var xml = output.ToString();
        Assert.Contains("<KeyValue>", xml);
        Assert.Contains("<Key>TestKey</Key>", xml);
        Assert.Contains("<Value>TestValue</Value>", xml);
    }

    [Fact]
    public void BeginSection_AddsSectionStart()
    {
        // Arrange
        using var output = new StringWriter();
        var formatter = new XmlOutputFormatter(output);

        // Act
        formatter.BeginSection("Test Section");
        formatter.Flush();

        // Assert
        var xml = output.ToString();
        Assert.Contains("<SectionStart title=\"Test Section\"", xml);
    }

    [Fact]
    public void EndSection_AddsSectionEnd()
    {
        // Arrange
        using var output = new StringWriter();
        var formatter = new XmlOutputFormatter(output);

        // Act
        formatter.EndSection();
        formatter.Flush();

        // Assert
        var xml = output.ToString();
        Assert.Contains("<SectionEnd />", xml);
    }

    [Fact]
    public void Flush_OutputsValidXml()
    {
        // Arrange
        using var output = new StringWriter();
        var formatter = new XmlOutputFormatter(output);

        // Act
        formatter.WriteSuccess("Message 1");
        formatter.WriteError("Message 2");
        formatter.Flush();

        // Assert
        var xml = output.ToString();
        var doc = XDocument.Parse(xml);
        Assert.NotNull(doc.Root);
        Assert.Equal("CoseSignToolOutput", doc.Root!.Name.LocalName);
        Assert.Equal(2, doc.Root.Elements().Count());
    }

    [Fact]
    public void Constructor_WithNullWriter_UsesConsole()
    {
        // Act
        var formatter = new XmlOutputFormatter();

        // Assert
        Assert.NotNull(formatter);
    }

    [Fact]
    public void MultipleMessages_CreateValidXml()
    {
        // Arrange
        using var output = new StringWriter();
        var formatter = new XmlOutputFormatter(output);

        // Act
        formatter.WriteSuccess("Success 1");
        formatter.WriteInfo("Info 1");
        formatter.WriteWarning("Warning 1");
        formatter.WriteError("Error 1");
        formatter.WriteKeyValue("Key1", "Value1");
        formatter.BeginSection("Section 1");
        formatter.EndSection();
        formatter.Flush();

        // Assert
        var xml = output.ToString();
        var doc = XDocument.Parse(xml);
        Assert.Equal(7, doc.Root!.Elements().Count());
    }

    [Fact]
    public void XmlOutput_IsWellFormed()
    {
        // Arrange
        using var output = new StringWriter();
        var formatter = new XmlOutputFormatter(output);

        // Act
        formatter.WriteSuccess("Test");
        formatter.Flush();

        // Assert - Should not throw
        var xml = output.ToString();
        var doc = XDocument.Parse(xml); // Will throw if malformed
        Assert.NotNull(doc);
    }

    [Fact]
    public void XmlOutput_HasDeclaration()
    {
        // Arrange
        using var output = new StringWriter();
        var formatter = new XmlOutputFormatter(output);

        // Act
        formatter.WriteSuccess("Test");
        formatter.Flush();

        // Assert
        var xml = output.ToString();
        Assert.Contains("<?xml version=\"1.0\" encoding=\"utf-16\"?>", xml);
    }
}
