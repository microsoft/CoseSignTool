// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Tests.Output;

using System.Xml.Linq;
using CoseSignTool.Output;

/// <summary>
/// Tests for the XmlOutputFormatter class.
/// </summary>
[TestFixture]
public class XmlOutputFormatterTests
{
    [Test]
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
        Assert.That(xml, Does.Contain("<Success>Test success</Success>"));
    }

    [Test]
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
        Assert.That(xml, Does.Contain("<Error>Test error</Error>"));
    }

    [Test]
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
        Assert.That(xml, Does.Contain("<Info>Test info</Info>"));
    }

    [Test]
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
        Assert.That(xml, Does.Contain("<Warning>Test warning</Warning>"));
    }

    [Test]
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
        Assert.That(xml, Does.Contain("<KeyValue>"));
        Assert.That(xml, Does.Contain("<Key>TestKey</Key>"));
        Assert.That(xml, Does.Contain("<Value>TestValue</Value>"));
    }

    [Test]
    public void WriteKeyValue_WhenKeyHasLeadingWhitespace_DoesNotPreserveIndentationInXml()
    {
        // Arrange
        using var output = new StringWriter();
        var formatter = new XmlOutputFormatter(output);

        // Act
        formatter.WriteKeyValue("  TestKey", "TestValue");
        formatter.Flush();

        // Assert
        var xml = output.ToString();
        Assert.That(xml, Does.Contain("<Key>TestKey</Key>"));
        Assert.That(xml, Does.Not.Contain("<Key>  TestKey</Key>"));
    }

    [Test]
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
        Assert.That(xml, Does.Contain("<SectionStart title=\"Test Section\""));
    }

    [Test]
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
        Assert.That(xml, Does.Contain("<SectionEnd />"));
    }

    [Test]
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
        Assert.That(doc.Root, Is.Not.Null);
        Assert.That(doc.Root!.Name.LocalName, Is.EqualTo("CoseSignToolOutput"));
        Assert.That(doc.Root.Elements().Count(), Is.EqualTo(2));
    }

    [Test]
    public void Constructor_WithNullWriter_UsesConsole()
    {
        // Act
        var formatter = new XmlOutputFormatter();

        // Assert
        Assert.That(formatter, Is.Not.Null);
    }

    [Test]
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
        Assert.That(doc.Root!.Elements().Count(), Is.EqualTo(7));
    }

    [Test]
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
        Assert.That(doc, Is.Not.Null);
    }

    [Test]
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
        Assert.That(xml, Does.Contain("<?xml version=\"1.0\" encoding=\"utf-16\"?>"));
    }

    [Test]
    public void WriteStructuredData_IsIgnored()
    {
        // Arrange
        using var output = new StringWriter();
        var formatter = new XmlOutputFormatter(output);
        var structuredData = new { name = "Test", value = 42 };

        // Act - XmlOutputFormatter uses message-based output, ignores structured data
        formatter.WriteStructuredData(structuredData);
        formatter.WriteSuccess("Test message");
        formatter.Flush();

        // Assert - Should still output message-based XML
        var xml = output.ToString();
        var doc = XDocument.Parse(xml);
        Assert.That(doc.Root!.Elements("Success").Count(), Is.EqualTo(1));
    }
}
