// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Text.Json;
using CoseSignTool.Output;

namespace CoseSignTool.Tests.Output;

/// <summary>
/// Tests for the JsonOutputFormatter class.
/// </summary>
[TestFixture]
public class JsonOutputFormatterTests
{
    [Test]
    public void WriteSuccess_AddsSuccessMessage()
    {
        // Arrange
        using var output = new StringWriter();
        var formatter = new JsonOutputFormatter(output);

        // Act
        formatter.WriteSuccess("Test success");
        formatter.Flush();

        // Assert
        var json = output.ToString();
        Assert.That(json, Does.Contain("success"));
        Assert.That(json, Does.Contain("Test success"));
    }

    [Test]
    public void WriteError_AddsErrorMessage()
    {
        // Arrange
        using var output = new StringWriter();
        var formatter = new JsonOutputFormatter(output);

        // Act
        formatter.WriteError("Test error");
        formatter.Flush();

        // Assert
        var json = output.ToString();
        Assert.That(json, Does.Contain("error"));
        Assert.That(json, Does.Contain("Test error"));
    }

    [Test]
    public void WriteInfo_AddsInfoMessage()
    {
        // Arrange
        using var output = new StringWriter();
        var formatter = new JsonOutputFormatter(output);

        // Act
        formatter.WriteInfo("Test info");
        formatter.Flush();

        // Assert
        var json = output.ToString();
        Assert.That(json, Does.Contain("info"));
        Assert.That(json, Does.Contain("Test info"));
    }

    [Test]
    public void WriteWarning_AddsWarningMessage()
    {
        // Arrange
        using var output = new StringWriter();
        var formatter = new JsonOutputFormatter(output);

        // Act
        formatter.WriteWarning("Test warning");
        formatter.Flush();

        // Assert
        var json = output.ToString();
        Assert.That(json, Does.Contain("warning"));
        Assert.That(json, Does.Contain("Test warning"));
    }

    [Test]
    public void WriteKeyValue_AddsKeyValuePair()
    {
        // Arrange
        using var output = new StringWriter();
        var formatter = new JsonOutputFormatter(output);

        // Act
        formatter.WriteKeyValue("TestKey", "TestValue");
        formatter.Flush();

        // Assert
        var json = output.ToString();
        Assert.That(json, Does.Contain("keyvalue"));
        Assert.That(json, Does.Contain("TestKey"));
        Assert.That(json, Does.Contain("TestValue"));
    }

    [Test]
    public void BeginSection_AddsSectionStart()
    {
        // Arrange
        using var output = new StringWriter();
        var formatter = new JsonOutputFormatter(output);

        // Act
        formatter.BeginSection("Test Section");
        formatter.Flush();

        // Assert
        var json = output.ToString();
        Assert.That(json, Does.Contain("section_start"));
        Assert.That(json, Does.Contain("Test Section"));
    }

    [Test]
    public void EndSection_AddsSectionEnd()
    {
        // Arrange
        using var output = new StringWriter();
        var formatter = new JsonOutputFormatter(output);

        // Act
        formatter.EndSection();
        formatter.Flush();

        // Assert
        var json = output.ToString();
        Assert.That(json, Does.Contain("section_end"));
    }

    [Test]
    public void Flush_OutputsValidJson()
    {
        // Arrange
        using var output = new StringWriter();
        var formatter = new JsonOutputFormatter(output);

        // Act
        formatter.WriteSuccess("Message 1");
        formatter.WriteError("Message 2");
        formatter.Flush();

        // Assert
        var json = output.ToString();
        var doc = JsonDocument.Parse(json);
        Assert.That(doc.RootElement.GetArrayLength(), Is.EqualTo(2));
    }

    [Test]
    public void Constructor_WithNullWriter_UsesConsole()
    {
        // Act
        var formatter = new JsonOutputFormatter();

        // Assert
        Assert.That(formatter, Is.Not.Null);
    }

    [Test]
    public void MultipleMessages_CreateArray()
    {
        // Arrange
        using var output = new StringWriter();
        var formatter = new JsonOutputFormatter(output);

        // Act
        formatter.WriteSuccess("Success 1");
        formatter.WriteInfo("Info 1");
        formatter.WriteWarning("Warning 1");
        formatter.WriteError("Error 1");
        formatter.Flush();

        // Assert
        var json = output.ToString();
        var doc = JsonDocument.Parse(json);
        Assert.That(doc.RootElement.GetArrayLength(), Is.EqualTo(4));
    }
}