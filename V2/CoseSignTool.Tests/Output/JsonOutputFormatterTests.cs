// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Tests.Output;

using System.Text.Json;
using CoseSignTool.Output;

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

    [Test]
    public void WriteStructuredData_OutputsObjectInsteadOfMessages()
    {
        // Arrange
        using var output = new StringWriter();
        var formatter = new JsonOutputFormatter(output);
        var structuredData = new { name = "Test", value = 42 };

        // Act
        formatter.WriteSuccess("This should be ignored");
        formatter.WriteStructuredData(structuredData);
        formatter.Flush();

        // Assert
        var json = output.ToString();
        var doc = JsonDocument.Parse(json);

        // Should be an object, not an array
        Assert.That(doc.RootElement.ValueKind, Is.EqualTo(JsonValueKind.Object));
        Assert.That(doc.RootElement.GetProperty("name").GetString(), Is.EqualTo("Test"));
        Assert.That(doc.RootElement.GetProperty("value").GetInt32(), Is.EqualTo(42));
    }

    [Test]
    public void WriteStructuredData_WithNullProperties_OmitsThem()
    {
        // Arrange
        using var output = new StringWriter();
        var formatter = new JsonOutputFormatter(output);
        var structuredData = new TestDataClass { Required = "value", Optional = null };

        // Act
        formatter.WriteStructuredData(structuredData);
        formatter.Flush();

        // Assert
        var json = output.ToString();
        var doc = JsonDocument.Parse(json);

        Assert.That(doc.RootElement.TryGetProperty("Required", out _), Is.True);
        // Optional should be omitted when null due to JsonIgnoreCondition.WhenWritingNull
        Assert.That(doc.RootElement.TryGetProperty("Optional", out _), Is.False);
    }

    [Test]
    public void WriteStructuredData_WithoutStructuredData_OutputsMessages()
    {
        // Arrange
        using var output = new StringWriter();
        var formatter = new JsonOutputFormatter(output);

        // Act - Don't call WriteStructuredData
        formatter.WriteSuccess("Success message");
        formatter.WriteInfo("Info message");
        formatter.Flush();

        // Assert
        var json = output.ToString();
        var doc = JsonDocument.Parse(json);

        // Should be an array of messages
        Assert.That(doc.RootElement.ValueKind, Is.EqualTo(JsonValueKind.Array));
        Assert.That(doc.RootElement.GetArrayLength(), Is.EqualTo(2));
    }

    [Test]
    public void WriteStructuredData_WithComplexObject_SerializesCorrectly()
    {
        // Arrange
        using var output = new StringWriter();
        var formatter = new JsonOutputFormatter(output);
        var structuredData = new
        {
            file = new { path = "/test/file.cose", sizeBytes = 1024 },
            headers = new { algorithm = new { id = -37, name = "PS256" } },
            certificates = new[] { new { subject = "CN=Test", thumbprint = "ABC123" } }
        };

        // Act
        formatter.WriteStructuredData(structuredData);
        formatter.Flush();

        // Assert
        var json = output.ToString();
        var doc = JsonDocument.Parse(json);

        Assert.That(doc.RootElement.GetProperty("file").GetProperty("path").GetString(), Is.EqualTo("/test/file.cose"));
        Assert.That(doc.RootElement.GetProperty("file").GetProperty("sizeBytes").GetInt32(), Is.EqualTo(1024));
        Assert.That(doc.RootElement.GetProperty("headers").GetProperty("algorithm").GetProperty("id").GetInt32(), Is.EqualTo(-37));
        Assert.That(doc.RootElement.GetProperty("certificates").GetArrayLength(), Is.EqualTo(1));
    }

    private class TestDataClass
    {
        public string? Required { get; set; }
        public string? Optional { get; set; }
    }
}
