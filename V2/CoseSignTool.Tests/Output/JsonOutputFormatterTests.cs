// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSignTool.Output;
using System.Text.Json;

namespace CoseSignTool.Tests.Output;

/// <summary>
/// Tests for the JsonOutputFormatter class.
/// </summary>
public class JsonOutputFormatterTests
{
    [Fact]
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
        json.Should().Contain("success");
        json.Should().Contain("Test success");
    }

    [Fact]
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
        json.Should().Contain("error");
        json.Should().Contain("Test error");
    }

    [Fact]
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
        json.Should().Contain("info");
        json.Should().Contain("Test info");
    }

    [Fact]
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
        json.Should().Contain("warning");
        json.Should().Contain("Test warning");
    }

    [Fact]
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
        json.Should().Contain("keyvalue");
        json.Should().Contain("TestKey");
        json.Should().Contain("TestValue");
    }

    [Fact]
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
        json.Should().Contain("section_start");
        json.Should().Contain("Test Section");
    }

    [Fact]
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
        json.Should().Contain("section_end");
    }

    [Fact]
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
        doc.RootElement.GetArrayLength().Should().Be(2);
    }

    [Fact]
    public void Constructor_WithNullWriter_UsesConsole()
    {
        // Act
        var formatter = new JsonOutputFormatter();

        // Assert
        formatter.Should().NotBeNull();
    }

    [Fact]
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
        doc.RootElement.GetArrayLength().Should().Be(4);
    }
}
