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
        Assert.Contains("success", json);
        Assert.Contains("Test success", json);
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
        Assert.Contains("error", json);
        Assert.Contains("Test error", json);
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
        Assert.Contains("info", json);
        Assert.Contains("Test info", json);
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
        Assert.Contains("warning", json);
        Assert.Contains("Test warning", json);
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
        Assert.Contains("keyvalue", json);
        Assert.Contains("TestKey", json);
        Assert.Contains("TestValue", json);
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
        Assert.Contains("section_start", json);
        Assert.Contains("Test Section", json);
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
        Assert.Contains("section_end", json);
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
        Assert.Equal(2, doc.RootElement.GetArrayLength());
    }

    [Fact]
    public void Constructor_WithNullWriter_UsesConsole()
    {
        // Act
        var formatter = new JsonOutputFormatter();

        // Assert
        Assert.NotNull(formatter);
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
        Assert.Equal(4, doc.RootElement.GetArrayLength());
    }
}
