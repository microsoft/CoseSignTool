// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Abstractions.Tests;

using System.Text.Json;
using CoseSign1.Headers.Local;
using CoseSignTool.Abstractions.Helpers;

/// <summary>
/// Tests for CoseHeaderDto and its extension methods.
/// </summary>
[TestClass]
public class CoseHeaderDtoTests
{
    /// <summary>
    /// Tests that CoseHeaderDto can be deserialized from JSON with expected property names.
    /// </summary>
    [TestMethod]
    public void Deserialize_WithValidJson_ReturnsCorrectDto()
    {
        // Arrange
        string json = """{"label": "test-label", "value": 42, "protected": true}""";

        // Act
        CoseHeaderDto<int>? dto = JsonSerializer.Deserialize<CoseHeaderDto<int>>(json);

        // Assert
        Assert.IsNotNull(dto);
        Assert.AreEqual("test-label", dto.Label);
        Assert.AreEqual(42, dto.Value);
        Assert.IsTrue(dto.IsProtected);
    }

    /// <summary>
    /// Tests that CoseHeaderDto with string values deserializes correctly.
    /// </summary>
    [TestMethod]
    public void Deserialize_WithStringValue_ReturnsCorrectDto()
    {
        // Arrange
        string json = """{"label": "content-type", "value": "application/json", "protected": false}""";

        // Act
        CoseHeaderDto<string>? dto = JsonSerializer.Deserialize<CoseHeaderDto<string>>(json);

        // Assert
        Assert.IsNotNull(dto);
        Assert.AreEqual("content-type", dto.Label);
        Assert.AreEqual("application/json", dto.Value);
        Assert.IsFalse(dto.IsProtected);
    }

    /// <summary>
    /// Tests that protected defaults to false when not specified in JSON.
    /// </summary>
    [TestMethod]
    public void Deserialize_WithoutProtected_DefaultsToFalse()
    {
        // Arrange
        string json = """{"label": "test", "value": 123}""";

        // Act
        CoseHeaderDto<int>? dto = JsonSerializer.Deserialize<CoseHeaderDto<int>>(json);

        // Assert
        Assert.IsNotNull(dto);
        Assert.IsFalse(dto.IsProtected);
    }

    /// <summary>
    /// Tests that ToCoseHeader converts the DTO correctly.
    /// </summary>
    [TestMethod]
    public void ToCoseHeader_ReturnsCorrectCoseHeader()
    {
        // Arrange
        CoseHeaderDto<int> dto = new()
        {
            Label = "my-header",
            Value = 999,
            IsProtected = true
        };

        // Act
        CoseHeader<int> header = dto.ToCoseHeader();

        // Assert
        Assert.AreEqual("my-header", header.Label);
        Assert.AreEqual(999, header.Value);
        Assert.IsTrue(header.IsProtected);
    }

    /// <summary>
    /// Tests that ToCoseHeaders extension method converts a list of DTOs correctly.
    /// </summary>
    [TestMethod]
    public void ToCoseHeaders_WithValidList_ReturnsConvertedHeaders()
    {
        // Arrange
        List<CoseHeaderDto<string>> dtos =
        [
            new() { Label = "header1", Value = "value1", IsProtected = true },
            new() { Label = "header2", Value = "value2", IsProtected = false }
        ];

        // Act
        List<CoseHeader<string>>? headers = dtos.ToCoseHeaders();

        // Assert
        Assert.IsNotNull(headers);
        Assert.AreEqual(2, headers.Count);
        Assert.AreEqual("header1", headers[0].Label);
        Assert.AreEqual("value1", headers[0].Value);
        Assert.IsTrue(headers[0].IsProtected);
        Assert.AreEqual("header2", headers[1].Label);
        Assert.AreEqual("value2", headers[1].Value);
        Assert.IsFalse(headers[1].IsProtected);
    }

    /// <summary>
    /// Tests that ToCoseHeaders returns null when given null input.
    /// </summary>
    [TestMethod]
    public void ToCoseHeaders_WithNull_ReturnsNull()
    {
        // Arrange
        List<CoseHeaderDto<int>>? dtos = null;

        // Act
        List<CoseHeader<int>>? headers = dtos.ToCoseHeaders();

        // Assert
        Assert.IsNull(headers);
    }

    /// <summary>
    /// Tests that ToCoseHeaders returns empty list when given empty input.
    /// </summary>
    [TestMethod]
    public void ToCoseHeaders_WithEmptyList_ReturnsEmptyList()
    {
        // Arrange
        List<CoseHeaderDto<int>> dtos = [];

        // Act
        List<CoseHeader<int>>? headers = dtos.ToCoseHeaders();

        // Assert
        Assert.IsNotNull(headers);
        Assert.AreEqual(0, headers.Count);
    }

    /// <summary>
    /// Tests deserializing a JSON array of header DTOs.
    /// </summary>
    [TestMethod]
    public void Deserialize_JsonArray_ReturnsListOfDtos()
    {
        // Arrange
        string json = """
            [
                {"label": "h1", "value": 1, "protected": true},
                {"label": "h2", "value": 2, "protected": false}
            ]
            """;

        // Act
        List<CoseHeaderDto<int>>? dtos = JsonSerializer.Deserialize<List<CoseHeaderDto<int>>>(json);

        // Assert
        Assert.IsNotNull(dtos);
        Assert.AreEqual(2, dtos.Count);
        Assert.AreEqual("h1", dtos[0].Label);
        Assert.AreEqual(1, dtos[0].Value);
        Assert.IsTrue(dtos[0].IsProtected);
        Assert.AreEqual("h2", dtos[1].Label);
        Assert.AreEqual(2, dtos[1].Value);
        Assert.IsFalse(dtos[1].IsProtected);
    }

    /// <summary>
    /// Tests the full workflow: deserialize JSON array then convert to CoseHeaders.
    /// </summary>
    [TestMethod]
    public void FullWorkflow_DeserializeAndConvert_Succeeds()
    {
        // Arrange
        string json = """
            [
                {"label": "alg", "value": -7, "protected": true},
                {"label": "kid", "value": 12345, "protected": true}
            ]
            """;

        // Act
        List<CoseHeaderDto<int>>? dtos = JsonSerializer.Deserialize<List<CoseHeaderDto<int>>>(json);
        List<CoseHeader<int>>? headers = dtos.ToCoseHeaders();

        // Assert
        Assert.IsNotNull(headers);
        Assert.AreEqual(2, headers.Count);
        Assert.AreEqual("alg", headers[0].Label);
        Assert.AreEqual(-7, headers[0].Value);
        Assert.AreEqual("kid", headers[1].Label);
        Assert.AreEqual(12345, headers[1].Value);
    }
}
