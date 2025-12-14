// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Abstractions.Helpers;

using System.Text.Json.Serialization;
using CoseSign1.Headers.Local;

/// <summary>
/// A JSON-serializable DTO for COSE headers used in command-line parsing.
/// </summary>
/// <typeparam name="T">The data type of the header value.</typeparam>
public class CoseHeaderDto<T>
{
    /// <summary>
    /// Gets or sets the Header label.
    /// </summary>
    [JsonRequired]
    [JsonPropertyName("label")]
    public string Label { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the Header value.
    /// </summary>
    [JsonRequired]
    [JsonPropertyName("value")]
    public T Value { get; set; } = default!;

    /// <summary>
    /// Gets or sets a value to indicate if this header is protected.
    /// </summary>
    [JsonPropertyName("protected")]
    public bool IsProtected { get; set; }

    /// <summary>
    /// Converts this DTO to a <see cref="CoseHeader{T}"/>.
    /// </summary>
    /// <returns>A new CoseHeader instance.</returns>
    public CoseHeader<T> ToCoseHeader() => new(Label, Value, IsProtected);
}

/// <summary>
/// Extension methods for CoseHeaderDto collections.
/// </summary>
public static class CoseHeaderDtoExtensions
{
    /// <summary>
    /// Converts a list of DTOs to a list of CoseHeaders.
    /// </summary>
    /// <typeparam name="T">The data type of the header value.</typeparam>
    /// <param name="dtos">The DTOs to convert.</param>
    /// <returns>A list of CoseHeader instances.</returns>
    public static List<CoseHeader<T>>? ToCoseHeaders<T>(this List<CoseHeaderDto<T>>? dtos)
    {
        return dtos?.Select(d => d.ToCoseHeader()).ToList();
    }
}
