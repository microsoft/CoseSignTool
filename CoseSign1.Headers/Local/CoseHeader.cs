// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Headers.Local;

/// <summary>
/// A type to represent a header.
/// </summary>
/// <typeparam name="TypeV">The data type of the header value.</typeparam>
public class CoseHeader<TypeV>
{
    /// <summary>
    /// Gets or sets the Header label.
    /// </summary>
    [JsonProperty(Required = Required.Always, PropertyName = "label")]
    public string Label { get; set; }

    /// <summary>
    /// Gets or sets the Header value.
    /// </summary>
    [JsonProperty(Required = Required.Always, PropertyName = "value")]
    public TypeV Value { get; set; }

    /// <summary>
    /// Gets or sets a value to indicate if this header is protected.
    /// </summary>
    [JsonProperty(PropertyName = "protected", DefaultValueHandling = DefaultValueHandling.Populate)]
    public bool IsProtected { get; set; }

    /// <summary>
    /// Creates a new instance of this type.
    /// </summary>
    /// <param name="label">The header label</param>
    /// <param name="value">The header value.</param>
    /// <param name="isProtected">A flag to indicate if the header is protected.</param>
    public CoseHeader(string label, TypeV value, bool isProtected)
    {
        Label = label;
        Value = value;
        IsProtected = isProtected;
    }

    /// <summary>
    /// A method to check if the header value is valid.
    /// </summary>
    /// <param name="validate">A function delegate that takes the value as input and returns a bool</param>
    /// <param name="value">The header value</param>
    /// <returns>True to indicate a valid value. False, otherwise.</returns>
    public static bool IsValid(Func<TypeV, bool> validate, TypeV value)
    {
        return validate(value);
    }
}
