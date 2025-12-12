// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Collections.Generic;
using System.Collections.ObjectModel;

namespace CoseSign1.Abstractions;

/// <summary>
/// Metadata about a signing service, including its name, description, and capabilities.
/// </summary>
public class SigningServiceMetadata
{
    /// <summary>
    /// Initializes a new instance of the <see cref="SigningServiceMetadata"/> class.
    /// </summary>
    /// <param name="serviceName">The name of the signing service.</param>
    /// <param name="description">A description of the signing service.</param>
    /// <param name="additionalData">Optional additional metadata about the service.</param>
    public SigningServiceMetadata(
        string serviceName,
        string? description = null,
        IDictionary<string, object>? additionalData = null)
    {
        ServiceName = serviceName ?? throw new ArgumentNullException(nameof(serviceName));
        Description = description ?? string.Empty;
        AdditionalData = additionalData != null
            ? new ReadOnlyDictionary<string, object>(new Dictionary<string, object>(additionalData))
            : new ReadOnlyDictionary<string, object>(new Dictionary<string, object>());
    }

    /// <summary>
    /// Gets the name of the signing service.
    /// </summary>
    public string ServiceName { get; }

    /// <summary>
    /// Gets a description of the signing service.
    /// </summary>
    public string Description { get; }

    /// <summary>
    /// Gets additional metadata about the service.
    /// </summary>
    public IReadOnlyDictionary<string, object> AdditionalData { get; }

    /// <summary>
    /// Returns a string representation of the signing service metadata.
    /// </summary>
    public override string ToString()
    {
        return $"SigningServiceMetadata[ServiceName={ServiceName}]";
    }
}