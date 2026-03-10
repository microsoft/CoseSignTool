// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Abstractions;

using System.Collections.ObjectModel;

/// <summary>
/// Metadata about a signing service, including its name, description, and capabilities.
/// </summary>
public class SigningServiceMetadata
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string ToStringFormat = "SigningServiceMetadata[ServiceName={0}]";
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="SigningServiceMetadata"/> class.
    /// </summary>
    /// <param name="serviceName">The name of the signing service.</param>
    /// <param name="description">A description of the signing service.</param>
    /// <param name="additionalData">Optional additional metadata about the service.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="serviceName"/> is <see langword="null"/>.</exception>
    public SigningServiceMetadata(
        string serviceName,
        string? description = null,
        IDictionary<string, object>? additionalData = null)
    {
        Guard.ThrowIfNull(serviceName);
        ServiceName = serviceName;
        Description = description ?? string.Empty;
        AdditionalData = additionalData != null
            ? new ReadOnlyDictionary<string, object>(new Dictionary<string, object>(additionalData))
            : new ReadOnlyDictionary<string, object>(new Dictionary<string, object>());
    }

    /// <summary>
    /// Gets the name of the signing service.
    /// </summary>
    /// <value>The name of the signing service.</value>
    public string ServiceName { get; }

    /// <summary>
    /// Gets a description of the signing service.
    /// </summary>
    /// <value>A description of the signing service.</value>
    public string Description { get; }

    /// <summary>
    /// Gets additional metadata about the service.
    /// </summary>
    /// <value>Additional metadata about the service.</value>
    public IReadOnlyDictionary<string, object> AdditionalData { get; }

    /// <summary>
    /// Returns a string representation of the signing service metadata.
    /// </summary>
    /// <returns>A string representation of the signing service metadata.</returns>
    public override string ToString()
    {
        return string.Format(ClassStrings.ToStringFormat, ServiceName);
    }
}