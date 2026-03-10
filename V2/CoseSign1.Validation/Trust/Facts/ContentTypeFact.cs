// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.Facts;

using CoseSign1.Abstractions;

/// <summary>
/// Provides the logical content type of the payload being protected by a COSE Sign1 message.
/// </summary>
public sealed class ContentTypeFact : IMessageFact
{
    /// <inheritdoc />
    public TrustFactScope Scope => TrustFactScope.Message;

    /// <summary>
    /// Initializes a new instance of the <see cref="ContentTypeFact"/> class.
    /// </summary>
    /// <param name="contentType">The resolved content type.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="contentType"/> is null.</exception>
    public ContentTypeFact(string contentType)
    {
        Guard.ThrowIfNull(contentType);
        ContentType = contentType;
    }

    /// <summary>
    /// Gets the resolved content type.
    /// </summary>
    public string ContentType { get; }
}
