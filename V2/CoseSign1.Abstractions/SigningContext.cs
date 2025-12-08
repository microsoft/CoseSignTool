using System.Collections.Generic;

namespace CoseSign1.Abstractions;

/// <summary>
/// Context information for a signing operation.
/// Contains the payload and per-operation metadata.
/// This is passed to header contributors at sign-time.
/// </summary>
public class SigningContext
{
    /// <summary>
    /// Initializes a new instance of the <see cref="SigningContext"/> class.
    /// </summary>
    public SigningContext(
        byte[] payload,
        string? contentType = null,
        IReadOnlyList<IHeaderContributor>? additionalHeaderContributors = null,
        IDictionary<string, object>? additionalContext = null)
    {
        Payload = payload ?? throw new ArgumentNullException(nameof(payload));
        ContentType = contentType;
        AdditionalHeaderContributors = additionalHeaderContributors;
        AdditionalContext = additionalContext;
    }

    /// <summary>
    /// Gets the payload to be signed.
    /// </summary>
    public byte[] Payload { get; }
    
    /// <summary>
    /// Gets the optional content type of the payload (e.g., "application/json").
    /// May be used by header contributors or for validation.
    /// </summary>
    public string? ContentType { get; }
    
    /// <summary>
    /// Gets additional header contributors to apply for this specific operation.
    /// Applied after the signing service's required contributors.
    /// </summary>
    public IReadOnlyList<IHeaderContributor>? AdditionalHeaderContributors { get; }
    
    /// <summary>
    /// Gets additional context for custom header contributors.
    /// </summary>
    public IDictionary<string, object>? AdditionalContext { get; }
}
