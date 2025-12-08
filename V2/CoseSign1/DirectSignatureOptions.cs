using CoseSign1.Abstractions;

namespace CoseSign1;

/// <summary>
/// Options specific to direct signature operations.
/// </summary>
public class DirectSignatureOptions : SigningOptions
{
    /// <summary>
    /// Gets or sets whether to embed the payload in the signature.
    /// Default is true (embedded payload).
    /// </summary>
    public bool EmbedPayload { get; set; } = true;
}
