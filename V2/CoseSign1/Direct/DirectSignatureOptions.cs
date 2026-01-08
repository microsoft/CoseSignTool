// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Direct;

/// <summary>
/// Options specific to direct signature operations.
/// </summary>
public class DirectSignatureOptions : SigningOptions
{
    /// <summary>
    /// Gets or sets whether to embed the payload in the signature.
    /// Default is true (embedded payload).
    /// </summary>
    public virtual bool EmbedPayload { get; set; } = true;
}