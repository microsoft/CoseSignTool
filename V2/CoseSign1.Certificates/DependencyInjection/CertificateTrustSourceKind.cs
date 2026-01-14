// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Trust;

/// <summary>
/// Identifies the certificate trust source mode used during chain evaluation.
/// </summary>
public enum CertificateTrustSourceKind
{
    /// <summary>
    /// No trust source configured.
    /// </summary>
    None,

    /// <summary>
    /// Build a chain using system trust roots.
    /// </summary>
    System,

    /// <summary>
    /// Build a chain using a caller-supplied custom root store.
    /// </summary>
    CustomRoot,

    /// <summary>
    /// Build a chain using only the certificates embedded in the message (x5chain),
    /// allowing unknown roots (typically paired with identity pinning).
    /// </summary>
    EmbeddedChainOnly,
}
