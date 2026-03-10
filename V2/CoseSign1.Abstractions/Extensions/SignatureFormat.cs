// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace System.Security.Cryptography.Cose;

/// <summary>
/// Specifies the signature format used by a COSE Sign1 message.
/// </summary>
public enum SignatureFormat
{
    /// <summary>
    /// Standard embedded or detached signature where the payload is signed directly.
    /// </summary>
    Direct,

    /// <summary>
    /// Legacy indirect signature with "+hash-sha256" style content-type extension.
    /// The payload contains a hash of the original content.
    /// </summary>
    IndirectHashLegacy,

    /// <summary>
    /// Indirect signature with "+cose-hash-v" content-type extension.
    /// Uses COSE Hash V format for the payload hash.
    /// </summary>
    IndirectCoseHashV,

    /// <summary>
    /// Indirect signature using COSE Hash Envelope format (RFC 9054).
    /// Uses headers 258, 259, and optionally 260 to describe the hash and original content.
    /// </summary>
    IndirectCoseHashEnvelope
}
