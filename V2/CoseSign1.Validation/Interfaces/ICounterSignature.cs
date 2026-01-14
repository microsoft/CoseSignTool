// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Interfaces;

using CoseSign1.Abstractions;

/// <summary>
/// Represents a resolved COSE counter-signature along with the signing key used to validate it.
/// </summary>
/// <remarks>
/// <para>
/// Counter-signatures are resolved by <see cref="ICounterSignatureResolver"/> implementations that understand the
/// specific counter-signature format and how to locate/resolve the signing key material used to validate it.
/// </para>
/// <para>
/// The <see cref="RawCounterSignatureBytes"/> are treated as immutable by convention.
/// </para>
/// </remarks>
public interface ICounterSignature
{
    /// <summary>
    /// Gets the raw bytes of the counter-signature structure.
    /// </summary>
    byte[] RawCounterSignatureBytes { get; }

    /// <summary>
    /// Gets a value indicating whether the counter-signature was discovered in protected headers.
    /// </summary>
    bool IsProtectedHeader { get; }

    /// <summary>
    /// Gets the signing key used to validate this counter-signature.
    /// </summary>
    ISigningKey SigningKey { get; }
}
