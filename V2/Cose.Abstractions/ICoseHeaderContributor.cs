// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Cose.Abstractions;

using System.Security.Cryptography.Cose;

/// <summary>
/// Defines how to handle conflicts when a header already exists in the map.
/// </summary>
public enum HeaderMergeStrategy
{
    /// <summary>
    /// Throw an exception if the header already exists.
    /// This is the safest default behavior.
    /// </summary>
    Fail,

    /// <summary>
    /// Skip adding the header if it already exists (keep existing value).
    /// </summary>
    KeepExisting,

    /// <summary>
    /// Replace the existing header value with the new one.
    /// </summary>
    Replace,

    /// <summary>
    /// Allow the contributor to decide based on the existing value.
    /// The contributor's Contribute method will be called and can inspect existing headers.
    /// </summary>
    Custom
}

/// <summary>
/// Contributes headers to COSE messages independent of any specific COSE message type.
/// This is the generic COSE header contribution interface per RFC 9052.
/// All COSE message types (Sign1, Sign, Encrypt0, Encrypt, Mac0, Mac) share
/// the same protected/unprotected header structure.
/// </summary>
/// <remarks>
/// <para>
/// Implementations MUST be thread-safe as they may be called concurrently.
/// Contributors should be immutable or use thread-safe operations.
/// </para>
/// <para>
/// For COSE Sign1-specific header contribution that requires access to the signing key,
/// use <c>ICoseSign1HeaderContributor</c> from CoseSign1.Abstractions instead.
/// </para>
/// </remarks>
public interface ICoseHeaderContributor
{
    /// <summary>
    /// Gets the merge strategy for handling conflicts when headers already exist.
    /// Default behavior should be Fail for safety.
    /// </summary>
    /// <value>The merge strategy to use when a contributed header already exists.</value>
    HeaderMergeStrategy MergeStrategy { get; }

    /// <summary>
    /// Contributes protected headers. Called during message creation.
    /// MUST be thread-safe — may be called concurrently from multiple threads.
    /// </summary>
    /// <param name="headers">The header map to contribute to. May already contain headers.</param>
    void ContributeProtectedHeaders(CoseHeaderMap headers);

    /// <summary>
    /// Contributes unprotected headers. Called during message creation.
    /// MUST be thread-safe — may be called concurrently from multiple threads.
    /// </summary>
    /// <param name="headers">The header map to contribute to. May already contain headers.</param>
    void ContributeUnprotectedHeaders(CoseHeaderMap headers);
}