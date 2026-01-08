// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation;

using CoseSign1.Validation.Builders;
using CoseSign1.Validation.Interfaces;

/// <summary>
/// Elegant entry point for building COSE validators.
/// </summary>
public static class Cose
{
    [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string ObsoleteSign1VerifierMessage = "Use Sign1Validator() or Sign1Message()";
    }

    /// <summary>
    /// Starts building a staged validator for COSE Sign1 messages.
    /// </summary>
    /// <remarks>
    /// This is the security-default entry point for V2. It enforces a staged model:
    /// key material extraction/resolution, trust establishment, signature verification, and post-signature checks.
    /// </remarks>
    /// <returns>A new validation builder instance.</returns>
    public static ICoseSign1ValidationBuilder Sign1Message()
    {
        return new CoseSign1ValidationBuilder();
    }

    /// <summary>
    /// Starts building a staged validator for COSE Sign1 messages.
    /// </summary>
    /// <returns>A new validation builder instance.</returns>
    public static ICoseSign1ValidationBuilder Sign1Validator()
    {
        return Sign1Message();
    }

    /// <summary>
    /// Legacy alias for <see cref="Sign1Validator"/>.
    /// </summary>
    /// <returns>A new validation builder instance.</returns>
    [Obsolete(ClassStrings.ObsoleteSign1VerifierMessage)]
    public static ICoseSign1ValidationBuilder Sign1Verifier() => Sign1Validator();
}