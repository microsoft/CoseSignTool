// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation;

/// <summary>
/// Elegant entry point for building COSE validators.
/// </summary>
public static class Cose
{
    /// <summary>
    /// Starts building a validator for COSE Sign1 messages.
    /// </summary>
    /// <returns>A new validation builder instance.</returns>
    public static ICoseMessageValidationBuilder Sign1Message()
    {
        return new CoseMessageValidationBuilder();
    }
}
