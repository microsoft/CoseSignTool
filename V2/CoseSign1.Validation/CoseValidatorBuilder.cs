// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation;

/// <summary>
/// Entry point for building COSE message validators.
/// </summary>
public static class CoseValidatorBuilder
{
    /// <summary>
    /// Starts building a validator for COSE Sign1 messages.
    /// </summary>
    /// <returns>A new validation builder instance.</returns>
    public static ICoseMessageValidationBuilder ForMessage()
    {
        return new CoseMessageValidationBuilder();
    }
}
