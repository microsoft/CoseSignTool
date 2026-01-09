// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation;

using CoseSign1.Validation.Builders;
using CoseSign1.Validation.Interfaces;
using Microsoft.Extensions.Logging;

/// <summary>
/// Elegant entry point for building COSE validators.
/// </summary>
public static class Cose
{
    /// <summary>
    /// Starts building a staged validator for COSE Sign1 messages.
    /// </summary>
    /// <remarks>
    /// This is the security-default entry point for V2. It enforces a staged model:
    /// key material extraction/resolution, trust establishment, signature verification, and post-signature checks.
    /// </remarks>
    /// <param name="loggerFactory">Optional logger factory for creating loggers in validators.</param>
    /// <returns>A new validation builder instance.</returns>
    public static ICoseSign1ValidationBuilder Sign1Message(ILoggerFactory? loggerFactory = null)
    {
        return new CoseSign1ValidationBuilder(loggerFactory);
    }
}