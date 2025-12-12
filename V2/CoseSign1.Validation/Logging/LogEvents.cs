// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Logging;

/// <summary>
/// Defines event IDs for structured logging in the CoseSign1.Validation library.
/// </summary>
/// <remarks>
/// Event ID ranges for CoseSign1.Validation:
/// - 2000-2099: Validation operations
/// </remarks>
public static class LogEvents
{
    // Validation Operations (2000-2099)
    /// <summary>Starting a validation operation.</summary>
    public const int ValidationStarted = 2000;
    /// <summary>Validation operation completed.</summary>
    public const int ValidationCompleted = 2001;
    /// <summary>Validation operation failed.</summary>
    public const int ValidationFailed = 2002;
    /// <summary>Validator registered.</summary>
    public const int ValidatorRegistered = 2010;
    /// <summary>Validator executing.</summary>
    public const int ValidatorExecuting = 2020;
    /// <summary>Validator passed.</summary>
    public const int ValidatorPassed = 2021;
    /// <summary>Validator failed with specific error.</summary>
    public const int ValidatorFailure = 2022;
    /// <summary>Signature verification result.</summary>
    public const int SignatureVerified = 2030;
    /// <summary>Signature verification failed.</summary>
    public const int SignatureVerificationFailed = 2031;
}