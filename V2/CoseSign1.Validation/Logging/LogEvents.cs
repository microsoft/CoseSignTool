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
    /// <summary>Validator executing.</summary>
    public const int ValidatorExecuting = 2020;
    /// <summary>Validator passed.</summary>
    public const int ValidatorPassed = 2021;
    /// <summary>Validator failed with specific error.</summary>
    public const int ValidatorFailure = 2022;

    // Static EventId instances to avoid allocations on each log call
    /// <summary>EventId for validation started.</summary>
    public static readonly EventId ValidationStartedEvent = new(ValidationStarted, nameof(ValidationStarted));
    /// <summary>EventId for validation completed.</summary>
    public static readonly EventId ValidationCompletedEvent = new(ValidationCompleted, nameof(ValidationCompleted));
    /// <summary>EventId for validation failed.</summary>
    public static readonly EventId ValidationFailedEvent = new(ValidationFailed, nameof(ValidationFailed));
    /// <summary>EventId for validator executing.</summary>
    public static readonly EventId ValidatorExecutingEvent = new(ValidatorExecuting, nameof(ValidatorExecuting));
    /// <summary>EventId for validator passed.</summary>
    public static readonly EventId ValidatorPassedEvent = new(ValidatorPassed, nameof(ValidatorPassed));
    /// <summary>EventId for validator failure.</summary>
    public static readonly EventId ValidatorFailureEvent = new(ValidatorFailure, nameof(ValidatorFailure));
}