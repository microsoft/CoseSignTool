// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Logging;

/// <summary>
/// Defines event IDs for structured logging in the CoseSign1.Validation library.
/// </summary>
/// <remarks>
/// Event ID ranges for CoseSign1.Validation:
/// - 2000-2009: Overall validation lifecycle
/// - 2010-2019: Stage-level operations
/// - 2020-2029: Individual validator operations
/// - 2030-2039: Trust policy evaluation
/// - 2040-2049: Signature validation specifics
/// </remarks>
public static class LogEvents
{
    // Overall Validation Lifecycle (2000-2009)
    /// <summary>Starting a validation operation.</summary>
    public const int ValidationStarted = 2000;
    /// <summary>Validation operation completed.</summary>
    public const int ValidationCompleted = 2001;
    /// <summary>Validation operation failed.</summary>
    public const int ValidationFailed = 2002;
    /// <summary>Validation skipped (not applicable).</summary>
    public const int ValidationSkipped = 2003;

    // Stage-Level Operations (2010-2019)
    /// <summary>Validation stage started.</summary>
    public const int StageStarted = 2010;
    /// <summary>Validation stage completed.</summary>
    public const int StageCompleted = 2011;
    /// <summary>Validation stage failed.</summary>
    public const int StageFailed = 2012;
    /// <summary>Validation stage skipped.</summary>
    public const int StageSkipped = 2013;

    // Individual Validator Operations (2020-2029)
    /// <summary>Validator executing.</summary>
    public const int ValidatorExecuting = 2020;
    /// <summary>Validator passed.</summary>
    public const int ValidatorPassed = 2021;
    /// <summary>Validator failed with specific error.</summary>
    public const int ValidatorFailure = 2022;
    /// <summary>Validator skipped (not applicable).</summary>
    public const int ValidatorSkipped = 2023;
    /// <summary>Validator selected (for any-of validators).</summary>
    public const int ValidatorSelected = 2024;

    // Trust Policy Evaluation (2030-2039)
    /// <summary>Trust policy evaluation started.</summary>
    public const int TrustPolicyEvaluationStarted = 2030;
    /// <summary>Trust policy satisfied.</summary>
    public const int TrustPolicySatisfied = 2031;
    /// <summary>Trust policy not satisfied.</summary>
    public const int TrustPolicyNotSatisfied = 2032;
    /// <summary>Trust assertion recorded.</summary>
    public const int TrustAssertionRecorded = 2033;

    // Signature Validation Specifics (2040-2049)
    /// <summary>Signature verification started.</summary>
    public const int SignatureVerificationStarted = 2040;
    /// <summary>Signature verification succeeded.</summary>
    public const int SignatureVerificationSucceeded = 2041;
    /// <summary>Signature verification failed.</summary>
    public const int SignatureVerificationFailed = 2042;

    // Static EventId instances to avoid allocations on each log call
    /// <summary>EventId for validation started.</summary>
    public static readonly EventId ValidationStartedEvent = new(ValidationStarted, nameof(ValidationStarted));
    /// <summary>EventId for validation completed.</summary>
    public static readonly EventId ValidationCompletedEvent = new(ValidationCompleted, nameof(ValidationCompleted));
    /// <summary>EventId for validation failed.</summary>
    public static readonly EventId ValidationFailedEvent = new(ValidationFailed, nameof(ValidationFailed));
    /// <summary>EventId for validation skipped.</summary>
    public static readonly EventId ValidationSkippedEvent = new(ValidationSkipped, nameof(ValidationSkipped));
    /// <summary>EventId for stage started.</summary>
    public static readonly EventId StageStartedEvent = new(StageStarted, nameof(StageStarted));
    /// <summary>EventId for stage completed.</summary>
    public static readonly EventId StageCompletedEvent = new(StageCompleted, nameof(StageCompleted));
    /// <summary>EventId for stage failed.</summary>
    public static readonly EventId StageFailedEvent = new(StageFailed, nameof(StageFailed));
    /// <summary>EventId for stage skipped.</summary>
    public static readonly EventId StageSkippedEvent = new(StageSkipped, nameof(StageSkipped));
    /// <summary>EventId for validator executing.</summary>
    public static readonly EventId ValidatorExecutingEvent = new(ValidatorExecuting, nameof(ValidatorExecuting));
    /// <summary>EventId for validator passed.</summary>
    public static readonly EventId ValidatorPassedEvent = new(ValidatorPassed, nameof(ValidatorPassed));
    /// <summary>EventId for validator failure.</summary>
    public static readonly EventId ValidatorFailureEvent = new(ValidatorFailure, nameof(ValidatorFailure));
    /// <summary>EventId for validator skipped.</summary>
    public static readonly EventId ValidatorSkippedEvent = new(ValidatorSkipped, nameof(ValidatorSkipped));
    /// <summary>EventId for validator selected.</summary>
    public static readonly EventId ValidatorSelectedEvent = new(ValidatorSelected, nameof(ValidatorSelected));
    /// <summary>EventId for trust policy evaluation started.</summary>
    public static readonly EventId TrustPolicyEvaluationStartedEvent = new(TrustPolicyEvaluationStarted, nameof(TrustPolicyEvaluationStarted));
    /// <summary>EventId for trust policy satisfied.</summary>
    public static readonly EventId TrustPolicySatisfiedEvent = new(TrustPolicySatisfied, nameof(TrustPolicySatisfied));
    /// <summary>EventId for trust policy not satisfied.</summary>
    public static readonly EventId TrustPolicyNotSatisfiedEvent = new(TrustPolicyNotSatisfied, nameof(TrustPolicyNotSatisfied));
    /// <summary>EventId for trust assertion recorded.</summary>
    public static readonly EventId TrustAssertionRecordedEvent = new(TrustAssertionRecorded, nameof(TrustAssertionRecorded));
    /// <summary>EventId for signature verification started.</summary>
    public static readonly EventId SignatureVerificationStartedEvent = new(SignatureVerificationStarted, nameof(SignatureVerificationStarted));
    /// <summary>EventId for signature verification succeeded.</summary>
    public static readonly EventId SignatureVerificationSucceededEvent = new(SignatureVerificationSucceeded, nameof(SignatureVerificationSucceeded));
    /// <summary>EventId for signature verification failed.</summary>
    public static readonly EventId SignatureVerificationFailedEvent = new(SignatureVerificationFailed, nameof(SignatureVerificationFailed));
}