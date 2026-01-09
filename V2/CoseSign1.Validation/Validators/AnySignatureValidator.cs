// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Validators;

using System.Diagnostics.CodeAnalysis;
using CoseSign1.Validation.Interfaces;
using CoseSign1.Validation.Results;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Executes a set of signature validators and requires that at least one applicable validator succeeds.
/// Intended for scenarios where multiple signature schemes may be present (e.g., X.509 vs embedded COSE_Key).
/// </summary>
public sealed partial class AnySignatureValidator : IValidator
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public static readonly string ValidatorName = nameof(AnySignatureValidator);

        public static readonly string ErrorCodeNullInput = "NULL_INPUT";
        public static readonly string ErrorMessageNullInput = "Input message is null";

        public static readonly string ErrorCodeNoApplicableValidator = "NO_APPLICABLE_SIGNATURE_VALIDATOR";
        public static readonly string ErrorMessageNoApplicableValidator = "No applicable signature verifier was found for this message";

        public static readonly string NotApplicableReasonUnsupportedStageFormat = "Unsupported validation stage: {0}";

        public static readonly string MetadataKeySelectedValidator = "SelectedValidator";
    }

    #region LoggerMessage methods

    [LoggerMessage(
        EventId = 2001,
        Level = LogLevel.Debug,
        Message = "Starting signature verification. CandidateValidators: {ValidatorCount}")]
    private partial void LogSignatureVerificationStarted(int validatorCount);

    [LoggerMessage(
        EventId = 2002,
        Level = LogLevel.Trace,
        Message = "Skipping validator (not applicable): {ValidatorType}")]
    private partial void LogValidatorSkipped(string validatorType);

    [LoggerMessage(
        EventId = 2003,
        Level = LogLevel.Trace,
        Message = "Executing signature validator: {ValidatorType}")]
    private partial void LogValidatorExecuting(string validatorType);

    [LoggerMessage(
        EventId = 2004,
        Level = LogLevel.Debug,
        Message = "Signature validator passed: {ValidatorType}")]
    private partial void LogValidatorPassed(string validatorType);

    [LoggerMessage(
        EventId = 2005,
        Level = LogLevel.Debug,
        Message = "Signature validator failed: {ValidatorType}. FailureCount: {FailureCount}")]
    private partial void LogValidatorFailed(string validatorType, int failureCount);

    [LoggerMessage(
        EventId = 2006,
        Level = LogLevel.Information,
        Message = "No applicable signature validator found")]
    private partial void LogNoApplicableValidator();

    [LoggerMessage(
        EventId = 2007,
        Level = LogLevel.Debug,
        Message = "Signature verification succeeded using {ValidatorType}")]
    private partial void LogSignatureVerificationSucceeded(string validatorType);

    [LoggerMessage(
        EventId = 2008,
        Level = LogLevel.Information,
        Message = "Signature verification failed. TotalFailures: {FailureCount}")]
    private partial void LogSignatureVerificationFailed(int failureCount);

    #endregion

    private readonly IReadOnlyList<IValidator> Validators;
    private readonly ILogger<AnySignatureValidator> Logger;
    private static readonly IReadOnlyCollection<ValidationStage> StagesField = new[] { ValidationStage.Signature };

    /// <summary>
    /// Initializes a new instance of the <see cref="AnySignatureValidator"/> class.
    /// </summary>
    /// <param name="validators">The candidate signature validators to execute.</param>
    /// <param name="logger">Optional logger for diagnostic output. If null, logging is disabled.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="validators"/> is null.</exception>
    public AnySignatureValidator(IEnumerable<IValidator> validators, ILogger<AnySignatureValidator>? logger = null)
    {
        Validators = validators?.ToList() ?? throw new ArgumentNullException(nameof(validators));
        Logger = logger ?? NullLogger<AnySignatureValidator>.Instance;
    }

    /// <inheritdoc/>
    public IReadOnlyCollection<ValidationStage> Stages => StagesField;

    /// <inheritdoc/>
    public ValidationResult Validate(CoseSign1Message input, ValidationStage stage)
    {
        if (input is null)
        {
            return ValidationResult.Failure(ClassStrings.ValidatorName, stage, ClassStrings.ErrorMessageNullInput, ClassStrings.ErrorCodeNullInput);
        }

        if (stage != ValidationStage.Signature)
        {
            return ValidationResult.NotApplicable(
                ClassStrings.ValidatorName,
                stage,
                string.Format(ClassStrings.NotApplicableReasonUnsupportedStageFormat, stage));
        }

        LogSignatureVerificationStarted(Validators.Count);

        var failures = new List<ValidationFailure>();
        bool executedAny = false;

        foreach (var validator in Validators)
        {
            if (!validator.Stages.Contains(stage))
            {
                LogValidatorSkipped(validator.GetType().Name);
                continue;
            }

            if (validator is IConditionalValidator conditional && !conditional.IsApplicable(input, stage))
            {
                LogValidatorSkipped(validator.GetType().Name);
                continue;
            }

            LogValidatorExecuting(validator.GetType().Name);

            executedAny = true;
            var result = validator.Validate(input, stage);
            if (result.IsNotApplicable)
            {
                LogValidatorSkipped(validator.GetType().Name);
                executedAny = false;
                continue;
            }

            if (result.IsValid)
            {
                LogValidatorPassed(validator.GetType().Name);

                var metadata = new Dictionary<string, object>();
                foreach (var kvp in result.Metadata)
                {
                    metadata[kvp.Key] = kvp.Value;
                }

                metadata[ClassStrings.MetadataKeySelectedValidator] = result.ValidatorName;

                LogSignatureVerificationSucceeded(validator.GetType().Name);

                return ValidationResult.Success(ClassStrings.ValidatorName, stage, metadata);
            }

            if (result.IsFailure)
            {
                LogValidatorFailed(validator.GetType().Name, result.Failures.Count);
                failures.AddRange(result.Failures);
            }
        }

        if (!executedAny)
        {
            LogNoApplicableValidator();

            return ValidationResult.Failure(
                ClassStrings.ValidatorName,
                stage,
                ClassStrings.ErrorMessageNoApplicableValidator,
                ClassStrings.ErrorCodeNoApplicableValidator);
        }

        if (failures.Count == 0)
        {
            failures.Add(new ValidationFailure
            {
                ErrorCode = ClassStrings.ErrorCodeNoApplicableValidator,
                Message = ClassStrings.ErrorMessageNoApplicableValidator
            });
        }

        LogSignatureVerificationFailed(failures.Count);

        return ValidationResult.Failure(ClassStrings.ValidatorName, stage, failures.ToArray());
    }

    /// <inheritdoc/>
    public async Task<ValidationResult> ValidateAsync(CoseSign1Message input, ValidationStage stage, CancellationToken cancellationToken = default)
    {
        if (input is null)
        {
            return ValidationResult.Failure(ClassStrings.ValidatorName, stage, ClassStrings.ErrorMessageNullInput, ClassStrings.ErrorCodeNullInput);
        }

        if (stage != ValidationStage.Signature)
        {
            return ValidationResult.NotApplicable(
                ClassStrings.ValidatorName,
                stage,
                string.Format(ClassStrings.NotApplicableReasonUnsupportedStageFormat, stage));
        }

        var failures = new List<ValidationFailure>();
        bool executedAny = false;

        foreach (var validator in Validators)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!validator.Stages.Contains(stage))
            {
                continue;
            }

            if (validator is IConditionalValidator conditional && !conditional.IsApplicable(input, stage))
            {
                continue;
            }

            executedAny = true;
            var result = await validator.ValidateAsync(input, stage, cancellationToken).ConfigureAwait(false);
            if (result.IsNotApplicable)
            {
                executedAny = false;
                continue;
            }

            if (result.IsValid)
            {
                var metadata = new Dictionary<string, object>();
                foreach (var kvp in result.Metadata)
                {
                    metadata[kvp.Key] = kvp.Value;
                }

                metadata[ClassStrings.MetadataKeySelectedValidator] = result.ValidatorName;

                return ValidationResult.Success(ClassStrings.ValidatorName, stage, metadata);
            }

            if (result.IsFailure)
            {
                failures.AddRange(result.Failures);
            }
        }

        if (!executedAny)
        {
            return ValidationResult.Failure(
                ClassStrings.ValidatorName,
                stage,
                ClassStrings.ErrorMessageNoApplicableValidator,
                ClassStrings.ErrorCodeNoApplicableValidator);
        }

        return ValidationResult.Failure(ClassStrings.ValidatorName, stage, failures.ToArray());
    }
}
