// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Validators;

using System.Diagnostics.CodeAnalysis;
using CoseSign1.Validation.Interfaces;
using CoseSign1.Validation.Results;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Combines multiple validators into a single composite validator.
/// Can run validators sequentially or in parallel and aggregate results.
/// </summary>
public sealed partial class CompositeValidator : IValidator
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string MetadataKeySeparator = ".";

        // Error codes and messages
        public static readonly string ValidatorName = "CompositeValidator";
        public static readonly string ErrorInputNull = "Input message is null";
        public static readonly string ErrorCodeNullInput = "NULL_INPUT";
    }

    #region LoggerMessage methods

    [LoggerMessage(
        EventId = 1001,
        Level = LogLevel.Warning,
        Message = "Validation failed: input message is null")]
    private partial void LogInputNull();

    [LoggerMessage(
        EventId = 1002,
        Level = LogLevel.Debug,
        Message = "Validation completed with no validators configured")]
    private partial void LogNoValidators();

    [LoggerMessage(
        EventId = 1003,
        Level = LogLevel.Debug,
        Message = "Starting validation with {ValidatorCount} validators. StopOnFirstFailure: {StopOnFirstFailure}, RunInParallel: {RunInParallel}")]
    private partial void LogValidationStarted(int validatorCount, bool stopOnFirstFailure, bool runInParallel);

    [LoggerMessage(
        EventId = 1004,
        Level = LogLevel.Trace,
        Message = "Executing validator: {ValidatorType}")]
    private partial void LogExecutingValidator(string validatorType);

    [LoggerMessage(
        EventId = 1005,
        Level = LogLevel.Trace,
        Message = "Skipping validator (not applicable): {ValidatorType}")]
    private partial void LogSkippingValidator(string validatorType);

    [LoggerMessage(
        EventId = 1006,
        Level = LogLevel.Debug,
        Message = "Validator {ValidatorType} failed with {FailureCount} failures")]
    private partial void LogValidatorFailed(string validatorType, int failureCount);

    [LoggerMessage(
        EventId = 1007,
        Level = LogLevel.Debug,
        Message = "Stopping validation on first failure")]
    private partial void LogStoppingOnFirstFailure();

    [LoggerMessage(
        EventId = 1008,
        Level = LogLevel.Trace,
        Message = "Validator {ValidatorType} passed")]
    private partial void LogValidatorPassed(string validatorType);

    [LoggerMessage(
        EventId = 1009,
        Level = LogLevel.Information,
        Message = "Validation failed with {FailureCount} total failures")]
    private partial void LogValidationFailed(int failureCount);

    [LoggerMessage(
        EventId = 1010,
        Level = LogLevel.Debug,
        Message = "All {ValidatorCount} validators passed successfully")]
    private partial void LogAllValidatorsPassed(int validatorCount);

    #endregion

    private readonly IReadOnlyList<IValidator> Validators;
    private readonly IReadOnlyCollection<ValidationStage> StagesField;
    private readonly bool StopOnFirstFailureField;
    private readonly bool RunInParallelField;
    private readonly ILogger<CompositeValidator> Logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="CompositeValidator"/> class.
    /// </summary>
    /// <param name="validators">The validators to combine.</param>
    /// <param name="stopOnFirstFailure">Whether to stop on first failure.</param>
    /// <param name="runInParallel">Whether to run validators in parallel.</param>
    /// <param name="logger">Optional logger for diagnostic output. If null, logging is disabled.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="validators"/> is null.</exception>
    public CompositeValidator(
        IEnumerable<IValidator> validators,
        bool stopOnFirstFailure = false,
        bool runInParallel = false,
        ILogger<CompositeValidator>? logger = null)
    {
        Validators = validators?.ToList() ?? throw new ArgumentNullException(nameof(validators));

        var stageSet = new HashSet<ValidationStage>();
        foreach (var validator in Validators)
        {
            if (validator?.Stages is null)
            {
                continue;
            }

            foreach (var stage in validator.Stages)
            {
                stageSet.Add(stage);
            }
        }
        StagesField = stageSet.ToArray();

        StopOnFirstFailureField = stopOnFirstFailure;
        RunInParallelField = runInParallel;
        Logger = logger ?? NullLogger<CompositeValidator>.Instance;
    }

    /// <inheritdoc/>
    public IReadOnlyCollection<ValidationStage> Stages => StagesField;

    /// <summary>
    /// Validates the input using all composed validators.
    /// </summary>
    /// <param name="input">The COSE Sign1 message to validate.</param>
    /// <param name="stage">The validation stage being executed.</param>
    /// <returns>An aggregated validation result.</returns>
    public ValidationResult Validate(CoseSign1Message input, ValidationStage stage)
    {
        if (input == null)
        {
            LogInputNull();
            return ValidationResult.Failure(ClassStrings.ValidatorName, ClassStrings.ErrorInputNull, ClassStrings.ErrorCodeNullInput);
        }

        if (Validators.Count == 0)
        {
            LogNoValidators();
            return ValidationResult.Success(ClassStrings.ValidatorName);
        }

        LogValidationStarted(Validators.Count, StopOnFirstFailureField, RunInParallelField);

        var results = new List<ValidationResult>();
        var allFailures = new List<ValidationFailure>();

        foreach (var validator in Validators)
        {
            if (!validator.Stages.Contains(stage))
            {
                continue;
            }

            if (validator is IConditionalValidator conditional && !conditional.IsApplicable(input, stage))
            {
                LogSkippingValidator(validator.GetType().Name);
                continue;
            }

            LogExecutingValidator(validator.GetType().Name);

            var result = validator.Validate(input, stage);
            results.Add(result);

            if (result.IsNotApplicable)
            {
                LogSkippingValidator(validator.GetType().Name);
                continue;
            }

            if (result.IsFailure)
            {
                LogValidatorFailed(validator.GetType().Name, result.Failures.Count);
                allFailures.AddRange(result.Failures);

                if (StopOnFirstFailureField)
                {
                    LogStoppingOnFirstFailure();
                    break;
                }
            }
            else
            {
                LogValidatorPassed(validator.GetType().Name);
            }
        }

        if (allFailures.Count > 0)
        {
            LogValidationFailed(allFailures.Count);
            return ValidationResult.Failure(ClassStrings.ValidatorName, allFailures.ToArray());
        }

        LogAllValidatorsPassed(Validators.Count);

        // Merge metadata from all successful validators
        var mergedMetadata = new Dictionary<string, object>();
        foreach (var result in results)
        {
            if (!result.IsValid)
            {
                continue;
            }

            foreach (var kvp in result.Metadata)
            {
                mergedMetadata[string.Concat(result.ValidatorName, ClassStrings.MetadataKeySeparator, kvp.Key)] = kvp.Value;
            }
        }

        return ValidationResult.Success(ClassStrings.ValidatorName, stage, mergedMetadata);
    }

    /// <summary>
    /// Asynchronously validates the input using all composed validators.
    /// </summary>
    /// <param name="input">The COSE Sign1 message to validate.</param>
    /// <param name="stage">The validation stage being executed.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A task representing the asynchronous validation operation.</returns>
    public async Task<ValidationResult> ValidateAsync(CoseSign1Message input, ValidationStage stage, CancellationToken cancellationToken = default)
    {
        if (input == null)
        {
            return ValidationResult.Failure(ClassStrings.ValidatorName, ClassStrings.ErrorInputNull, ClassStrings.ErrorCodeNullInput);
        }

        if (Validators.Count == 0)
        {
            return ValidationResult.Success(ClassStrings.ValidatorName);
        }

        var allFailures = new List<ValidationFailure>();
        var results = new List<ValidationResult>();

        if (RunInParallelField)
        {
            // Run validators in parallel
            var applicableValidators = Validators
                .Where(v => v.Stages.Contains(stage))
                .Where(v => v is not IConditionalValidator c || c.IsApplicable(input, stage))
                .ToArray();

            var tasks = applicableValidators.Select(v => v.ValidateAsync(input, stage, cancellationToken));
            var parallelResults = await Task.WhenAll(tasks).ConfigureAwait(false);
            results.AddRange(parallelResults);

            foreach (var result in parallelResults)
            {
                if (result.IsFailure)
                {
                    allFailures.AddRange(result.Failures);
                }
            }
        }
        else
        {
            // Run validators sequentially
            foreach (var validator in Validators)
            {
                if (!validator.Stages.Contains(stage))
                {
                    continue;
                }

                if (validator is IConditionalValidator conditional && !conditional.IsApplicable(input, stage))
                {
                    continue;
                }

                var result = await validator.ValidateAsync(input, stage, cancellationToken).ConfigureAwait(false);
                results.Add(result);

                if (result.IsNotApplicable)
                {
                    continue;
                }

                if (result.IsFailure)
                {
                    allFailures.AddRange(result.Failures);

                    if (StopOnFirstFailureField)
                    {
                        break;
                    }
                }
            }
        }

        if (allFailures.Count > 0)
        {
            return ValidationResult.Failure(ClassStrings.ValidatorName, allFailures.ToArray());
        }

        // Merge metadata from all successful validators
        var mergedMetadata = new Dictionary<string, object>();
        foreach (var result in results)
        {
            if (!result.IsValid)
            {
                continue;
            }

            foreach (var kvp in result.Metadata)
            {
                mergedMetadata[string.Concat(result.ValidatorName, ClassStrings.MetadataKeySeparator, kvp.Key)] = kvp.Value;
            }
        }

        return ValidationResult.Success(ClassStrings.ValidatorName, stage, mergedMetadata);
    }
}