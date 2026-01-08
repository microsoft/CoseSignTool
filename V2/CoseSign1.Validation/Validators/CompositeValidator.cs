// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Diagnostics.CodeAnalysis;
using CoseSign1.Validation.Logging;
using CoseSign1.Validation.Interfaces;
using CoseSign1.Validation.Results;
using Microsoft.Extensions.Logging.Abstractions;

namespace CoseSign1.Validation.Validators;

/// <summary>
/// Combines multiple validators into a single composite validator.
/// Can run validators sequentially or in parallel and aggregate results.
/// </summary>
public sealed class CompositeValidator : IValidator
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        // Log message templates
        public static readonly string LogInputNull = "Validation failed: input message is null";
        public static readonly string LogNoValidators = "Validation completed with no validators configured";
        public static readonly string LogValidationStarted = "Starting validation with {ValidatorCount} validators. StopOnFirstFailure: {StopOnFirstFailure}, RunInParallel: {RunInParallel}";
        public static readonly string LogExecutingValidator = "Executing validator: {ValidatorType}";
        public static readonly string LogSkippingValidator = "Skipping validator (not applicable): {ValidatorType}";
        public static readonly string LogValidatorFailed = "Validator {ValidatorType} failed with {FailureCount} failures";
        public static readonly string LogStoppingOnFirstFailure = "Stopping validation on first failure";
        public static readonly string LogValidatorPassed = "Validator {ValidatorType} passed";
        public static readonly string LogValidationFailed = "Validation failed with {FailureCount} total failures";
        public static readonly string LogAllValidatorsPassed = "All {ValidatorCount} validators passed successfully";
        public const string MetadataKeySeparator = ".";

        // Error codes and messages
        public static readonly string ValidatorName = "CompositeValidator";
        public static readonly string ErrorInputNull = "Input message is null";
        public static readonly string ErrorCodeNullInput = "NULL_INPUT";
    }

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
            Logger.LogWarning(
                LogEvents.ValidationFailedEvent,
                ClassStrings.LogInputNull);
            return ValidationResult.Failure(ClassStrings.ValidatorName, ClassStrings.ErrorInputNull, ClassStrings.ErrorCodeNullInput);
        }

        if (Validators.Count == 0)
        {
            Logger.LogDebug(
                LogEvents.ValidationCompletedEvent,
                ClassStrings.LogNoValidators);
            return ValidationResult.Success(ClassStrings.ValidatorName);
        }

        Logger.LogDebug(
            LogEvents.ValidationStartedEvent,
            ClassStrings.LogValidationStarted,
            Validators.Count,
            StopOnFirstFailureField,
            RunInParallelField);

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
                Logger.LogTrace(
                    LogEvents.ValidatorExecutingEvent,
                    ClassStrings.LogSkippingValidator,
                    validator.GetType().Name);
                continue;
            }

            Logger.LogTrace(
                LogEvents.ValidatorExecutingEvent,
                ClassStrings.LogExecutingValidator,
                validator.GetType().Name);

            var result = validator.Validate(input, stage);
            results.Add(result);

            if (result.IsNotApplicable)
            {
                Logger.LogTrace(
                    LogEvents.ValidatorExecutingEvent,
                    ClassStrings.LogSkippingValidator,
                    validator.GetType().Name);
                continue;
            }

            if (result.IsFailure)
            {
                Logger.LogDebug(
                    LogEvents.ValidatorFailureEvent,
                    ClassStrings.LogValidatorFailed,
                    validator.GetType().Name,
                    result.Failures.Count);
                allFailures.AddRange(result.Failures);

                if (StopOnFirstFailureField)
                {
                    Logger.LogDebug(
                        LogEvents.ValidationCompletedEvent,
                        ClassStrings.LogStoppingOnFirstFailure);
                    break;
                }
            }
            else
            {
                Logger.LogTrace(
                    LogEvents.ValidatorPassedEvent,
                    ClassStrings.LogValidatorPassed,
                    validator.GetType().Name);
            }
        }

        if (allFailures.Count > 0)
        {
            Logger.LogInformation(
                LogEvents.ValidationFailedEvent,
                ClassStrings.LogValidationFailed,
                allFailures.Count);
            return ValidationResult.Failure(ClassStrings.ValidatorName, allFailures.ToArray());
        }

        Logger.LogDebug(
            LogEvents.ValidationCompletedEvent,
            ClassStrings.LogAllValidatorsPassed,
            Validators.Count);

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