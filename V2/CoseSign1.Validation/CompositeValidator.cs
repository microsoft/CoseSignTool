// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Diagnostics.CodeAnalysis;
using CoseSign1.Validation.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace CoseSign1.Validation;

/// <summary>
/// Combines multiple validators into a single composite validator.
/// Can run validators sequentially or in parallel and aggregate results.
/// </summary>
public sealed class CompositeValidator : IValidator<CoseSign1Message>
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        // Log message templates
        public static readonly string LogInputNull = "Validation failed: input message is null";
        public static readonly string LogNoValidators = "Validation completed with no validators configured";
        public static readonly string LogValidationStarted = "Starting validation with {ValidatorCount} validators. StopOnFirstFailure: {StopOnFirstFailure}, RunInParallel: {RunInParallel}";
        public static readonly string LogExecutingValidator = "Executing validator: {ValidatorType}";
        public static readonly string LogValidatorFailed = "Validator {ValidatorType} failed with {FailureCount} failures";
        public static readonly string LogStoppingOnFirstFailure = "Stopping validation on first failure";
        public static readonly string LogValidatorPassed = "Validator {ValidatorType} passed";
        public static readonly string LogValidationFailed = "Validation failed with {FailureCount} total failures";
        public static readonly string LogAllValidatorsPassed = "All {ValidatorCount} validators passed successfully";

        // Error codes and messages
        public static readonly string ValidatorName = "CompositeValidator";
        public static readonly string ErrorInputNull = "Input message is null";
        public static readonly string ErrorCodeNullInput = "NULL_INPUT";
    }

    private readonly IReadOnlyList<IValidator<CoseSign1Message>> Validators;
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
    public CompositeValidator(
        IEnumerable<IValidator<CoseSign1Message>> validators,
        bool stopOnFirstFailure = false,
        bool runInParallel = false,
        ILogger<CompositeValidator>? logger = null)
    {
        Validators = validators?.ToList() ?? throw new ArgumentNullException(nameof(validators));
        StopOnFirstFailureField = stopOnFirstFailure;
        RunInParallelField = runInParallel;
        Logger = logger ?? NullLogger<CompositeValidator>.Instance;
    }

    /// <summary>
    /// Validates the input using all composed validators.
    /// </summary>
    /// <param name="input">The COSE Sign1 message to validate.</param>
    /// <returns>An aggregated validation result.</returns>
    public ValidationResult Validate(CoseSign1Message input)
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
            Logger.LogTrace(
                LogEvents.ValidatorExecutingEvent,
                ClassStrings.LogExecutingValidator,
                validator.GetType().Name);

            var result = validator.Validate(input);
            results.Add(result);

            if (!result.IsValid)
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
            foreach (var kvp in result.Metadata)
            {
                mergedMetadata[$"{result.ValidatorName}.{kvp.Key}"] = kvp.Value;
            }
        }

        return ValidationResult.Success("CompositeValidator", mergedMetadata);
    }

    /// <summary>
    /// Asynchronously validates the input using all composed validators.
    /// </summary>
    /// <param name="input">The COSE Sign1 message to validate.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A task representing the asynchronous validation operation.</returns>
    public async Task<ValidationResult> ValidateAsync(CoseSign1Message input, CancellationToken cancellationToken = default)
    {
        if (input == null)
        {
            return ValidationResult.Failure("CompositeValidator", "Input message is null", "NULL_INPUT");
        }

        if (Validators.Count == 0)
        {
            return ValidationResult.Success("CompositeValidator");
        }

        var allFailures = new List<ValidationFailure>();
        var results = new List<ValidationResult>();

        if (RunInParallelField)
        {
            // Run validators in parallel
            var tasks = Validators.Select(v => v.ValidateAsync(input, cancellationToken));
            var parallelResults = await Task.WhenAll(tasks).ConfigureAwait(false);
            results.AddRange(parallelResults);

            foreach (var result in parallelResults)
            {
                if (!result.IsValid)
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
                var result = await validator.ValidateAsync(input, cancellationToken).ConfigureAwait(false);
                results.Add(result);

                if (!result.IsValid)
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
            return ValidationResult.Failure("CompositeValidator", allFailures.ToArray());
        }

        // Merge metadata from all successful validators
        var mergedMetadata = new Dictionary<string, object>();
        foreach (var result in results)
        {
            foreach (var kvp in result.Metadata)
            {
                mergedMetadata[$"{result.ValidatorName}.{kvp.Key}"] = kvp.Value;
            }
        }

        return ValidationResult.Success("CompositeValidator", mergedMetadata);
    }
}