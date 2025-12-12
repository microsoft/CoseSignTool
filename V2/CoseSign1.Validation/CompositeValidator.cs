// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSign1.Validation.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace CoseSign1.Validation;

/// <summary>
/// Combines multiple validators into a single composite validator.
/// Can run validators sequentially or in parallel and aggregate results.
/// </summary>
public sealed class CompositeValidator : IValidator<CoseSign1Message>
{
    private readonly IReadOnlyList<IValidator<CoseSign1Message>> _validators;
    private readonly bool _stopOnFirstFailure;
    private readonly bool _runInParallel;
    private readonly ILogger<CompositeValidator> _logger;

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
        _validators = validators?.ToList() ?? throw new ArgumentNullException(nameof(validators));
        _stopOnFirstFailure = stopOnFirstFailure;
        _runInParallel = runInParallel;
        _logger = logger ?? NullLogger<CompositeValidator>.Instance;
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
            _logger.LogWarning(
                new EventId(LogEvents.ValidationFailed, nameof(LogEvents.ValidationFailed)),
                "Validation failed: input message is null");
            return ValidationResult.Failure("CompositeValidator", "Input message is null", "NULL_INPUT");
        }

        if (_validators.Count == 0)
        {
            _logger.LogDebug(
                new EventId(LogEvents.ValidationCompleted, nameof(LogEvents.ValidationCompleted)),
                "Validation completed with no validators configured");
            return ValidationResult.Success("CompositeValidator");
        }

        _logger.LogDebug(
            new EventId(LogEvents.ValidationStarted, nameof(LogEvents.ValidationStarted)),
            "Starting validation with {ValidatorCount} validators. StopOnFirstFailure: {StopOnFirstFailure}, RunInParallel: {RunInParallel}",
            _validators.Count,
            _stopOnFirstFailure,
            _runInParallel);

        var results = new List<ValidationResult>();
        var allFailures = new List<ValidationFailure>();

        foreach (var validator in _validators)
        {
            _logger.LogTrace(
                new EventId(LogEvents.ValidatorExecuting, nameof(LogEvents.ValidatorExecuting)),
                "Executing validator: {ValidatorType}",
                validator.GetType().Name);

            var result = validator.Validate(input);
            results.Add(result);

            if (!result.IsValid)
            {
                _logger.LogDebug(
                    new EventId(LogEvents.ValidatorFailure, nameof(LogEvents.ValidatorFailure)),
                    "Validator {ValidatorType} failed with {FailureCount} failures",
                    validator.GetType().Name,
                    result.Failures.Count);
                allFailures.AddRange(result.Failures);

                if (_stopOnFirstFailure)
                {
                    _logger.LogDebug(
                        new EventId(LogEvents.ValidationCompleted, nameof(LogEvents.ValidationCompleted)),
                        "Stopping validation on first failure");
                    break;
                }
            }
            else
            {
                _logger.LogTrace(
                    new EventId(LogEvents.ValidatorPassed, nameof(LogEvents.ValidatorPassed)),
                    "Validator {ValidatorType} passed",
                    validator.GetType().Name);
            }
        }

        if (allFailures.Count > 0)
        {
            _logger.LogInformation(
                new EventId(LogEvents.ValidationFailed, nameof(LogEvents.ValidationFailed)),
                "Validation failed with {FailureCount} total failures",
                allFailures.Count);
            return ValidationResult.Failure("CompositeValidator", allFailures.ToArray());
        }

        _logger.LogDebug(
            new EventId(LogEvents.ValidationCompleted, nameof(LogEvents.ValidationCompleted)),
            "All {ValidatorCount} validators passed successfully",
            _validators.Count);

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

        if (_validators.Count == 0)
        {
            return ValidationResult.Success("CompositeValidator");
        }

        var allFailures = new List<ValidationFailure>();
        var results = new List<ValidationResult>();

        if (_runInParallel)
        {
            // Run validators in parallel
            var tasks = _validators.Select(v => v.ValidateAsync(input, cancellationToken));
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
            foreach (var validator in _validators)
            {
                var result = await validator.ValidateAsync(input, cancellationToken).ConfigureAwait(false);
                results.Add(result);

                if (!result.IsValid)
                {
                    allFailures.AddRange(result.Failures);

                    if (_stopOnFirstFailure)
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