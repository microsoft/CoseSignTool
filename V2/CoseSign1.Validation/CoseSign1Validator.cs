// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation;

using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography.Cose;
using CoseSign1.Abstractions;
using CoseSign1.Validation.Interfaces;
using CoseSign1.Validation.Results;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Orchestrates staged validation of a COSE Sign1 message.
/// </summary>
/// <remarks>
/// <para>
/// This is the library-level orchestration layer used by CoseSign1 consumers (including CoseSignTool).
/// It enforces the secure-by-default stage ordering:
/// </para>
/// <list type="number">
/// <item><description>Key Resolution via <see cref="ISigningKeyResolver"/></description></item>
/// <item><description>Trust via <see cref="ISigningKeyAssertionProvider"/> + <see cref="TrustPolicy"/></description></item>
/// <item><description>Signature Verification using <see cref="ISigningKey.GetCoseKey"/></description></item>
/// <item><description>Post-Signature via <see cref="IPostSignatureValidator"/></description></item>
/// </list>
/// </remarks>
public sealed partial class CoseSign1Validator : ICoseSign1Validator
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string ValidatorNameOverall = "Validate";

        public const string StageNameKeyMaterialResolution = "Key Material Resolution";
        public const string StageNameKeyMaterialTrust = "Signing Key Trust";
        public const string StageNameSignature = "Signature";
        public const string StageNamePostSignature = "Post-Signature Validation";

        public const string NotApplicableReasonPriorStageFailed = "Prior stage failed";
        public const string NotApplicableReasonSigningKeyNotTrusted = "Signing key not trusted";
        public const string NotApplicableReasonSignatureValidationFailed = "Signature validation failed";
        public const string NotApplicableReasonNoSigningKeyResolved = "No signing key was resolved";

        public const string MetadataPrefixResolution = "Resolution";
        public const string MetadataPrefixTrust = "Trust";
        public const string MetadataPrefixSignature = "Signature";
        public const string MetadataPrefixPost = "Post";

        public const string MetadataKeySeparator = ".";

        public const string ErrorCodeTrustPolicyNotSatisfied = "TRUST_POLICY_NOT_SATISFIED";
        public const string ErrorMessageTrustPolicyNotSatisfied = "Trust policy was not satisfied";

        public const string ErrorCodeNoSigningKeyResolved = "NO_SIGNING_KEY_RESOLVED";
        public const string ErrorMessageNoSigningKeyResolved = "No signing key could be resolved from the message";

        public const string ErrorCodeNoApplicableSignatureValidator = "NO_APPLICABLE_SIGNATURE_VALIDATOR";
        public const string ErrorMessageNoApplicableSignatureValidator = "No applicable signature validator was found for this message";

        public const string ErrorCodeSignatureVerificationFailed = "SIGNATURE_VERIFICATION_FAILED";
        public const string ErrorMessageSignatureVerificationFailed = "Cryptographic signature verification failed";

        public const string ErrorCodeSignatureMissingPayload = "SIGNATURE_MISSING_PAYLOAD";
        public const string ErrorMessageSignatureMissingPayload = "Message has detached content but no payload was provided for verification";

        public const string MetadataKeySelectedValidator = "SelectedValidator";

        public const string ErrorNoComponents = "No validation components were provided";
    }

    // High-performance logging via source generation
    [LoggerMessage(Level = LogLevel.Debug, Message = "Starting staged validation. Components: {ComponentCount}, Resolvers: {ResolverCount}, AssertionProviders: {ProviderCount}, PostValidators: {PostCount}")]
    private partial void LogValidationStarted(int componentCount, int resolverCount, int providerCount, int postCount);

    [LoggerMessage(Level = LogLevel.Debug, Message = "Validation stage completed: {StageName}. Success: {Success}, ElapsedMs: {ElapsedMs}")]
    private partial void LogStageCompleted(string stageName, bool success, long elapsedMs);

    [LoggerMessage(Level = LogLevel.Debug, Message = "Starting validation stage: {StageName}. ComponentCount: {ComponentCount}")]
    private partial void LogStageStarted(string stageName, int componentCount);

    [LoggerMessage(Level = LogLevel.Information, Message = "Validation stage failed: {StageName}. FailureCount: {FailureCount}, ElapsedMs: {ElapsedMs}")]
    private partial void LogStageFailed(string stageName, int failureCount, long elapsedMs);

    [LoggerMessage(Level = LogLevel.Debug, Message = "Validation stage skipped: {StageName}. Reason: {Reason}")]
    private partial void LogStageSkipped(string stageName, string reason);

    [LoggerMessage(Level = LogLevel.Debug, Message = "Evaluating trust policy. AssertionCount: {AssertionCount}")]
    private partial void LogTrustPolicyStarted(int assertionCount);

    [LoggerMessage(Level = LogLevel.Debug, Message = "Trust policy satisfied")]
    private partial void LogTrustPolicySatisfied();

    [LoggerMessage(Level = LogLevel.Information, Message = "Trust policy not satisfied. ReasonCount: {ReasonCount}")]
    private partial void LogTrustPolicyNotSatisfied(int reasonCount);

    [LoggerMessage(Level = LogLevel.Trace, Message = "Trust assertion: {Domain} - {Description}")]
    private partial void LogTrustAssertionRecorded(string domain, string description);

    [LoggerMessage(Level = LogLevel.Debug, Message = "Staged validation completed. Success: {Success}, TotalElapsedMs: {ElapsedMs}")]
    private partial void LogValidationCompleted(bool success, long elapsedMs);

    [LoggerMessage(Level = LogLevel.Information, Message = "Staged validation failed at stage: {FailedStage}. TotalElapsedMs: {ElapsedMs}")]
    private partial void LogValidationFailed(string failedStage, long elapsedMs);

    [LoggerMessage(Level = LogLevel.Trace, Message = "Validation stage completed (no components): {StageName}. ElapsedMs: {ElapsedMs}")]
    private partial void LogStageCompletedNoComponents(string stageName, long elapsedMs);

    [LoggerMessage(Level = LogLevel.Debug, Message = "Signing key resolved: {KeyType}")]
    private partial void LogSigningKeyResolved(string keyType);

    [LoggerMessage(Level = LogLevel.Debug, Message = "Signature verification succeeded")]
    private partial void LogSignatureVerificationSucceeded();

    [LoggerMessage(Level = LogLevel.Information, Message = "Signature verification failed: {Reason}")]
    private partial void LogSignatureVerificationFailed(string reason);

    private readonly CoseSign1ValidationOptions Options;
    private readonly ILogger<CoseSign1Validator> Logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="CoseSign1Validator"/> class.
    /// </summary>
    /// <param name="components">Validation components. Components are filtered by type internally.</param>
    /// <param name="trustPolicy">The trust policy evaluated against trust assertions.</param>
    /// <param name="options">Validation options including detached payload, associated data, and signature-only mode.</param>
    /// <param name="logger">Optional logger for diagnostic output. If null, logging is disabled.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="components"/> or <paramref name="trustPolicy"/> is null.</exception>
    /// <exception cref="InvalidOperationException">Thrown when no components are provided.</exception>
    public CoseSign1Validator(
        IReadOnlyList<IValidationComponent> components,
        TrustPolicy trustPolicy,
        CoseSign1ValidationOptions? options = null,
        ILogger<CoseSign1Validator>? logger = null)
    {
        Components = components ?? throw new ArgumentNullException(nameof(components));
        TrustPolicy = trustPolicy ?? throw new ArgumentNullException(nameof(trustPolicy));
        Options = options ?? new CoseSign1ValidationOptions();
        Logger = logger ?? NullLogger<CoseSign1Validator>.Instance;

        if (Components.Count == 0)
        {
            throw new InvalidOperationException(ClassStrings.ErrorNoComponents);
        }
    }

    /// <inheritdoc />
    public TrustPolicy TrustPolicy { get; }

    /// <inheritdoc />
    public IReadOnlyList<IValidationComponent> Components { get; }

    /// <summary>
    /// Filters components by applicability to the message and categorizes them by interface type in a single pass.
    /// </summary>
    private (List<ISigningKeyResolver> Resolvers, List<ISigningKeyAssertionProvider> AssertionProviders, List<IPostSignatureValidator> PostValidators) 
        FilterApplicableComponents(CoseSign1Message message)
    {
        var resolvers = new List<ISigningKeyResolver>();
        var assertionProviders = new List<ISigningKeyAssertionProvider>();
        var postValidators = new List<IPostSignatureValidator>();

        foreach (var component in Components)
        {
            if (!component.IsApplicableTo(message))
            {
                continue;
            }

            if (component is ISigningKeyResolver resolver)
            {
                resolvers.Add(resolver);
            }

            if (component is ISigningKeyAssertionProvider provider)
            {
                assertionProviders.Add(provider);
            }

            if (component is IPostSignatureValidator validator)
            {
                postValidators.Add(validator);
            }
        }

        return (resolvers, assertionProviders, postValidators);
    }

    /// <inheritdoc />
    public CoseSign1ValidationResult Validate(CoseSign1Message message)
    {
        var totalStopwatch = Stopwatch.StartNew();

        var result = ValidateInternal(message);

        totalStopwatch.Stop();

        if (result.Overall.IsValid)
        {
            LogValidationCompleted(true, totalStopwatch.ElapsedMilliseconds);
        }
        else
        {
            LogValidationFailed(result.Overall.ValidatorName, totalStopwatch.ElapsedMilliseconds);
        }

        return result;
    }

    /// <inheritdoc />
    public async Task<CoseSign1ValidationResult> ValidateAsync(
        CoseSign1Message message,
        CancellationToken cancellationToken = default)
    {
        var totalStopwatch = Stopwatch.StartNew();

        var result = await ValidateInternalAsync(message, cancellationToken).ConfigureAwait(false);

        totalStopwatch.Stop();

        if (result.Overall.IsValid)
        {
            LogValidationCompleted(true, totalStopwatch.ElapsedMilliseconds);
        }
        else
        {
            LogValidationFailed(result.Overall.ValidatorName, totalStopwatch.ElapsedMilliseconds);
        }

        return result;
    }

    /// <summary>
    /// Validates a COSE Sign1 message using staged validation.
    /// </summary>
    /// <param name="message">The message to validate.</param>
    /// <param name="components">Validation components.</param>
    /// <param name="trustPolicy">The trust policy evaluated against trust assertions.</param>
    /// <returns>A staged validation result.</returns>
    /// <exception cref="ArgumentNullException">Thrown when any parameter is null.</exception>
    public static CoseSign1ValidationResult Validate(
        CoseSign1Message message,
        IReadOnlyList<IValidationComponent> components,
        TrustPolicy trustPolicy)
    {
        if (message == null)
        {
            throw new ArgumentNullException(nameof(message));
        }

        if (components == null)
        {
            throw new ArgumentNullException(nameof(components));
        }

        if (trustPolicy == null)
        {
            throw new ArgumentNullException(nameof(trustPolicy));
        }

        var validator = new CoseSign1Validator(components, trustPolicy);
        return validator.Validate(message);
    }

    private CoseSign1ValidationResult ValidateInternal(CoseSign1Message message)
    {
        // Sync path: use ValueTask wrapper that completes synchronously
        return ValidateCoreAsync(message, async: false, CancellationToken.None).GetAwaiter().GetResult();
    }

    private Task<CoseSign1ValidationResult> ValidateInternalAsync(
        CoseSign1Message message,
        CancellationToken cancellationToken)
    {
        // Async path: returns awaitable task
        return ValidateCoreAsync(message, async: true, cancellationToken).AsTask();
    }

    private async ValueTask<CoseSign1ValidationResult> ValidateCoreAsync(
        CoseSign1Message message,
        bool async,
        CancellationToken cancellationToken)
    {
        if (message == null)
        {
            throw new ArgumentNullException(nameof(message));
        }

        // Single-pass filter: applicable components categorized by interface type
        var (resolvers, assertionProviders, postValidators) = FilterApplicableComponents(message);

        LogValidationStarted(Components.Count, resolvers.Count, assertionProviders.Count, postValidators.Count);

        // Stage 1: Key Material Resolution
        var (resolutionResult, signingKey) = await RunResolutionStageCoreAsync(message, resolvers, async, cancellationToken).ConfigureAwait(false);

        if (!resolutionResult.IsValid)
        {
            LogStageSkipped(ClassStrings.StageNameKeyMaterialTrust, ClassStrings.NotApplicableReasonPriorStageFailed);

            return new CoseSign1ValidationResult(
                resolutionResult,
                trust: ValidationResult.NotApplicable(ClassStrings.StageNameKeyMaterialTrust, ClassStrings.NotApplicableReasonPriorStageFailed),
                signature: ValidationResult.NotApplicable(ClassStrings.StageNameSignature, ClassStrings.NotApplicableReasonPriorStageFailed),
                postSignaturePolicy: ValidationResult.NotApplicable(ClassStrings.StageNamePostSignature, ClassStrings.NotApplicableReasonPriorStageFailed),
                overall: resolutionResult);
        }

        // Stage 2: Key Material Trust
        var (trustResult, assertionSet, trustDecision) = await RunTrustStageCoreAsync(message, signingKey, assertionProviders, async, cancellationToken).ConfigureAwait(false);

        if (!trustResult.IsValid)
        {
            LogStageSkipped(ClassStrings.StageNameSignature, ClassStrings.NotApplicableReasonSigningKeyNotTrusted);

            return new CoseSign1ValidationResult(
                resolutionResult,
                trustResult,
                signature: ValidationResult.NotApplicable(ClassStrings.StageNameSignature, ClassStrings.NotApplicableReasonSigningKeyNotTrusted),
                postSignaturePolicy: ValidationResult.NotApplicable(ClassStrings.StageNamePostSignature, ClassStrings.NotApplicableReasonSigningKeyNotTrusted),
                overall: trustResult);
        }

        // Stage 3: Signature Verification
        var signatureResult = await RunSignatureStageCoreAsync(message, signingKey!, async, cancellationToken).ConfigureAwait(false);

        if (!signatureResult.IsValid)
        {
            LogStageSkipped(ClassStrings.StageNamePostSignature, ClassStrings.NotApplicableReasonSignatureValidationFailed);

            return new CoseSign1ValidationResult(
                resolutionResult,
                trustResult,
                signatureResult,
                postSignaturePolicy: ValidationResult.NotApplicable(ClassStrings.StageNamePostSignature, ClassStrings.NotApplicableReasonSignatureValidationFailed),
                overall: signatureResult);
        }

        // Stage 4: Post-Signature Policy
        var postSignatureResult = await RunPostSignatureStageCoreAsync(message, signingKey, assertionSet, trustDecision, signatureResult.Metadata, postValidators, async, cancellationToken).ConfigureAwait(false);

        if (!postSignatureResult.IsValid)
        {
            return new CoseSign1ValidationResult(
                resolutionResult,
                trustResult,
                signatureResult,
                postSignatureResult,
                overall: postSignatureResult);
        }

        // Combine metadata from all successful stage results
        var combinedMetadata = new Dictionary<string, object>();
        MergeStageMetadata(combinedMetadata, ClassStrings.MetadataPrefixResolution, resolutionResult);
        MergeStageMetadata(combinedMetadata, ClassStrings.MetadataPrefixTrust, trustResult);
        MergeStageMetadata(combinedMetadata, ClassStrings.MetadataPrefixSignature, signatureResult);
        MergeStageMetadata(combinedMetadata, ClassStrings.MetadataPrefixPost, postSignatureResult);

        var overall = ValidationResult.Success(ClassStrings.ValidatorNameOverall, combinedMetadata);

        return new CoseSign1ValidationResult(
            resolutionResult,
            trustResult,
            signatureResult,
            postSignatureResult,
            overall);
    }

    private async ValueTask<(ValidationResult Result, ISigningKey? SigningKey)> RunResolutionStageCoreAsync(
        CoseSign1Message message,
        List<ISigningKeyResolver> resolvers,
        bool async,
        CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();

        if (resolvers.Count == 0)
        {
            stopwatch.Stop();
            LogStageCompletedNoComponents(ClassStrings.StageNameKeyMaterialResolution, stopwatch.ElapsedMilliseconds);

            return (
                ValidationResult.Failure(
                    ClassStrings.StageNameKeyMaterialResolution,
                    ClassStrings.ErrorMessageNoSigningKeyResolved,
                    ClassStrings.ErrorCodeNoSigningKeyResolved),
                null);
        }

        LogStageStarted(ClassStrings.StageNameKeyMaterialResolution, resolvers.Count);

        ISigningKey? resolvedKey = null;
        var diagnostics = new List<string>();

        foreach (var resolver in resolvers)
        {
            if (async)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var result = await resolver.ResolveAsync(message, cancellationToken).ConfigureAwait(false);
                diagnostics.AddRange(result.Diagnostics);

                if (result.IsSuccess && result.SigningKey != null)
                {
                    resolvedKey = result.SigningKey;
                    LogSigningKeyResolved(resolvedKey.GetType().Name);
                    break;
                }
            }
            else
            {
                var result = resolver.Resolve(message);
                diagnostics.AddRange(result.Diagnostics);

                if (result.IsSuccess && result.SigningKey != null)
                {
                    resolvedKey = result.SigningKey;
                    LogSigningKeyResolved(resolvedKey.GetType().Name);
                    break;
                }
            }
        }

        stopwatch.Stop();

        if (resolvedKey == null)
        {
            LogStageFailed(ClassStrings.StageNameKeyMaterialResolution, 1, stopwatch.ElapsedMilliseconds);
            return (
                ValidationResult.Failure(
                    ClassStrings.StageNameKeyMaterialResolution,
                    ClassStrings.ErrorMessageNoSigningKeyResolved,
                    ClassStrings.ErrorCodeNoSigningKeyResolved),
                null);
        }

        LogStageCompleted(ClassStrings.StageNameKeyMaterialResolution, true, stopwatch.ElapsedMilliseconds);
        return (ValidationResult.Success(ClassStrings.StageNameKeyMaterialResolution), resolvedKey);
    }

    private async ValueTask<(ValidationResult Result, IReadOnlyList<ISigningKeyAssertion> Assertions, TrustDecision Decision)> RunTrustStageCoreAsync(
        CoseSign1Message message,
        ISigningKey? signingKey,
        List<ISigningKeyAssertionProvider> assertionProviders,
        bool async,
        CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();

        // Collect assertions from all providers
        var allAssertions = new List<ISigningKeyAssertion>();

        if (signingKey != null)
        {
            foreach (var provider in assertionProviders)
            {
                IEnumerable<ISigningKeyAssertion> assertions;

                if (async)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    assertions = await provider.ExtractAssertionsAsync(signingKey, message, Options, cancellationToken).ConfigureAwait(false);
                }
                else
                {
                    assertions = provider.ExtractAssertions(signingKey, message, Options);
                }

                allAssertions.AddRange(assertions);

                foreach (var assertion in assertions)
                {
                    LogTrustAssertionRecorded(assertion.Domain, assertion.Description);
                }
            }
        }

        LogTrustPolicyStarted(allAssertions.Count);

        // Evaluate trust policy
        var trustDecision = TrustPolicy.Evaluate(allAssertions);

        stopwatch.Stop();

        if (!trustDecision.IsTrusted)
        {
            LogTrustPolicyNotSatisfied(trustDecision.Reasons.Count);

            var failures = trustDecision.Reasons.Count == 0
                ? new[]
                {
                    new ValidationFailure
                    {
                        ErrorCode = ClassStrings.ErrorCodeTrustPolicyNotSatisfied,
                        Message = ClassStrings.ErrorMessageTrustPolicyNotSatisfied
                    }
                }
                : trustDecision.Reasons.Select(r => new ValidationFailure
                {
                    ErrorCode = ClassStrings.ErrorCodeTrustPolicyNotSatisfied,
                    Message = r
                }).ToArray();

            return (
                ValidationResult.Failure(ClassStrings.StageNameKeyMaterialTrust, failures),
                allAssertions,
                trustDecision);
        }

        LogTrustPolicySatisfied();
        LogStageCompleted(ClassStrings.StageNameKeyMaterialTrust, true, stopwatch.ElapsedMilliseconds);

        return (ValidationResult.Success(ClassStrings.StageNameKeyMaterialTrust), allAssertions, trustDecision);
    }

    /// <summary>
    /// Threshold in bytes above which we use async stream-based verification to avoid large memory allocations.
    /// Default is 85,000 bytes (just under the Large Object Heap threshold of 85KB).
    /// </summary>
    private const long LargeStreamThreshold = 85_000;

    private async ValueTask<ValidationResult> RunSignatureStageCoreAsync(
        CoseSign1Message message,
        ISigningKey signingKey,
        bool async,
        CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();
        LogStageStarted(ClassStrings.StageNameSignature, 1);

        try
        {
            var coseKey = signingKey.GetCoseKey();
            bool isEmbedded = message.Content != null;
            bool isValid;

            if (isEmbedded)
            {
                isValid = message.VerifyEmbedded(coseKey);
            }
            else
            {
                // Detached signature - need payload stream
                if (Options.DetachedPayload == null)
                {
                    stopwatch.Stop();
                    LogSignatureVerificationFailed(ClassStrings.ErrorCodeSignatureMissingPayload);
                    return ValidationResult.Failure(
                        ClassStrings.StageNameSignature,
                        ClassStrings.ErrorMessageSignatureMissingPayload,
                        ClassStrings.ErrorCodeSignatureMissingPayload);
                }

                // Reset stream position if seekable
                if (Options.DetachedPayload.CanSeek)
                {
                    Options.DetachedPayload.Position = 0;
                }

                bool isLargeStream = Options.DetachedPayload.CanSeek && Options.DetachedPayload.Length > LargeStreamThreshold;
                bool isUnknownSizeStream = !Options.DetachedPayload.CanSeek;

                if (async || isLargeStream || isUnknownSizeStream)
                {
                    // Use async API for large streams or when running async
                    isValid = Options.AssociatedData != null
                        ? await message.VerifyDetachedAsync(coseKey, Options.DetachedPayload, (ReadOnlyMemory<byte>)Options.AssociatedData, cancellationToken).ConfigureAwait(false)
                        : await message.VerifyDetachedAsync(coseKey, Options.DetachedPayload, cancellationToken: cancellationToken).ConfigureAwait(false);
                }
                else
                {
                    // Small seekable stream in sync mode - read to bytes for sync verification
                    using var memoryStream = new MemoryStream();
                    Options.DetachedPayload.CopyTo(memoryStream);
                    var payloadBytes = memoryStream.ToArray();

                    if (payloadBytes.Length == 0)
                    {
                        stopwatch.Stop();
                        LogSignatureVerificationFailed(ClassStrings.ErrorCodeSignatureMissingPayload);
                        return ValidationResult.Failure(
                            ClassStrings.StageNameSignature,
                            ClassStrings.ErrorMessageSignatureMissingPayload,
                            ClassStrings.ErrorCodeSignatureMissingPayload);
                    }

                    isValid = message.VerifyDetached(coseKey, payloadBytes, Options.AssociatedData?.ToArray());
                }
            }

            if (!isValid)
            {
                stopwatch.Stop();
                LogSignatureVerificationFailed(ClassStrings.ErrorCodeSignatureVerificationFailed);
                return ValidationResult.Failure(
                    ClassStrings.StageNameSignature,
                    ClassStrings.ErrorMessageSignatureVerificationFailed,
                    ClassStrings.ErrorCodeSignatureVerificationFailed);
            }

            LogSignatureVerificationSucceeded();

            stopwatch.Stop();
            LogStageCompleted(ClassStrings.StageNameSignature, true, stopwatch.ElapsedMilliseconds);
            return ValidationResult.Success(ClassStrings.StageNameSignature);
        }
        catch (Exception ex)
        {
            stopwatch.Stop();
            LogSignatureVerificationFailed(ex.Message);
            return ValidationResult.Failure(
                ClassStrings.StageNameSignature,
                ex.Message,
                ClassStrings.ErrorCodeSignatureVerificationFailed);
        }
    }

    private async ValueTask<ValidationResult> RunPostSignatureStageCoreAsync(
        CoseSign1Message message,
        ISigningKey? signingKey,
        IReadOnlyList<ISigningKeyAssertion> assertions,
        TrustDecision trustDecision,
        IReadOnlyDictionary<string, object> signatureMetadata,
        List<IPostSignatureValidator> postValidators,
        bool async,
        CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();

        if (postValidators.Count == 0)
        {
            stopwatch.Stop();
            LogStageCompletedNoComponents(ClassStrings.StageNamePostSignature, stopwatch.ElapsedMilliseconds);
            return ValidationResult.Success(ClassStrings.StageNamePostSignature);
        }

        LogStageStarted(ClassStrings.StageNamePostSignature, postValidators.Count);

        var context = new PostSignatureValidationContext(
            message,
            assertions,
            trustDecision,
            signatureMetadata,
            Options,
            signingKey);

        var failures = new List<ValidationFailure>();

        foreach (var validator in postValidators)
        {
            ValidationResult result;

            if (async)
            {
                cancellationToken.ThrowIfCancellationRequested();
                result = await validator.ValidateAsync(context, cancellationToken).ConfigureAwait(false);
            }
            else
            {
                result = validator.Validate(context);
            }

            if (result.IsFailure)
            {
                failures.AddRange(result.Failures);
            }
        }

        stopwatch.Stop();

        if (failures.Count > 0)
        {
            LogStageFailed(ClassStrings.StageNamePostSignature, failures.Count, stopwatch.ElapsedMilliseconds);
            return ValidationResult.Failure(ClassStrings.StageNamePostSignature, failures.ToArray());
        }

        LogStageCompleted(ClassStrings.StageNamePostSignature, true, stopwatch.ElapsedMilliseconds);
        return ValidationResult.Success(ClassStrings.StageNamePostSignature);
    }

    private static void MergeStageMetadata(Dictionary<string, object> combined, string prefix, ValidationResult stage)
    {
        foreach (var kvp in stage.Metadata)
        {
            combined[string.Concat(prefix, ClassStrings.MetadataKeySeparator, kvp.Key)] = kvp.Value;
        }
    }
}
