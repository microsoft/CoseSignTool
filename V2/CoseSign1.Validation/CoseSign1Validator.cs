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

    private readonly IReadOnlyList<ISigningKeyResolver> SigningKeyResolvers;
    private readonly IReadOnlyList<ISigningKeyAssertionProvider> AssertionProviders;
    private readonly IReadOnlyList<IPostSignatureValidator> PostSignatureValidators;
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

        // Filter components by type
        SigningKeyResolvers = Components.OfType<ISigningKeyResolver>().ToList();
        AssertionProviders = Components.OfType<ISigningKeyAssertionProvider>().ToList();
        PostSignatureValidators = Components.OfType<IPostSignatureValidator>().ToList();
    }

    /// <inheritdoc />
    public TrustPolicy TrustPolicy { get; }

    /// <inheritdoc />
    public IReadOnlyList<IValidationComponent> Components { get; }

    /// <inheritdoc />
    public CoseSign1ValidationResult Validate(CoseSign1Message message)
    {
        var totalStopwatch = Stopwatch.StartNew();

        LogValidationStarted(
            Components.Count,
            SigningKeyResolvers.Count,
            AssertionProviders.Count,
            PostSignatureValidators.Count);

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

        LogValidationStarted(
            Components.Count,
            SigningKeyResolvers.Count,
            AssertionProviders.Count,
            PostSignatureValidators.Count);

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
        if (message == null)
        {
            throw new ArgumentNullException(nameof(message));
        }

        // Stage 1: Key Material Resolution
        var (resolutionResult, signingKey) = RunResolutionStage(message);

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
        var (trustResult, assertionSet, trustDecision) = RunTrustStage(message, signingKey);

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
        var signatureResult = RunSignatureStage(message, signingKey!);

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
        var postSignatureResult = RunPostSignatureStage(message, signingKey, assertionSet, trustDecision, signatureResult.Metadata);

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

    private async Task<CoseSign1ValidationResult> ValidateInternalAsync(
        CoseSign1Message message,
        CancellationToken cancellationToken)
    {
        if (message == null)
        {
            throw new ArgumentNullException(nameof(message));
        }

        // Stage 1: Key Material Resolution
        var (resolutionResult, signingKey) = await RunResolutionStageAsync(message, cancellationToken).ConfigureAwait(false);

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
        var (trustResult, assertionSet, trustDecision) = await RunTrustStageAsync(message, signingKey, cancellationToken).ConfigureAwait(false);

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
        var signatureResult = await RunSignatureStageAsync(message, signingKey!, cancellationToken).ConfigureAwait(false);

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
        var postSignatureResult = await RunPostSignatureStageAsync(message, signingKey, assertionSet, trustDecision, signatureResult.Metadata, cancellationToken).ConfigureAwait(false);

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

    private (ValidationResult Result, ISigningKey? SigningKey) RunResolutionStage(CoseSign1Message message)
    {
        var stopwatch = Stopwatch.StartNew();

        if (SigningKeyResolvers.Count == 0)
        {
            stopwatch.Stop();
            LogStageCompletedNoComponents(ClassStrings.StageNameKeyMaterialResolution, stopwatch.ElapsedMilliseconds);

            // No resolvers configured - this is an error because we need a signing key
            return (
                ValidationResult.Failure(
                    ClassStrings.StageNameKeyMaterialResolution,
                    ClassStrings.ErrorMessageNoSigningKeyResolved,
                    ClassStrings.ErrorCodeNoSigningKeyResolved),
                null);
        }

        LogStageStarted(ClassStrings.StageNameKeyMaterialResolution, SigningKeyResolvers.Count);

        ISigningKey? resolvedKey = null;
        var diagnostics = new List<string>();

        foreach (var resolver in SigningKeyResolvers)
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

    private async Task<(ValidationResult Result, ISigningKey? SigningKey)> RunResolutionStageAsync(
        CoseSign1Message message,
        CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();

        if (SigningKeyResolvers.Count == 0)
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

        LogStageStarted(ClassStrings.StageNameKeyMaterialResolution, SigningKeyResolvers.Count);

        ISigningKey? resolvedKey = null;
        var diagnostics = new List<string>();

        foreach (var resolver in SigningKeyResolvers)
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

    private (ValidationResult Result, SigningKeyAssertionSet Assertions, TrustDecision Decision) RunTrustStage(
        CoseSign1Message message,
        ISigningKey? signingKey)
    {
        var stopwatch = Stopwatch.StartNew();

        // Collect assertions from all providers
        var allAssertions = new List<ISigningKeyAssertion>();

        if (signingKey != null)
        {
            foreach (var provider in AssertionProviders)
            {
                if (!provider.CanProvideAssertions(signingKey))
                {
                    continue;
                }

                var assertions = provider.ExtractAssertions(signingKey, message);
                allAssertions.AddRange(assertions);

                foreach (var assertion in assertions)
                {
                    LogTrustAssertionRecorded(assertion.Domain, assertion.Description);
                }
            }
        }

        var assertionSet = new SigningKeyAssertionSet(allAssertions);
        LogTrustPolicyStarted(assertionSet.Count);

        // Evaluate trust policy
        var trustDecision = TrustPolicy.Evaluate(assertionSet);

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
                assertionSet,
                trustDecision);
        }

        LogTrustPolicySatisfied();
        LogStageCompleted(ClassStrings.StageNameKeyMaterialTrust, true, stopwatch.ElapsedMilliseconds);

        return (ValidationResult.Success(ClassStrings.StageNameKeyMaterialTrust), assertionSet, trustDecision);
    }

    private async Task<(ValidationResult Result, SigningKeyAssertionSet Assertions, TrustDecision Decision)> RunTrustStageAsync(
        CoseSign1Message message,
        ISigningKey? signingKey,
        CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();

        // Collect assertions from all providers
        var allAssertions = new List<ISigningKeyAssertion>();

        if (signingKey != null)
        {
            foreach (var provider in AssertionProviders)
            {
                cancellationToken.ThrowIfCancellationRequested();

                if (!provider.CanProvideAssertions(signingKey))
                {
                    continue;
                }

                var assertions = await provider.ExtractAssertionsAsync(signingKey, message, cancellationToken).ConfigureAwait(false);
                allAssertions.AddRange(assertions);

                foreach (var assertion in assertions)
                {
                    LogTrustAssertionRecorded(assertion.Domain, assertion.Description);
                }
            }
        }

        var assertionSet = new SigningKeyAssertionSet(allAssertions);
        LogTrustPolicyStarted(assertionSet.Count);

        // Evaluate trust policy
        var trustDecision = TrustPolicy.Evaluate(assertionSet);

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
                assertionSet,
                trustDecision);
        }

        LogTrustPolicySatisfied();
        LogStageCompleted(ClassStrings.StageNameKeyMaterialTrust, true, stopwatch.ElapsedMilliseconds);

        return (ValidationResult.Success(ClassStrings.StageNameKeyMaterialTrust), assertionSet, trustDecision);
    }

    /// <summary>
    /// Threshold in bytes above which we use async stream-based verification to avoid large memory allocations.
    /// Default is 85,000 bytes (just under the Large Object Heap threshold of 85KB).
    /// </summary>
    private const long LargeStreamThreshold = 85_000;

    private ValidationResult RunSignatureStage(CoseSign1Message message, ISigningKey signingKey)
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

                // For large streams or non-seekable streams where we can't determine size,
                // use async path to avoid large memory allocations
                bool isLargeStream = Options.DetachedPayload.CanSeek && Options.DetachedPayload.Length > LargeStreamThreshold;
                bool isUnknownSizeStream = !Options.DetachedPayload.CanSeek;

                if (isLargeStream || isUnknownSizeStream)
                {
                    // Reset stream position if seekable
                    if (Options.DetachedPayload.CanSeek)
                    {
                        Options.DetachedPayload.Position = 0;
                    }

                    // Use async API synchronously to leverage stream-based verification
                    isValid =  Options.AssociatedData != null
                                ? message.VerifyDetachedAsync(coseKey, Options.DetachedPayload, (ReadOnlyMemory<byte>)Options.AssociatedData, Options.CancellationToken).GetAwaiter().GetResult()
                                : message.VerifyDetachedAsync(coseKey, Options.DetachedPayload, cancellationToken:Options.CancellationToken).GetAwaiter().GetResult();
                }
                else
                {
                    // Small seekable stream - read to bytes for sync verification
                    Options.DetachedPayload.Position = 0;
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

    private Task<ValidationResult> RunSignatureStageAsync(
        CoseSign1Message message,
        ISigningKey signingKey,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        bool isEmbedded = message.Content != null;

        // For embedded signatures or when no detached payload, use sync path
        if (isEmbedded || Options.DetachedPayload == null)
        {
            return Task.FromResult(RunSignatureStage(message, signingKey));
        }

        // For detached signatures with stream payload, use async stream-based verification
        var coseKey = signingKey.GetCoseKey();
        return RunSignatureStageWithStreamAsync(message, coseKey, cancellationToken);
    }

    private async Task<ValidationResult> RunSignatureStageWithStreamAsync(
        CoseSign1Message message,
        CoseKey coseKey,
        CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();
        LogStageStarted(ClassStrings.StageNameSignature, 1);

        try
        {
            // Reset stream position if seekable
            if (Options.DetachedPayload!.CanSeek)
            {
                Options.DetachedPayload.Position = 0;
            }

            bool isValid = Options.AssociatedData.HasValue
                ? await message.VerifyDetachedAsync(coseKey, Options.DetachedPayload, (ReadOnlyMemory<byte>)Options.AssociatedData, Options.CancellationToken).ConfigureAwait(false)
                : await message.VerifyDetachedAsync(coseKey, Options.DetachedPayload, cancellationToken: Options.CancellationToken).ConfigureAwait(false);

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

    private ValidationResult RunPostSignatureStage(
        CoseSign1Message message,
        ISigningKey? signingKey,
        SigningKeyAssertionSet assertionSet,
        TrustDecision trustDecision,
        IReadOnlyDictionary<string, object> signatureMetadata)
    {
        var stopwatch = Stopwatch.StartNew();

        if (PostSignatureValidators.Count == 0)
        {
            stopwatch.Stop();
            LogStageCompletedNoComponents(ClassStrings.StageNamePostSignature, stopwatch.ElapsedMilliseconds);
            return ValidationResult.Success(ClassStrings.StageNamePostSignature);
        }

        LogStageStarted(ClassStrings.StageNamePostSignature, PostSignatureValidators.Count);

        var context = new PostSignatureValidationContext(
            message,
            assertionSet,
            trustDecision,
            signatureMetadata,
            Options,
            signingKey);

        var failures = new List<ValidationFailure>();

        foreach (var validator in PostSignatureValidators)
        {
            var result = validator.Validate(context);

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

    private async Task<ValidationResult> RunPostSignatureStageAsync(
        CoseSign1Message message,
        ISigningKey? signingKey,
        SigningKeyAssertionSet assertionSet,
        TrustDecision trustDecision,
        IReadOnlyDictionary<string, object> signatureMetadata,
        CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();

        if (PostSignatureValidators.Count == 0)
        {
            stopwatch.Stop();
            LogStageCompletedNoComponents(ClassStrings.StageNamePostSignature, stopwatch.ElapsedMilliseconds);
            return ValidationResult.Success(ClassStrings.StageNamePostSignature);
        }

        LogStageStarted(ClassStrings.StageNamePostSignature, PostSignatureValidators.Count);

        var context = new PostSignatureValidationContext(
            message,
            assertionSet,
            trustDecision,
            signatureMetadata,
            Options,
            signingKey);

        var failures = new List<ValidationFailure>();

        foreach (var validator in PostSignatureValidators)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var result = await validator.ValidateAsync(context, cancellationToken).ConfigureAwait(false);

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
