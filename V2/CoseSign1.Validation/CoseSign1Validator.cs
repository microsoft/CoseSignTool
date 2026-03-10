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
/// <item><description>Trust via <see cref="Trust.Plan.CompiledTrustPlan"/></description></item>
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
        public const string NotApplicableReasonSatisfiedByToBeSignedAttestation = "Satisfied by counter-signature ToBeSigned attestation";

        public const string MetadataPrefixResolution = "Resolution";
        public const string MetadataPrefixTrust = "Trust";
        public const string MetadataPrefixSignature = "Signature";
        public const string MetadataPrefixPost = "Post";

        public const string MetadataKeySeparator = ".";

        public const string ErrorCodeTrustPlanNotSatisfied = "TRUST_PLAN_NOT_SATISFIED";
        public const string ErrorMessageTrustPlanNotSatisfied = "Trust plan was not satisfied";

        public const string ErrorCodeNoSigningKeyResolved = "NO_SIGNING_KEY_RESOLVED";
        public const string ErrorMessageNoSigningKeyResolved = "No signing key could be resolved from the message";

        public const string ErrorCodeNoApplicableSignatureValidator = "NO_APPLICABLE_SIGNATURE_VALIDATOR";
        public const string ErrorMessageNoApplicableSignatureValidator = "No applicable signature validator was found for this message";

        public const string ErrorCodeSignatureVerificationFailed = "SIGNATURE_VERIFICATION_FAILED";
        public const string ErrorMessageSignatureVerificationFailed = "Cryptographic signature verification failed";

        public const string ErrorCodeSignatureMissingPayload = "SIGNATURE_MISSING_PAYLOAD";
        public const string ErrorMessageSignatureMissingPayload = "Message has detached content but no payload was provided for verification";

        public const string MetadataKeySelectedValidator = "SelectedValidator";

        public const string MetadataKeyToBeSignedAttestationProvider = "ToBeSignedAttestation.Provider";
        public const string MetadataKeyToBeSignedAttestationDetails = "ToBeSignedAttestation.Details";

        public const string ErrorNoComponents = "No validation components were provided";

    }

    // High-performance logging via source generation
    [LoggerMessage(Level = LogLevel.Debug, Message = "Starting staged validation. Resolvers: {ResolverCount}, PostValidators: {PostCount}")]
    private partial void LogValidationStarted(int resolverCount, int postCount);

    [LoggerMessage(Level = LogLevel.Debug, Message = "Validation stage completed: {StageName}. Success: {Success}, ElapsedMs: {ElapsedMs}")]
    private partial void LogStageCompleted(string stageName, bool success, long elapsedMs);

    [LoggerMessage(Level = LogLevel.Debug, Message = "Starting validation stage: {StageName}. ComponentCount: {ComponentCount}")]
    private partial void LogStageStarted(string stageName, int componentCount);

    [LoggerMessage(Level = LogLevel.Information, Message = "Validation stage failed: {StageName}. FailureCount: {FailureCount}, ElapsedMs: {ElapsedMs}")]
    private partial void LogStageFailed(string stageName, int failureCount, long elapsedMs);

    [LoggerMessage(Level = LogLevel.Debug, Message = "Validation stage skipped: {StageName}. Reason: {Reason}")]
    private partial void LogStageSkipped(string stageName, string reason);

    [LoggerMessage(Level = LogLevel.Debug, Message = "Evaluating trust plan")]
    private partial void LogTrustPlanStarted();

    [LoggerMessage(Level = LogLevel.Debug, Message = "Trust satisfied")]
    private partial void LogTrustSatisfied();

    [LoggerMessage(Level = LogLevel.Information, Message = "Trust not satisfied. ReasonCount: {ReasonCount}")]
    private partial void LogTrustNotSatisfied(int reasonCount);

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
    private readonly TrustEvaluationOptions TrustEvaluationOptions;
    private readonly Trust.Plan.CompiledTrustPlan _trustPlan;
    private readonly IReadOnlyList<ISigningKeyResolver> SigningKeyResolvers;
    private readonly IReadOnlyList<IPostSignatureValidator> PostSignatureValidators;
    private readonly IReadOnlyList<IToBeSignedAttestor> ToBeSignedAttestors;
    private readonly ILogger<CoseSign1Validator> Logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="CoseSign1Validator"/> class.
    /// </summary>
    /// <param name="signingKeyResolvers">Signing key resolvers for the key-resolution stage.</param>
    /// <param name="postSignatureValidators">Post-signature validators to run after trust and signature verification.</param>
    /// <param name="toBeSignedAttestors">Optional attestors that can assert the message ToBeSigned has already been validated.</param>
    /// <param name="trustPlan">The compiled trust plan evaluated during the trust stage.</param>
    /// <param name="options">Validation options including detached payload, associated data, and signature-only mode.</param>
    /// <param name="logger">Optional logger for diagnostic output. If null, logging is disabled.</param>
    /// <param name="trustEvaluationOptions">Options controlling trust evaluation behavior (including bypass).</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="signingKeyResolvers"/> or <paramref name="trustPlan"/> is null.</exception>
    public CoseSign1Validator(
        IEnumerable<ISigningKeyResolver> signingKeyResolvers,
        IEnumerable<IPostSignatureValidator>? postSignatureValidators,
        IEnumerable<IToBeSignedAttestor>? toBeSignedAttestors,
        Trust.Plan.CompiledTrustPlan trustPlan,
        CoseSign1ValidationOptions? options = null,
        TrustEvaluationOptions? trustEvaluationOptions = null,
        ILogger<CoseSign1Validator>? logger = null)
    {
        Guard.ThrowIfNull(signingKeyResolvers);
        Guard.ThrowIfNull(trustPlan);

        SigningKeyResolvers = signingKeyResolvers as IReadOnlyList<ISigningKeyResolver>
            ?? signingKeyResolvers.ToArray();

        PostSignatureValidators = postSignatureValidators == null
            ? Array.Empty<IPostSignatureValidator>()
            : (postSignatureValidators as IReadOnlyList<IPostSignatureValidator> ?? postSignatureValidators.ToArray());

        ToBeSignedAttestors = toBeSignedAttestors == null
            ? Array.Empty<IToBeSignedAttestor>()
            : (toBeSignedAttestors as IReadOnlyList<IToBeSignedAttestor> ?? toBeSignedAttestors.ToArray());

        _trustPlan = trustPlan;
        Options = options ?? new CoseSign1ValidationOptions();
        Logger = logger ?? NullLogger<CoseSign1Validator>.Instance;
        TrustEvaluationOptions = trustEvaluationOptions ?? new TrustEvaluationOptions();
    }

    /// <inheritdoc />
    public Trust.Plan.CompiledTrustPlan TrustPlan => _trustPlan;

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
        Guard.ThrowIfNull(message);

        // Ensures the logger field is treated as used even when log methods are source-generated.
        _ = Logger.IsEnabled(LogLevel.Trace);

        LogValidationStarted(SigningKeyResolvers.Count, PostSignatureValidators.Count);

        // Stage 1: Trust evaluation (policy) is performed first.
        // This allows receipt/counter-signature-based trust models to succeed even when no primary signing key is resolvable.
        var (trustResult, trustDecision) = await RunTrustStageCoreAsync(message, async, cancellationToken).ConfigureAwait(false);

        if (!trustResult.IsValid)
        {
            LogStageSkipped(ClassStrings.StageNameKeyMaterialResolution, ClassStrings.NotApplicableReasonPriorStageFailed);
            LogStageSkipped(ClassStrings.StageNameSignature, ClassStrings.NotApplicableReasonSigningKeyNotTrusted);
            LogStageSkipped(ClassStrings.StageNamePostSignature, ClassStrings.NotApplicableReasonSigningKeyNotTrusted);

            return new CoseSign1ValidationResult(
                resolution: ValidationResult.NotApplicable(ClassStrings.StageNameKeyMaterialResolution, ClassStrings.NotApplicableReasonPriorStageFailed),
                trust: trustResult,
                signature: ValidationResult.NotApplicable(ClassStrings.StageNameSignature, ClassStrings.NotApplicableReasonSigningKeyNotTrusted),
                postSignaturePolicy: ValidationResult.NotApplicable(ClassStrings.StageNamePostSignature, ClassStrings.NotApplicableReasonSigningKeyNotTrusted),
                overall: trustResult);
        }

        // Optional short-circuit: if a counter-signature attests it has validated the same Sig_structure / ToBeSigned,
        // the primary signing key may not need to be resolved or validated.
        if (Options.AllowToBeSignedAttestationToSkipPrimarySignature && ToBeSignedAttestors.Count > 0)
        {
            var attestation = await TryGetToBeSignedAttestationAsync(message, async, cancellationToken).ConfigureAwait(false);

            if (attestation.HasValue && attestation.Value.IsAttested)
            {
                var attestationMetadata = new Dictionary<string, object>();
                MergeStageMetadata(attestationMetadata, ClassStrings.MetadataPrefixTrust, trustResult);
                var attestationProvider = attestation.Value.Provider;
                if (attestationProvider is not null && !string.IsNullOrWhiteSpace(attestationProvider))
                {
                    attestationMetadata[ClassStrings.MetadataKeyToBeSignedAttestationProvider] = attestationProvider;
                }
                var attestationDetails = attestation.Value.Details;
                if (attestationDetails is not null && !string.IsNullOrWhiteSpace(attestationDetails))
                {
                    attestationMetadata[ClassStrings.MetadataKeyToBeSignedAttestationDetails] = attestationDetails;
                }

                var attestationOverall = ValidationResult.Success(ClassStrings.ValidatorNameOverall, attestationMetadata);

                return new CoseSign1ValidationResult(
                    resolution: ValidationResult.NotApplicable(ClassStrings.StageNameKeyMaterialResolution, ClassStrings.NotApplicableReasonSatisfiedByToBeSignedAttestation),
                    trust: trustResult,
                    signature: ValidationResult.NotApplicable(ClassStrings.StageNameSignature, ClassStrings.NotApplicableReasonSatisfiedByToBeSignedAttestation),
                    postSignaturePolicy: ValidationResult.NotApplicable(ClassStrings.StageNamePostSignature, ClassStrings.NotApplicableReasonSatisfiedByToBeSignedAttestation),
                    overall: attestationOverall);
            }
        }

        // Stage 2: Key Material Resolution
        var (resolutionResult, signingKey) = await RunResolutionStageCoreAsync(message, SigningKeyResolvers, async, cancellationToken).ConfigureAwait(false);

        if (!resolutionResult.IsValid)
        {
            LogStageSkipped(ClassStrings.StageNameSignature, ClassStrings.NotApplicableReasonPriorStageFailed);
            LogStageSkipped(ClassStrings.StageNamePostSignature, ClassStrings.NotApplicableReasonPriorStageFailed);

            return new CoseSign1ValidationResult(
                resolution: resolutionResult,
                trust: trustResult,
                signature: ValidationResult.NotApplicable(ClassStrings.StageNameSignature, ClassStrings.NotApplicableReasonPriorStageFailed),
                postSignaturePolicy: ValidationResult.NotApplicable(ClassStrings.StageNamePostSignature, ClassStrings.NotApplicableReasonPriorStageFailed),
                overall: resolutionResult);
        }

        // Stage 3: Signature Verification
        var signatureResult = await RunSignatureStageCoreAsync(message, signingKey!, async, cancellationToken).ConfigureAwait(false);

        if (!signatureResult.IsValid)
        {
            LogStageSkipped(ClassStrings.StageNamePostSignature, ClassStrings.NotApplicableReasonSignatureValidationFailed);

            return new CoseSign1ValidationResult(
                resolution: resolutionResult,
                trust: trustResult,
                signature: signatureResult,
                postSignaturePolicy: ValidationResult.NotApplicable(ClassStrings.StageNamePostSignature, ClassStrings.NotApplicableReasonSignatureValidationFailed),
                overall: signatureResult);
        }

        // Stage 4: Post-Signature Policy
        var postSignatureResult = await RunPostSignatureStageCoreAsync(
            message,
            signingKey,
            trustDecision,
            signatureResult.Metadata,
            PostSignatureValidators,
            async,
            cancellationToken).ConfigureAwait(false);

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

    private async ValueTask<ToBeSignedAttestationResult?> TryGetToBeSignedAttestationAsync(
        CoseSign1Message message,
        bool async,
        CancellationToken cancellationToken)
    {
        foreach (var attestor in ToBeSignedAttestors)
        {
            if (async)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var result = await attestor.AttestAsync(message, cancellationToken).ConfigureAwait(false);
                if (result.IsAttested)
                {
                    return result;
                }
            }
            else
            {
                var result = await attestor.AttestAsync(message, cancellationToken).ConfigureAwait(false);
                if (result.IsAttested)
                {
                    return result;
                }
            }
        }

        return null;
    }

    private async ValueTask<(ValidationResult Result, ISigningKey? SigningKey)> RunResolutionStageCoreAsync(
        CoseSign1Message message,
        IReadOnlyList<ISigningKeyResolver> resolvers,
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

    private async ValueTask<(ValidationResult Result, TrustDecision Decision)> RunTrustStageCoreAsync(
        CoseSign1Message message,
        bool async,
        CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();

        LogTrustPlanStarted();

        if (TrustEvaluationOptions.BypassTrust)
        {
            stopwatch.Stop();
            LogTrustSatisfied();
            LogStageCompleted(ClassStrings.StageNameKeyMaterialTrust, true, stopwatch.ElapsedMilliseconds);

            var bypassDecision = TrustDecision.Trusted(nameof(TrustEvaluationOptions.BypassTrust));

            var bypassMetadata = new Dictionary<string, object>
            {
                [nameof(TrustEvaluationOptions.BypassTrust)] = true,
                [nameof(TrustDecision)] = bypassDecision
            };

            return (ValidationResult.Success(ClassStrings.StageNameKeyMaterialTrust, bypassMetadata), bypassDecision);
        }

        TrustDecision trustDecision;
        TrustDecisionAudit? audit = null;

        var subject = TrustSubject.Message(message);
        var messageId = subject.Id;

        if (async)
        {
            var eval = await _trustPlan.EvaluateWithAuditAsync(messageId, message, subject, TrustEvaluationOptions, memoryCache: null, cancellationToken).ConfigureAwait(false);
            trustDecision = eval.Decision;
            audit = eval.Audit;
        }
        else
        {
            var eval = _trustPlan.EvaluateWithAudit(messageId, message, subject, TrustEvaluationOptions, memoryCache: null, cancellationToken);
            trustDecision = eval.Decision;
            audit = eval.Audit;
        }

        stopwatch.Stop();

        if (!trustDecision.IsTrusted)
        {
            LogTrustNotSatisfied(trustDecision.Reasons.Count);

            var failures = trustDecision.Reasons.Count == 0
                ? new[]
                {
                    new ValidationFailure
                    {
                        ErrorCode = ClassStrings.ErrorCodeTrustPlanNotSatisfied,
                        Message = ClassStrings.ErrorMessageTrustPlanNotSatisfied
                    }
                }
                : trustDecision.Reasons.Select(r => new ValidationFailure
                {
                    ErrorCode = ClassStrings.ErrorCodeTrustPlanNotSatisfied,
                    Message = r
                }).ToArray();

            var failureMetadata = new Dictionary<string, object>
            {
                [nameof(TrustDecision)] = trustDecision
            };

            if (audit != null)
            {
                failureMetadata[nameof(TrustDecisionAudit)] = audit;
            }

            var failureResult = new ValidationResult
            {
                Kind = ValidationResultKind.Failure,
                ValidatorName = ClassStrings.StageNameKeyMaterialTrust,
                Failures = failures,
                Metadata = failureMetadata
            };

            return (failureResult, trustDecision);
        }

        LogTrustSatisfied();
        LogStageCompleted(ClassStrings.StageNameKeyMaterialTrust, true, stopwatch.ElapsedMilliseconds);

        if (audit != null)
        {
            var metadata = new Dictionary<string, object>
            {
                [nameof(TrustDecision)] = trustDecision,
                [nameof(TrustDecisionAudit)] = audit
            };
            return (ValidationResult.Success(ClassStrings.StageNameKeyMaterialTrust, metadata), trustDecision);
        }

        return (ValidationResult.Success(ClassStrings.StageNameKeyMaterialTrust), trustDecision);
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
        TrustDecision trustDecision,
        IReadOnlyDictionary<string, object> signatureMetadata,
        IReadOnlyList<IPostSignatureValidator> postValidators,
        bool async,
        CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();

        // Signature-only mode skips all post-signature policy checks.
        if (Options.SkipPostSignatureValidation)
        {
            stopwatch.Stop();
            LogStageCompletedNoComponents(ClassStrings.StageNamePostSignature, stopwatch.ElapsedMilliseconds);
            return ValidationResult.Success(ClassStrings.StageNamePostSignature);
        }

        if (postValidators.Count == 0)
        {
            stopwatch.Stop();
            LogStageCompletedNoComponents(ClassStrings.StageNamePostSignature, stopwatch.ElapsedMilliseconds);
            return ValidationResult.Success(ClassStrings.StageNamePostSignature);
        }

        LogStageStarted(ClassStrings.StageNamePostSignature, postValidators.Count);

        var context = new PostSignatureValidationContext(
            message,
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
