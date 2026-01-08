// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation;

using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography.Cose;
using CoseSign1.Validation.Interfaces;
using CoseSign1.Validation.Results;
using CoseSign1.Validation.Validators;

/// <summary>
/// Orchestrates staged validation of a COSE Sign1 message.
/// </summary>
/// <remarks>
/// This is the library-level orchestration layer used by CoseSign1 consumers (including CoseSignTool).
/// It enforces the secure-by-default stage ordering:
///   resolution → trust → signature → post-signature.
/// </remarks>
public sealed class CoseSign1Validator : ICoseSign1Validator
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

        public const string MetadataPrefixResolution = "Resolution";
        public const string MetadataPrefixTrust = "Trust";
        public const string MetadataPrefixSignature = "Signature";
        public const string MetadataPrefixPost = "Post";

        public const string MetadataKeySeparator = ".";

        public const string ErrorCodeTrustPolicyNotSatisfied = "TRUST_POLICY_NOT_SATISFIED";
        public const string ErrorMessageTrustPolicyNotSatisfied = "Trust policy was not satisfied";

        public const string ErrorNoValidators = "No validators were provided";
        public const string ErrorNoSignatureValidators = "No signature validators were provided";
    }

    private readonly IReadOnlyList<IValidator>? ResolutionValidators;
    private readonly IReadOnlyList<IValidator>? TrustValidators;
    private readonly IReadOnlyList<IValidator> SignatureValidators;
    private readonly IReadOnlyList<IValidator>? PostSignatureValidators;

    /// <summary>
    /// Initializes a new instance of the <see cref="CoseSign1Validator"/> class.
    /// </summary>
    /// <param name="validators">Validators for any stage. Validators declare supported stages via <see cref="IValidator.Stages"/>.</param>
    /// <param name="trustPolicy">The trust policy evaluated against trust assertions.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="validators"/> or <paramref name="trustPolicy"/> is null.</exception>
    /// <exception cref="InvalidOperationException">Thrown when no validators are provided, or when no signature validators are provided.</exception>
    public CoseSign1Validator(IReadOnlyList<IValidator> validators, TrustPolicy trustPolicy)
    {
        Validators = validators ?? throw new ArgumentNullException(nameof(validators));
        TrustPolicy = trustPolicy ?? throw new ArgumentNullException(nameof(trustPolicy));

        if (Validators.Count == 0)
        {
            throw new InvalidOperationException(ClassStrings.ErrorNoValidators);
        }

        ResolutionValidators = FilterStageValidatorsOrNull(Validators, ValidationStage.KeyMaterialResolution);
        TrustValidators = FilterStageValidatorsOrNull(Validators, ValidationStage.KeyMaterialTrust);
        SignatureValidators = FilterStageValidatorsOrNull(Validators, ValidationStage.Signature)
            ?? throw new InvalidOperationException(ClassStrings.ErrorNoSignatureValidators);
        PostSignatureValidators = FilterStageValidatorsOrNull(Validators, ValidationStage.PostSignature);

        if (SignatureValidators.Count == 0)
        {
            throw new InvalidOperationException(ClassStrings.ErrorNoSignatureValidators);
        }
    }

    /// <inheritdoc />
    public TrustPolicy TrustPolicy { get; }

    /// <inheritdoc />
    public IReadOnlyList<IValidator> Validators { get; }

    /// <inheritdoc />
    public CoseSign1ValidationResult Validate(CoseSign1Message message)
    {
        return Validate(
            message,
            ResolutionValidators,
            TrustValidators,
            TrustPolicy,
            SignatureValidators,
            PostSignatureValidators);
    }

    /// <summary>
    /// Validates a COSE Sign1 message using staged validation.
    /// </summary>
    /// <param name="message">The message to validate.</param>
    /// <param name="validators">Validators for any stage. Validators declare supported stages via <see cref="IValidator.Stages"/>.</param>
    /// <param name="trustPolicy">The trust policy evaluated against trust assertions.</param>
    /// <returns>A staged validation result.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="message"/>, <paramref name="validators"/>, or <paramref name="trustPolicy"/> is null.</exception>
    public static CoseSign1ValidationResult Validate(
        CoseSign1Message message,
        IReadOnlyList<IValidator> validators,
        TrustPolicy trustPolicy)
    {
        if (message == null)
        {
            throw new ArgumentNullException(nameof(message));
        }

        if (validators == null)
        {
            throw new ArgumentNullException(nameof(validators));
        }

        if (trustPolicy == null)
        {
            throw new ArgumentNullException(nameof(trustPolicy));
        }

        var validator = new CoseSign1Validator(validators, trustPolicy);
        return validator.Validate(message);
    }

    private static CoseSign1ValidationResult Validate(
        CoseSign1Message message,
        IReadOnlyList<IValidator>? resolutionValidators,
        IReadOnlyList<IValidator>? trustValidators,
        TrustPolicy trustPolicy,
        IReadOnlyList<IValidator> signatureValidators,
        IReadOnlyList<IValidator>? postSignatureValidators)
    {
        if (message == null)
        {
            throw new ArgumentNullException(nameof(message));
        }

        if (signatureValidators == null)
        {
            throw new ArgumentNullException(nameof(signatureValidators));
        }

        if (trustPolicy == null)
        {
            throw new ArgumentNullException(nameof(trustPolicy));
        }

        if (signatureValidators.Count == 0)
        {
            throw new InvalidOperationException(ClassStrings.ErrorNoSignatureValidators);
        }

        var resolution = RunStage(
            stageName: ClassStrings.StageNameKeyMaterialResolution,
            stage: ValidationStage.KeyMaterialResolution,
            stageValidators: resolutionValidators,
            msg: message);

        if (!resolution.IsValid)
        {
            return new CoseSign1ValidationResult(
                resolution,
                trust: ValidationResult.NotApplicable(ClassStrings.StageNameKeyMaterialTrust, ValidationStage.KeyMaterialTrust, ClassStrings.NotApplicableReasonPriorStageFailed),
                signature: ValidationResult.NotApplicable(ClassStrings.StageNameSignature, ValidationStage.Signature, ClassStrings.NotApplicableReasonPriorStageFailed),
                postSignaturePolicy: ValidationResult.NotApplicable(ClassStrings.StageNamePostSignature, ValidationStage.PostSignature, ClassStrings.NotApplicableReasonPriorStageFailed),
                overall: resolution);
        }

        var trust = RunTrustStage(
            stageName: ClassStrings.StageNameKeyMaterialTrust,
            trustValidators: trustValidators,
            trustPolicy: trustPolicy,
            msg: message);

        if (!trust.IsValid)
        {
            // Trust failures are terminal.
            return new CoseSign1ValidationResult(
                resolution,
                trust,
                signature: ValidationResult.NotApplicable(ClassStrings.StageNameSignature, ValidationStage.Signature, ClassStrings.NotApplicableReasonSigningKeyNotTrusted),
                postSignaturePolicy: ValidationResult.NotApplicable(ClassStrings.StageNamePostSignature, ValidationStage.PostSignature, ClassStrings.NotApplicableReasonSigningKeyNotTrusted),
                overall: trust);
        }

        // Signature verification is always required and is never overridden.
        var signatureStageValidator = new AnySignatureValidator(signatureValidators);
        var signature = signatureStageValidator.Validate(message, ValidationStage.Signature);

        if (!signature.IsValid)
        {
            // Signature failures are terminal.
            return new CoseSign1ValidationResult(
                resolution,
                trust,
                signature,
                postSignaturePolicy: ValidationResult.NotApplicable(ClassStrings.StageNamePostSignature, ValidationStage.PostSignature, ClassStrings.NotApplicableReasonSignatureValidationFailed),
                overall: signature);
        }

        var postSignaturePolicy = RunStage(
            stageName: ClassStrings.StageNamePostSignature,
            stage: ValidationStage.PostSignature,
            stageValidators: postSignatureValidators,
            msg: message);

        if (!postSignaturePolicy.IsValid)
        {
            // Post-signature policy failures are terminal.
            return new CoseSign1ValidationResult(
                resolution,
                trust,
                signature,
                postSignaturePolicy,
                overall: postSignaturePolicy);
        }

        // Combine metadata from all successful stage results.
        var combinedMetadata = new Dictionary<string, object>();

        MergeStageMetadata(combinedMetadata, ClassStrings.MetadataPrefixResolution, resolution);
        MergeStageMetadata(combinedMetadata, ClassStrings.MetadataPrefixTrust, trust);
        MergeStageMetadata(combinedMetadata, ClassStrings.MetadataPrefixSignature, signature);
        MergeStageMetadata(combinedMetadata, ClassStrings.MetadataPrefixPost, postSignaturePolicy);

        var overall = ValidationResult.Success(ClassStrings.ValidatorNameOverall, combinedMetadata);

        return new CoseSign1ValidationResult(
            resolution,
            trust,
            signature,
            postSignaturePolicy,
            overall);
    }

    private static ValidationResult RunStage(
        string stageName,
        ValidationStage stage,
        IReadOnlyList<IValidator>? stageValidators,
        CoseSign1Message msg)
    {
        if (stageValidators == null || stageValidators.Count == 0)
        {
            return ValidationResult.Success(stageName, stage);
        }

        // StopOnFirstFailure is false for better diagnostics within a stage.
        var composite = new CompositeValidator(stageValidators, stopOnFirstFailure: false, runInParallel: false);
        var result = composite.Validate(msg, stage);

        if (!result.IsValid)
        {
            // Preserve failures but rename the stage for clearer output.
            return ValidationResult.Failure(stageName, stage, result.Failures.ToArray());
        }

        var metadataCopy = new Dictionary<string, object>();
        foreach (var kvp in result.Metadata)
        {
            metadataCopy[kvp.Key] = kvp.Value;
        }

        return ValidationResult.Success(stageName, stage, metadataCopy);
    }

    private static ValidationResult RunTrustStage(
        string stageName,
        IReadOnlyList<IValidator>? trustValidators,
        TrustPolicy trustPolicy,
        CoseSign1Message msg)
    {
        // Run the trust validators (if any) to collect trust assertions.
        ValidationResult trustValidatorsResult = RunStage(
            stageName: stageName,
            stage: ValidationStage.KeyMaterialTrust,
            stageValidators: trustValidators,
            msg: msg);

        // If any trust validator hard-failed, preserve that failure.
        // NOTE: callers are encouraged to model "not trusted" as a trust assertion instead of validator failures.
        if (!trustValidatorsResult.IsValid)
        {
            return trustValidatorsResult;
        }

        // Extract all assertions from metadata (if present).
        var assertions = GetTrustAssertionsOrEmpty(trustValidatorsResult.Metadata);
        var claims = new Dictionary<string, bool>(StringComparer.Ordinal);

        foreach (var a in assertions)
        {
            // "false" is meaningful (negative claim). Last writer wins.
            claims[a.ClaimId] = a.Satisfied;
        }

        if (!trustPolicy.IsSatisfied(claims))
        {
            var reasons = new List<string>();
            trustPolicy.Explain(claims, reasons);

            var failures = reasons.Count == 0
                ? new[]
                {
                    new ValidationFailure
                    {
                        ErrorCode = ClassStrings.ErrorCodeTrustPolicyNotSatisfied,
                        Message = ClassStrings.ErrorMessageTrustPolicyNotSatisfied
                    }
                }
                : reasons.Select(r => new ValidationFailure
                {
                    ErrorCode = ClassStrings.ErrorCodeTrustPolicyNotSatisfied,
                    Message = r
                }).ToArray();

            return ValidationResult.Failure(stageName, ValidationStage.KeyMaterialTrust, failures);
        }

        // Preserve the trust validator metadata on success.
        var metadataCopy = new Dictionary<string, object>();
        foreach (var kvp in trustValidatorsResult.Metadata)
        {
            metadataCopy[kvp.Key] = kvp.Value;
        }

        return ValidationResult.Success(stageName, ValidationStage.KeyMaterialTrust, metadataCopy);
    }

    private static IReadOnlyList<TrustAssertion> GetTrustAssertionsOrEmpty(IReadOnlyDictionary<string, object>? metadata)
    {
        if (metadata == null || metadata.Count == 0)
        {
            return Array.Empty<TrustAssertion>();
        }

        var assertions = new List<TrustAssertion>();

        foreach (var kvp in metadata)
        {
            // CompositeValidator prefixes metadata keys like "<ValidatorName>.<Key>".
            // We treat both "TrustAssertions" and "*.TrustAssertions" as assertion containers.
            if (!string.Equals(kvp.Key, TrustAssertionMetadata.AssertionsKey, StringComparison.Ordinal) &&
                !kvp.Key.EndsWith(string.Concat(ClassStrings.MetadataKeySeparator, TrustAssertionMetadata.AssertionsKey), StringComparison.Ordinal))
            {
                continue;
            }

            if (kvp.Value is IReadOnlyList<TrustAssertion> list)
            {
                assertions.AddRange(list);
            }
            else if (kvp.Value is IEnumerable<TrustAssertion> enumerable)
            {
                assertions.AddRange(enumerable);
            }
        }

        return assertions;
    }

    private static void MergeStageMetadata(Dictionary<string, object> combined, string prefix, ValidationResult stage)
    {
        foreach (var kvp in stage.Metadata)
        {
            combined[string.Concat(prefix, ClassStrings.MetadataKeySeparator, kvp.Key)] = kvp.Value;
        }
    }

    private static IReadOnlyList<IValidator>? FilterStageValidatorsOrNull(IReadOnlyList<IValidator> validators, ValidationStage stage)
    {
        if (validators.Count == 0)
        {
            return null;
        }

        List<IValidator>? list = null;

        for (int i = 0; i < validators.Count; i++)
        {
            var v = validators[i];
            if (v.Stages.Contains(stage))
            {
                list ??= new List<IValidator>();
                list.Add(v);
            }
        }

        return list;
    }
}
