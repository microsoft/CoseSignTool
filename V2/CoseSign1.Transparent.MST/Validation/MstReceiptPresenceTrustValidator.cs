// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Transparent.MST.Validation;

using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography.Cose;
using CoseSign1.Transparent.MST.Extensions;
using CoseSign1.Validation;
using CoseSign1.Validation.Builders;
using CoseSign1.Validation.Interfaces;
using CoseSign1.Validation.Results;

/// <summary>
/// Emits trust assertions about whether an MST receipt is present.
/// This validator does not verify receipt trust.
/// </summary>
public sealed class MstReceiptPresenceTrustValidator : IValidator, IProvidesDefaultTrustPolicy
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public static readonly string ValidatorName = nameof(MstReceiptPresenceTrustValidator);

        public const string NotApplicableReasonUnsupportedStageFormat = "Unsupported validation stage: {0}";

        public const string ErrorMessageNullInput = "Input message cannot be null";
        public const string ErrorCodeNullInput = "MST_NULL_INPUT";

        public const string TrustDetailsNotVerified = "NotVerified";
        public const string TrustDetailsNoReceipt = "NoReceipt";
    }

    private static readonly IReadOnlyCollection<ValidationStage> StagesField = new[] { ValidationStage.KeyMaterialTrust };

    /// <inheritdoc/>
    public IReadOnlyCollection<ValidationStage> Stages => StagesField;

    /// <inheritdoc/>
    public ValidationResult Validate(CoseSign1Message input, ValidationStage stage)
    {
        if (stage != ValidationStage.KeyMaterialTrust)
        {
            return ValidationResult.NotApplicable(
                ClassStrings.ValidatorName,
                stage,
                string.Format(ClassStrings.NotApplicableReasonUnsupportedStageFormat, stage));
        }

        if (input == null)
        {
            return ValidationResult.Failure(
                ClassStrings.ValidatorName,
                stage,
                ClassStrings.ErrorMessageNullInput,
                ClassStrings.ErrorCodeNullInput);
        }

        bool hasReceipt = input.HasMstReceipt();

        return ValidationResult.Success(ClassStrings.ValidatorName, stage, new Dictionary<string, object>
        {
            [TrustAssertionMetadata.AssertionsKey] = new[]
            {
                new TrustAssertion(MstTrustClaims.ReceiptPresent, satisfied: hasReceipt),
                new TrustAssertion(MstTrustClaims.ReceiptTrusted, satisfied: false, details: hasReceipt ? ClassStrings.TrustDetailsNotVerified : ClassStrings.TrustDetailsNoReceipt)
            }
        });
    }

    /// <inheritdoc/>
    public Task<ValidationResult> ValidateAsync(CoseSign1Message input, ValidationStage stage, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(Validate(input, stage));
    }

    /// <inheritdoc/>
    public TrustPolicy GetDefaultTrustPolicy(ValidationBuilderContext context)
    {
        return TrustPolicy.Claim(MstTrustClaims.ReceiptPresent);
    }
}
