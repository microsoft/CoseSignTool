// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Transparent.MST.Validation;

using System.Security.Cryptography.Cose;
using System.Diagnostics.CodeAnalysis;
using Azure.Security.CodeTransparency;
using CoseSign1.Transparent.MST.Extensions;
using CoseSign1.Validation;
using CoseSign1.Validation.Builders;
using CoseSign1.Validation.Interfaces;
using CoseSign1.Validation.Results;

/// <summary>
/// Validates MST receipts by first querying the configured endpoint for its current signing keys,
/// then performing full receipt proof validation using only those keys (no fallback).
/// </summary>
public sealed class MstReceiptOnlineValidator : IConditionalValidator, IProvidesDefaultTrustPolicy
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public static readonly string ValidatorName = nameof(MstReceiptOnlineValidator);

        public const string NotApplicableReasonUnsupportedStageFormat = "Unsupported validation stage: {0}";

        public const string ErrorMessageNullInput = "Input message cannot be null";
        public const string ErrorCodeNullInput = "MST_NULL_INPUT";

        public const string TrustDetailsNoReceipt = "NoReceipt";
        public const string TrustDetailsVerificationFailed = "VerificationFailed";
        public const string TrustDetailsException = "Exception";

        public const string MetadataKeyProviderName = "ProviderName";
        public const string MetadataKeyErrors = "Errors";
        public const string MetadataKeyIssuerHost = "IssuerHost";
        public const string MetadataKeyExceptionType = "ExceptionType";
        public const string MetadataKeyExceptionMessage = "ExceptionMessage";

        public const string DefaultProviderName = "MST";
    }

    private readonly CodeTransparencyClient Client;
    private readonly string IssuerHost;

    private static readonly IReadOnlyCollection<ValidationStage> StagesField = new[] { ValidationStage.KeyMaterialTrust };

    /// <inheritdoc/>
    public IReadOnlyCollection<ValidationStage> Stages => StagesField;

    /// <summary>
    /// Initializes a new instance of the <see cref="MstReceiptOnlineValidator"/> class.
    /// </summary>
    /// <param name="client">The Azure Code Transparency client.</param>
    /// <param name="issuerHost">The issuer host name used for offline key association and authorization.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="client"/> is null.</exception>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="issuerHost"/> is null or whitespace.</exception>
    public MstReceiptOnlineValidator(CodeTransparencyClient client, string issuerHost)
    {
        Client = client ?? throw new ArgumentNullException(nameof(client));
        IssuerHost = string.IsNullOrWhiteSpace(issuerHost) ? throw new ArgumentNullException(nameof(issuerHost)) : issuerHost;
    }

    /// <inheritdoc/>
    public bool IsApplicable(CoseSign1Message input, ValidationStage stage)
    {
        if (input == null)
        {
            return false;
        }

        if (stage != ValidationStage.KeyMaterialTrust)
        {
            return false;
        }

        return input.HasMstReceipt();
    }

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

        return ValidateAsync(input, stage, CancellationToken.None).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public async Task<ValidationResult> ValidateAsync(CoseSign1Message input, ValidationStage stage, CancellationToken cancellationToken = default)
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

        if (!input.HasMstReceipt())
        {
            return ValidationResult.Success(ClassStrings.ValidatorName, stage, new Dictionary<string, object>
            {
                [TrustAssertionMetadata.AssertionsKey] = new[]
                {
                    new TrustAssertion(MstTrustClaims.ReceiptPresent, satisfied: false),
                    new TrustAssertion(MstTrustClaims.ReceiptTrusted, satisfied: false, details: ClassStrings.TrustDetailsNoReceipt)
                }
            });
        }

        try
        {
            // Fetch current signing keys for the configured endpoint.
            var jwksResponse = await Client.GetPublicKeysAsync(cancellationToken).ConfigureAwait(false);
            var jwks = jwksResponse.Value;

            var offlineKeys = new CodeTransparencyOfflineKeys();
            offlineKeys.Add(IssuerHost, jwks);

            var verificationOptions = new CodeTransparencyVerificationOptions
            {
                OfflineKeys = offlineKeys,
                OfflineKeysBehavior = OfflineKeysBehavior.NoFallbackToNetwork,
                AuthorizedDomains = new[] { IssuerHost },
                UnauthorizedReceiptBehavior = UnauthorizedReceiptBehavior.FailIfPresent
            };

            var provider = new MstTransparencyProvider(Client, verificationOptions, clientOptions: null);
            var transparencyResult = await provider.VerifyTransparencyProofAsync(input, cancellationToken).ConfigureAwait(false);

            if (!transparencyResult.IsValid)
            {
                var metadata = new Dictionary<string, object>
                {
                    [TrustAssertionMetadata.AssertionsKey] = new[]
                    {
                        new TrustAssertion(MstTrustClaims.ReceiptPresent, satisfied: true),
                        new TrustAssertion(MstTrustClaims.ReceiptTrusted, satisfied: false, details: ClassStrings.TrustDetailsVerificationFailed)
                    },
                    [ClassStrings.MetadataKeyProviderName] = transparencyResult.ProviderName ?? ClassStrings.DefaultProviderName,
                    [ClassStrings.MetadataKeyErrors] = transparencyResult.Errors.ToArray(),
                    [ClassStrings.MetadataKeyIssuerHost] = IssuerHost
                };

                if (transparencyResult.Metadata != null)
                {
                    foreach (var kvp in transparencyResult.Metadata)
                    {
                        metadata[kvp.Key] = kvp.Value;
                    }
                }

                return ValidationResult.Success(ClassStrings.ValidatorName, stage, metadata);
            }

            var successMetadata = new Dictionary<string, object>
            {
                [ClassStrings.MetadataKeyProviderName] = transparencyResult.ProviderName ?? ClassStrings.DefaultProviderName,
                [ClassStrings.MetadataKeyIssuerHost] = IssuerHost,
                [TrustAssertionMetadata.AssertionsKey] = new[]
                {
                    new TrustAssertion(MstTrustClaims.ReceiptPresent, satisfied: true),
                    new TrustAssertion(MstTrustClaims.ReceiptTrusted, satisfied: true)
                }
            };

            if (transparencyResult.Metadata != null)
            {
                foreach (var kvp in transparencyResult.Metadata)
                {
                    successMetadata[kvp.Key] = kvp.Value;
                }
            }

            return ValidationResult.Success(ClassStrings.ValidatorName, stage, successMetadata);
        }
        catch (Exception ex)
        {
            return ValidationResult.Success(ClassStrings.ValidatorName, stage, new Dictionary<string, object>
            {
                [TrustAssertionMetadata.AssertionsKey] = new[]
                {
                    new TrustAssertion(MstTrustClaims.ReceiptPresent, satisfied: true),
                    new TrustAssertion(MstTrustClaims.ReceiptTrusted, satisfied: false, details: ClassStrings.TrustDetailsException)
                },
                [ClassStrings.MetadataKeyExceptionType] = ex.GetType().FullName ?? ex.GetType().Name,
                [ClassStrings.MetadataKeyExceptionMessage] = ex.Message,
                [ClassStrings.MetadataKeyIssuerHost] = IssuerHost
            });
        }
    }

    /// <inheritdoc/>
    public TrustPolicy GetDefaultTrustPolicy(ValidationBuilderContext context)
    {
        return TrustPolicy.And(
            TrustPolicy.Claim(MstTrustClaims.ReceiptPresent),
            TrustPolicy.Claim(MstTrustClaims.ReceiptTrusted));
    }
}
