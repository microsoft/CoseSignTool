// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Diagnostics.CodeAnalysis;
using CoseSign1.Certificates.Extensions;
using CoseSign1.Validation;

namespace CoseSign1.Certificates.Validation;

/// <summary>
/// Validates that X.509 signing key material can be resolved from a COSE_Sign1 message.
/// </summary>
/// <remarks>
/// <para>
/// This validator is intentionally <strong>not</strong> a signature verifier and does not attempt to
/// establish certificate trust. It exists to make the verification pipeline explicit and safe:
/// </para>
/// <list type="number">
/// <item><description><strong>Resolve</strong>: extract and parse key material from headers</description></item>
/// <item><description><strong>Trust</strong>: validate chain / identity / policy for that key material</description></item>
/// <item><description><strong>Verify</strong>: verify the COSE signature only after trust succeeds</description></item>
/// </list>
/// <para>
/// For X.509 signatures, "resolution" means ensuring the message contains a usable <c>x5t</c> and
/// <c>x5chain</c>, that the chain parses correctly, and that the signing certificate can be identified
/// by matching <c>x5t</c> to a certificate in <c>x5chain</c>.
/// </para>
/// </remarks>
public sealed class CertificateKeyMaterialResolutionValidator :
    IValidator,
    IConditionalValidator
{
    private static readonly IReadOnlyCollection<ValidationStage> StagesField = new[] { ValidationStage.KeyMaterialResolution };

    /// <inheritdoc/>
    public IReadOnlyCollection<ValidationStage> Stages => StagesField;

    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public static readonly string ValidatorName = nameof(CertificateKeyMaterialResolutionValidator);

        public static readonly string ErrorCodeNullInput = "NULL_INPUT";
        public static readonly string ErrorCodeMissingOrInvalidChain = "X5CHAIN_INVALID";
        public static readonly string ErrorCodeMissingOrInvalidThumbprint = "X5T_INVALID";
        public static readonly string ErrorCodeSigningCertNotFound = "SIGNING_CERT_NOT_FOUND";

        public static readonly string ErrorMessageNullInput = "Input message is null";
        public static readonly string ErrorMessageMissingOrInvalidChain = "Message does not contain a valid x5chain header";
        public static readonly string ErrorMessageMissingOrInvalidThumbprint = "Message does not contain a valid x5t header";
        public static readonly string ErrorMessageSigningCertNotFound = "Signing certificate could not be identified from x5t + x5chain";

        public static readonly string MetaKeyChainLength = "ChainLength";
        public static readonly string MetaKeySigningThumbprint = "SigningThumbprint";
        public static readonly string MetaKeySigningSubject = "SigningSubject";
    }

    private readonly bool AllowUnprotectedHeaders;

    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateKeyMaterialResolutionValidator"/> class.
    /// </summary>
    /// <param name="allowUnprotectedHeaders">
    /// Whether key material may be resolved from unprotected headers.
    /// For compatibility with some existing emitters, the CLI defaults to allowing unprotected headers.
    /// </param>
    public CertificateKeyMaterialResolutionValidator(bool allowUnprotectedHeaders = false)
    {
        AllowUnprotectedHeaders = allowUnprotectedHeaders;
    }

    /// <inheritdoc/>
    public bool IsApplicable(CoseSign1Message input, ValidationStage stage)
    {
        if (input is null)
        {
            return false;
        }

        // Only apply when the message appears to use certificate-based headers.
        bool hasX5t = input.TryGetCertificateThumbprint(out _, AllowUnprotectedHeaders);
        bool hasX5chain = input.TryGetCertificateChain(out _, AllowUnprotectedHeaders);
        return hasX5t || hasX5chain;
    }

    /// <inheritdoc/>
    public ValidationResult Validate(CoseSign1Message input, ValidationStage stage)
    {
        if (input is null)
        {
            return ValidationResult.Failure(
                ClassStrings.ValidatorName,
                ClassStrings.ErrorMessageNullInput,
                ClassStrings.ErrorCodeNullInput);
        }

        if (!input.TryGetCertificateChain(out var chain, AllowUnprotectedHeaders) || chain == null || chain.Count == 0)
        {
            return ValidationResult.Failure(
                ClassStrings.ValidatorName,
                ClassStrings.ErrorMessageMissingOrInvalidChain,
                ClassStrings.ErrorCodeMissingOrInvalidChain);
        }

        if (!input.TryGetCertificateThumbprint(out var thumbprint, AllowUnprotectedHeaders) || thumbprint == null)
        {
            return ValidationResult.Failure(
                ClassStrings.ValidatorName,
                ClassStrings.ErrorMessageMissingOrInvalidThumbprint,
                ClassStrings.ErrorCodeMissingOrInvalidThumbprint);
        }

        if (!input.TryGetSigningCertificate(out var signingCertificate, AllowUnprotectedHeaders) || signingCertificate == null)
        {
            return ValidationResult.Failure(
                ClassStrings.ValidatorName,
                ClassStrings.ErrorMessageSigningCertNotFound,
                ClassStrings.ErrorCodeSigningCertNotFound);
        }

        var metadata = new Dictionary<string, object>
        {
            [ClassStrings.MetaKeyChainLength] = chain.Count,
            [ClassStrings.MetaKeySigningThumbprint] = signingCertificate.Thumbprint,
            [ClassStrings.MetaKeySigningSubject] = signingCertificate.Subject,
        };

        return ValidationResult.Success(ClassStrings.ValidatorName, metadata);
    }

    /// <inheritdoc/>
    public Task<ValidationResult> ValidateAsync(CoseSign1Message input, ValidationStage stage, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(Validate(input, stage));
    }
}
