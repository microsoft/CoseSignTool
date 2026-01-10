// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Validation;

using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography.Cose;
using CoseSign1.Certificates.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Resolves X.509 signing key material from a COSE_Sign1 message.
/// </summary>
/// <remarks>
/// <para>
/// This resolver is intentionally <strong>not</strong> a signature verifier and does not attempt to
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
public sealed partial class CertificateSigningKeyResolver : CertificateValidationComponentBase, ISigningKeyResolver
{
    /// <inheritdoc/>
    public override string ComponentName => ClassStrings.ValidatorName;

    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public static readonly string ValidatorName = nameof(CertificateSigningKeyResolver);

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

    private readonly CoseHeaderLocation CertificateHeaderLocation;
    private readonly ILogger<CertificateSigningKeyResolver> Logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateSigningKeyResolver"/> class.
    /// </summary>
    /// <param name="certificateHeaderLocation">
    /// Specifies where key material may be resolved from.
    /// For compatibility with some existing emitters, the CLI defaults to allowing unprotected headers.
    /// </param>
    /// <param name="logger">Optional logger for diagnostic output.</param>
    public CertificateSigningKeyResolver(
        CoseHeaderLocation certificateHeaderLocation = CoseHeaderLocation.Protected,
        ILogger<CertificateSigningKeyResolver>? logger = null)
    {
        CertificateHeaderLocation = certificateHeaderLocation;
        Logger = logger ?? NullLogger<CertificateSigningKeyResolver>.Instance;
    }

    // Log methods using source generators for high-performance logging
    [LoggerMessage(Level = LogLevel.Debug, Message = "Validating key material resolution for message")]
    private partial void LogValidatingKeyMaterial();

    [LoggerMessage(Level = LogLevel.Debug, Message = "Found certificate chain with {ChainLength} certificate(s)")]
    private partial void LogChainFound(int chainLength);

    [LoggerMessage(Level = LogLevel.Debug, Message = "Signing certificate resolved: Subject={Subject}, Thumbprint={Thumbprint}")]
    private partial void LogSigningCertResolved(string subject, string thumbprint);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Missing or invalid x5chain header")]
    private partial void LogMissingChain();

    [LoggerMessage(Level = LogLevel.Warning, Message = "Missing or invalid x5t header")]
    private partial void LogMissingThumbprint();

    [LoggerMessage(Level = LogLevel.Warning, Message = "Signing certificate not found in chain (x5t does not match any certificate)")]
    private partial void LogSigningCertNotFound();

    /// <inheritdoc/>
    public SigningKeyResolutionResult Resolve(CoseSign1Message message)
    {
        LogValidatingKeyMaterial();

        CoseHeaderLocation headerLocation = CertificateHeaderLocation;

        if (message is null)
        {
            return SigningKeyResolutionResult.Failure(
                ClassStrings.ErrorMessageNullInput,
                ClassStrings.ErrorCodeNullInput);
        }

        if (!message.TryGetCertificateChain(out var chain, headerLocation) || chain == null || chain.Count == 0)
        {
            LogMissingChain();
            return SigningKeyResolutionResult.Failure(
                ClassStrings.ErrorMessageMissingOrInvalidChain,
                ClassStrings.ErrorCodeMissingOrInvalidChain);
        }

        LogChainFound(chain.Count);

        if (!message.TryGetCertificateThumbprint(out var thumbprint, headerLocation) || thumbprint == null)
        {
            LogMissingThumbprint();
            return SigningKeyResolutionResult.Failure(
                ClassStrings.ErrorMessageMissingOrInvalidThumbprint,
                ClassStrings.ErrorCodeMissingOrInvalidThumbprint);
        }

        if (!message.TryGetSigningCertificate(out var signingCertificate, headerLocation) || signingCertificate == null)
        {
            LogSigningCertNotFound();
            return SigningKeyResolutionResult.Failure(
                ClassStrings.ErrorMessageSigningCertNotFound,
                ClassStrings.ErrorCodeSigningCertNotFound);
        }

        LogSigningCertResolved(signingCertificate.Subject, signingCertificate.Thumbprint);

        // Create a signing key from the certificate
        var signingKey = new X509CertificateSigningKey(signingCertificate, chain);

        return SigningKeyResolutionResult.Success(
            signingKey,
            keyId: null,
            thumbprint: thumbprint.Thumbprint.ToArray());
    }

    /// <inheritdoc/>
    public Task<SigningKeyResolutionResult> ResolveAsync(
        CoseSign1Message message,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(Resolve(message));
    }
}
