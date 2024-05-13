// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Local.Validators;

/// <summary>
/// This class provides common infrastructure for validating certificate based properties on a <see cref="CoseSign1Message"/>.
/// </summary>
public abstract class X509Certificate2MessageValidator : CoseSign1MessageValidator
{
    /// <summary>
    /// True to specify that the UnprotectedHeaders are allowed to contribute to the list of headers, false to only allow Protected Headers.
    /// </summary>
    public bool AllowUnprotected { get; }

    /// <summary>
    /// Creates a new <see cref="X509Certificate2MessageValidator"/> with allowing population from the UnprotectedHeaders field of the message.
    /// </summary>
    /// <param name="allowUnprotected">True if the UnprotectedHeaders is allowed, False otherwise.</param>
    public X509Certificate2MessageValidator(bool allowUnprotected = false)
    {
        AllowUnprotected = allowUnprotected;
    }

    /// <summary>
    /// Mock .ctor
    /// </summary>
    protected X509Certificate2MessageValidator() : base() { }

    /// <inheritdoc/>
    protected override CoseSign1ValidationResult ValidateMessage(CoseSign1Message message)
    {
        CoseSign1ValidationResult initialResult = new(GetType());

        // grab the signing cert
        if (!message.TryGetSigningCertificate(out X509Certificate2? signingCert, AllowUnprotected))
        {
            initialResult.ResultMessage = "Failed to extract certificate from message object";
            return initialResult;
        }

        // grab the sign cert chain
        _ = message.TryGetCertificateChain(out List<X509Certificate2>? certChain, AllowUnprotected);

        // grab the X5Bag elements
        _ = message.TryGetExtraCertificates(out List<X509Certificate2>? extraCertificates, AllowUnprotected);

        return ValidateCertificate(signingCert!, certChain, extraCertificates);
    }

    /// <summary>
    /// Called to perform additional certificate validation techniques after all certificate related properties have been extracted.
    /// </summary>
    /// <param name="signingCertificate">The signing certificate as located in <paramref name="certChain"/> matching the thumbprint encoded in the <see cref="CertificateCoseHeaderLabels.X5T"/> attribute.</param>
    /// <param name="certChain">The certificate chain stored in the <see cref="CertificateCoseHeaderLabels.X5Chain"/> header label.</param>
    /// <param name="extraCertificates">Any extra certificates stored within the <see cref="CertificateCoseHeaderLabels.X5Bag"/> header label.</param>
    /// <returns>A <see cref="CoseSign1ValidationResult"/> object from the validation.</returns>
    protected abstract CoseSign1ValidationResult ValidateCertificate(
        X509Certificate2 signingCertificate,
        List<X509Certificate2>? certChain,
        List<X509Certificate2>? extraCertificates);
}
