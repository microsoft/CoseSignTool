// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Formats.Cbor;
using System.Diagnostics.CodeAnalysis;
using CoseSign1.Certificates.Extensions;

namespace CoseSign1.Certificates;

/// <summary>
/// Header contributor that adds X5T (certificate thumbprint) and X5Chain (certificate chain) headers
/// to COSE signatures for certificate-based signing keys.
/// This contributor should be used with ICertificateSigningKey implementations.
/// </summary>
public class CertificateHeaderContributor : IHeaderContributor
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public static readonly string ErrorSigningCertificateNotProvided = "Signing certificate is not provided";
        public static readonly string ErrorSigningCertificateThumbprintMustMatchFirstChainElementFormat =
            "The signing certificate thumbprint \"{0}\" must match the first item in the certificate chain, which is \"{1}\".";
        public static readonly string NullValue = "null";
    }

    /// <summary>
    /// COSE header labels specific to certificate-based signatures.
    /// </summary>
    public static class HeaderLabels
    {
        /// <summary>
        /// Represents the thumbprint for the certificate used to sign the message (x5t).
        /// IANA COSE header parameter: 34
        /// </summary>
        public static readonly CoseHeaderLabel X5T = new(34);

        /// <summary>
        /// Represents an ordered list (leaf first) of the certificate chain (x5chain).
        /// IANA COSE header parameter: 33
        /// </summary>
        public static readonly CoseHeaderLabel X5Chain = new(33);

        /// <summary>
        /// Represents an unordered bag of certificates (x5bag).
        /// IANA COSE header parameter: 32
        /// </summary>
        public static readonly CoseHeaderLabel X5Bag = new(32);
    }

    /// <summary>
    /// Gets the merge strategy for handling conflicts. Uses Fail to prevent overwriting existing headers.
    /// </summary>
    public HeaderMergeStrategy MergeStrategy => HeaderMergeStrategy.Fail;

    /// <summary>
    /// Contributes protected headers including X5T and X5Chain.
    /// </summary>
    /// <param name="headers">The header map to contribute to.</param>
    /// <param name="context">The header contributor context.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="headers"/> or <paramref name="context"/> is null.</exception>
    /// <exception cref="InvalidOperationException">Thrown when the signing certificate is missing or does not match the provided chain.</exception>
    public void ContributeProtectedHeaders(CoseHeaderMap headers, HeaderContributorContext context)
    {
        if (headers == null)
        {
            throw new ArgumentNullException(nameof(headers));
        }

        if (context == null)
        {
            throw new ArgumentNullException(nameof(context));
        }

        // Only process if the signing key is a certificate-based key
        if (context.SigningKey is not ICertificateSigningKey certKey)
        {
            return;
        }

        var cborWriter = new CborWriter();
        var signingCertificate = certKey.GetSigningCertificate();

        if (signingCertificate == null)
        {
            throw new InvalidOperationException(ClassStrings.ErrorSigningCertificateNotProvided);
        }

        // Add X5T (certificate thumbprint)
        var thumbprint = new CoseX509Thumbprint(signingCertificate);
        byte[] encodedThumbprint = thumbprint.Serialize(cborWriter);
        headers.Add(HeaderLabels.X5T, CoseHeaderValue.FromEncodedValue(encodedThumbprint));

        // Add X5Chain (certificate chain in leaf-first order)
        var chain = certKey.GetCertificateChain(X509ChainSortOrder.LeafFirst);
        var firstCert = chain.FirstOrDefault();

        // Ensure the first chain element matches the signing certificate
        if (firstCert == null || !signingCertificate.Thumbprint.Equals(firstCert.Thumbprint, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(string.Format(
                ClassStrings.ErrorSigningCertificateThumbprintMustMatchFirstChainElementFormat,
                signingCertificate.Thumbprint,
                firstCert?.Thumbprint ?? ClassStrings.NullValue));
        }

        cborWriter.EncodeCertList(chain);
        byte[] encodedChain = cborWriter.Encode();
        headers.Add(HeaderLabels.X5Chain, CoseHeaderValue.FromEncodedValue(encodedChain));
    }

    /// <summary>
    /// Contributes unprotected headers (none for certificates).
    /// </summary>
    /// <param name="headers">The header map to contribute to.</param>
    /// <param name="context">The header contributor context.</param>
    public void ContributeUnprotectedHeaders(CoseHeaderMap headers, HeaderContributorContext context)
    {
        // No unprotected headers for certificates
    }
}