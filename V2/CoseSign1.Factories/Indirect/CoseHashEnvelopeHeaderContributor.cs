// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Factories.Indirect;

using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using CoseSign1.Abstractions;

/// <summary>
/// Header contributor for COSE Hash Envelope format (RFC 9054).
/// Adds protected headers: PayloadHashAlg (258), PreimageContentType (259), and optionally PayloadLocation (260).
/// Removes content-type header (label 3) per RFC requirements.
/// </summary>
public sealed class CoseHashEnvelopeHeaderContributor : IHeaderContributor
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        // Hash algorithm names (used in switch pattern)
        public static readonly string AlgSHA256 = nameof(SHA256);
        public static readonly string AlgSHA384 = nameof(SHA384);
        public static readonly string AlgSHA512 = nameof(SHA512);

        // Error messages
        public static readonly string ErrorUnsupportedHashAlgorithm = "Hash algorithm {0} is not supported";
    }

    private readonly HashAlgorithmName HashAlgorithm;
    private readonly string ContentType;
    private readonly string? PayloadLocation;

    /// <summary>
    /// COSE header labels for Hash Envelope format (RFC 9054).
    /// </summary>
    /// <remarks>
    /// For new code, consider using <see cref="IndirectSignatureHeaderLabels"/> directly.
    /// </remarks>
    public static class HeaderLabels
    {
        /// <summary>
        /// PayloadHashAlg (258) - COSE algorithm identifier for the hash algorithm.
        /// </summary>
        public static CoseHeaderLabel PayloadHashAlg => IndirectSignatureHeaderLabels.PayloadHashAlg;

        /// <summary>
        /// PreimageContentType (259) - Content type of the original payload before hashing.
        /// </summary>
        public static CoseHeaderLabel PreimageContentType => IndirectSignatureHeaderLabels.PreimageContentType;

        /// <summary>
        /// PayloadLocation (260) - Optional location where the payload can be retrieved.
        /// </summary>
        public static CoseHeaderLabel PayloadLocation => IndirectSignatureHeaderLabels.PayloadLocation;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="CoseHashEnvelopeHeaderContributor"/> class.
    /// </summary>
    /// <param name="hashAlgorithm">The hash algorithm to use for the payload hash.</param>
    /// <param name="contentType">The preimage content type to store in the hash envelope headers.</param>
    /// <param name="payloadLocation">Optional payload location header value.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="contentType"/> is <see langword="null"/>.</exception>
    public CoseHashEnvelopeHeaderContributor(
        HashAlgorithmName hashAlgorithm,
        string contentType,
        string? payloadLocation = null)
    {
        HashAlgorithm = hashAlgorithm;
        ContentType = contentType ?? throw new ArgumentNullException(nameof(contentType));
        PayloadLocation = payloadLocation;
    }

    /// <summary>
    /// Gets the merge strategy. Use Replace to override the placeholder content type.
    /// </summary>
    public HeaderMergeStrategy MergeStrategy => HeaderMergeStrategy.Replace;

    /// <summary>
    /// Contributes protected headers for COSE Hash Envelope format.
    /// Removes content type (3) and adds PayloadHashAlg (258), PreimageContentType (259), and optionally PayloadLocation (260).
    /// Per RFC: Label 3 (content_type) MUST NOT be present when using hash envelope format.
    /// </summary>
    /// <param name="headers">The header map to contribute headers to.</param>
    /// <param name="context">The header contribution context.</param>
    /// <exception cref="NotSupportedException">Thrown when the configured hash algorithm is not supported.</exception>
    public void ContributeProtectedHeaders(CoseHeaderMap headers, HeaderContributorContext context)
    {
        // Remove content type header (label 3) if present
        // Label 3 is easily confused with label 259 (PreimageContentType)
        // Per RFC: content_type (3) MUST NOT be present with hash envelope format
        if (headers.ContainsKey(CoseHeaderLabel.ContentType))
        {
            headers.Remove(CoseHeaderLabel.ContentType);
        }

        // Add PayloadHashAlg (258) - COSE algorithm identifier
        int coseAlgId;
        if (HashAlgorithm.Name == ClassStrings.AlgSHA256)
        {
            coseAlgId = -16; // COSE algorithm -16 = SHA-256
        }
        else if (HashAlgorithm.Name == ClassStrings.AlgSHA384)
        {
            coseAlgId = -43; // COSE algorithm -43 = SHA-384
        }
        else if (HashAlgorithm.Name == ClassStrings.AlgSHA512)
        {
            coseAlgId = -44; // COSE algorithm -44 = SHA-512
        }
        else
        {
            throw new NotSupportedException(string.Format(ClassStrings.ErrorUnsupportedHashAlgorithm, HashAlgorithm.Name));
        }

        // Add or update PayloadHashAlg (258)
        if (headers.ContainsKey(HeaderLabels.PayloadHashAlg))
        {
            headers[HeaderLabels.PayloadHashAlg] = CoseHeaderValue.FromInt32(coseAlgId);
        }
        else
        {
            headers.Add(HeaderLabels.PayloadHashAlg, CoseHeaderValue.FromInt32(coseAlgId));
        }

        // Add or update PreimageContentType (259)
        var contentTypeValue = CoseHeaderValue.FromString(ContentType);
        if (headers.ContainsKey(HeaderLabels.PreimageContentType))
        {
            headers[HeaderLabels.PreimageContentType] = contentTypeValue;
        }
        else
        {
            headers.Add(HeaderLabels.PreimageContentType, contentTypeValue);
        }

        // Add or update PayloadLocation (260) if specified
        if (!string.IsNullOrEmpty(PayloadLocation))
        {
            var locationValue = CoseHeaderValue.FromString(PayloadLocation!);
            if (headers.ContainsKey(HeaderLabels.PayloadLocation))
            {
                headers[HeaderLabels.PayloadLocation] = locationValue;
            }
            else
            {
                headers.Add(HeaderLabels.PayloadLocation, locationValue);
            }
        }
    }

    /// <summary>
    /// Ensures no content-type header in unprotected headers.
    /// </summary>
    /// <param name="headers">The header map to contribute headers to.</param>
    /// <param name="context">The header contribution context.</param>
    public void ContributeUnprotectedHeaders(CoseHeaderMap headers, HeaderContributorContext context)
    {
        // Remove content-type header (label 3) if present
        // Per RFC: Label 3 (content_type) MUST NOT be present in protected or unprotected headers
        if (headers.ContainsKey(CoseHeaderLabel.ContentType))
        {
            headers.Remove(CoseHeaderLabel.ContentType);
        }
    }
}
