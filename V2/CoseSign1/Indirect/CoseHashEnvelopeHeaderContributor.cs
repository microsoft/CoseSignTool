// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Indirect;

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
    private readonly HashAlgorithmName _hashAlgorithm;
    private readonly string _contentType;
    private readonly string? _payloadLocation;

    /// <summary>
    /// COSE header labels for Hash Envelope format (RFC 9054).
    /// </summary>
    public static class HeaderLabels
    {
        /// <summary>
        /// PayloadHashAlg (258) - COSE algorithm identifier for the hash algorithm.
        /// </summary>
        public static readonly CoseHeaderLabel PayloadHashAlg = new(258);

        /// <summary>
        /// PreimageContentType (259) - Content type of the original payload before hashing.
        /// </summary>
        public static readonly CoseHeaderLabel PreimageContentType = new(259);

        /// <summary>
        /// PayloadLocation (260) - Optional location where the payload can be retrieved.
        /// </summary>
        public static readonly CoseHeaderLabel PayloadLocation = new(260);
    }

    public CoseHashEnvelopeHeaderContributor(
        HashAlgorithmName hashAlgorithm,
        string contentType,
        string? payloadLocation = null)
    {
        _hashAlgorithm = hashAlgorithm;
        _contentType = contentType ?? throw new ArgumentNullException(nameof(contentType));
        _payloadLocation = payloadLocation;
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
        int coseAlgId = _hashAlgorithm.Name switch
        {
            nameof(SHA256) => -16, // COSE algorithm -16 = SHA-256
            nameof(SHA384) => -43, // COSE algorithm -43 = SHA-384
            nameof(SHA512) => -44, // COSE algorithm -44 = SHA-512
            _ => throw new NotSupportedException($"Hash algorithm {_hashAlgorithm.Name} is not supported")
        };

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
        var contentTypeValue = CoseHeaderValue.FromString(_contentType);
        if (headers.ContainsKey(HeaderLabels.PreimageContentType))
        {
            headers[HeaderLabels.PreimageContentType] = contentTypeValue;
        }
        else
        {
            headers.Add(HeaderLabels.PreimageContentType, contentTypeValue);
        }

        // Add or update PayloadLocation (260) if specified
        if (!string.IsNullOrEmpty(_payloadLocation))
        {
            var locationValue = CoseHeaderValue.FromString(_payloadLocation);
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