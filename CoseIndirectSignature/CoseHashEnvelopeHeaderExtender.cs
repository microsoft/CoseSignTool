// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseIndirectSignature;

using System.Collections.Generic;
using System.Security.Cryptography.Cose;

/// <summary>
/// Enumeration of COSE Hash Envelope header labels.
/// From https://www.iana.org/assignments/cose/cose.xhtml
/// </summary>
public enum CoseHashEnvelopeHeaderLabels : long
{
    /// <summary>
    /// No header label is defined.
    /// </summary>
    None = 0,
    /// <summary>
    /// The hash algorithm used to produce the payload.
    /// </summary>
    PayloadHashAlg = 258,
    /// <summary>
    /// The content type of the bytes that were hashed (preimage) to produce the payload, given as a content-format number or as a media-type name optionally with parameters.
    /// </summary>
    PreimageContentType = 259,
    /// <summary>
    /// An identifier enabling retrieval of the original resource (preimage) identified by the payload.
    /// </summary>
    PayloadLocation = 260
}

/// <summary>
/// This class implements the <see cref="ICoseHeaderExtender"/> interface for a CoseHashEnvelope indirect signature.
/// </summary>
public class CoseHashEnvelopeHeaderExtender: ICoseHeaderExtender
{
    private readonly HashAlgorithmName HashAlgoName;
    private readonly string ContentType;
    private readonly string? PayloadLocation;

    /// <summary>
    /// Initializes a new instance of the <see cref="CoseHashEnvelopeHeaderExtender"/> class.
    /// </summary>
    /// <param name="hashAlgoName">The <see cref="HashAlgoName"/> that the CoseHashEnvelope will use.</param>
    /// <param name="contentType">The content type of the original content being indirectly signed.</param>
    /// <param name="payloadLocation">The optional payload location which will be stored in the protected header if presented.</param>
    public CoseHashEnvelopeHeaderExtender(HashAlgorithmName hashAlgoName, string contentType, string? payloadLocation = null)
    {
        HashAlgoName = hashAlgoName;
        if(string.IsNullOrWhiteSpace(contentType))
        {
            throw new ArgumentNullException(nameof(contentType));
        }
        ContentType = contentType;
        PayloadLocation = payloadLocation;

        if(!HashAlgorithmToCoseHeaderValue.ContainsKey(hashAlgoName))
        {
            throw new CoseIndirectSignatureException($"Unsupported hash algorithm in {nameof(CoseHashEnvelopeHeaderExtender)}: {hashAlgoName}");
        }
    }
    /// <summary>
    /// A dictionary of COSE Hash Envelope header labels and their corresponding CoseHeaderLabel values.
    /// </summary>
    public static readonly Dictionary<CoseHashEnvelopeHeaderLabels,CoseHeaderLabel> CoseHashEnvelopeHeaderLabels = new()
    {
        { CoseIndirectSignature.CoseHashEnvelopeHeaderLabels.PayloadHashAlg, new CoseHeaderLabel(258) }, // payload-hash-alg
        { CoseIndirectSignature.CoseHashEnvelopeHeaderLabels.PreimageContentType, new CoseHeaderLabel(259) }, // preimage content type
        { CoseIndirectSignature.CoseHashEnvelopeHeaderLabels.PayloadLocation, new CoseHeaderLabel(260) } // payload-location
    };

    /// <summary>
    /// quick lookup of Cose Hash Algorithm name/value based on HashAlgorithmName
    /// </summary>
    private static readonly Dictionary<HashAlgorithmName, CoseHeaderValue> HashAlgorithmToCoseHeaderValue = new()
    {
        { HashAlgorithmName.SHA256, CoseHeaderValue.FromInt32((int)CoseHashAlgorithm.SHA256) },
        { HashAlgorithmName.SHA384, CoseHeaderValue.FromInt32((int)CoseHashAlgorithm.SHA384) },
        { HashAlgorithmName.SHA512, CoseHeaderValue.FromInt32((int)CoseHashAlgorithm.SHA512) }
    };

    /// <inheritdoc />
    /// <remarks>
    /// 3.  Header Parameters
    /// This document specifies the following new header parameters commonly
    /// used alongside hashes to identify resources:
    /// 258:  the hash algorithm used to produce the payload.
    /// 259:  the content type of the bytes that were hashed (preimage) to
    ///   produce the payload, given as a content-format number
    ///   (Section 12.3 of[RFC7252]) or as a media-type name optionally
    ///   with parameters(Section 8.3 of[RFC9110]).
    /// 260:  an identifier enabling retrieval of the original resource
    ///   (preimage) identified by the payload.
    /// </remarks>
    public CoseHeaderMap ExtendProtectedHeaders(CoseHeaderMap protectedHeaders)
    {
        _ = protectedHeaders ?? throw new ArgumentNullException(nameof(protectedHeaders));

        // Add the payload hash algorithm to the protected headers.
        protectedHeaders.Add(
            CoseHashEnvelopeHeaderLabels[CoseIndirectSignature.CoseHashEnvelopeHeaderLabels.PayloadHashAlg],
            HashAlgorithmToCoseHeaderValue[this.HashAlgoName]
        );

        // Add the preimage content type to the protected headers.
        protectedHeaders.Add(
            CoseHashEnvelopeHeaderLabels[CoseIndirectSignature.CoseHashEnvelopeHeaderLabels.PreimageContentType],
            CoseHeaderValue.FromString(ContentType)
        );

        // Add the payload location to the protected headers if it is not null.
        if (PayloadLocation != null)
        {
            protectedHeaders.Add(
                CoseHashEnvelopeHeaderLabels[CoseIndirectSignature.CoseHashEnvelopeHeaderLabels.PayloadLocation],
                CoseHeaderValue.FromString(PayloadLocation)
            );
        }

        // If the ContentType header is present, remove it.
        if (protectedHeaders.ContainsKey(CoseHeaderLabel.ContentType))
        {
            /*
               Label 3 (content_type) MUST NOT be present in the protected or
                  unprotected headers.

               Label 3 is easily confused with label TBD_2
               payload_preimage_content_type.  The difference between content_type
               (3) and payload_preimage_content_type (TBD2) is content_type is used
               to identify the content format associated with payload, whereas
               payload_preimage_content_type is used to identify the content format
               of the bytes which are hashed to produce the payload.
            */
            protectedHeaders.Remove(CoseHeaderLabel.ContentType);
        }

        return protectedHeaders;
    }

    /// <inheritdoc />
    public CoseHeaderMap ExtendUnProtectedHeaders(CoseHeaderMap? unProtectedHeaders)
    {
        if(unProtectedHeaders != null)
        {
            if(unProtectedHeaders.ContainsKey(CoseHeaderLabel.ContentType))
            {
                // If the ContentType header is present, remove it.
                /*
                   Label 3 (content_type) MUST NOT be present in the protected or
                      unprotected headers.
                */
                unProtectedHeaders.Remove(CoseHeaderLabel.ContentType);
            }
            return unProtectedHeaders;
        }
        return [];
    }
}
