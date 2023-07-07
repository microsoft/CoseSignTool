// ---------------------------------------------------------------------------
// <copyright file="ValidationFailureCode.cs" company="Microsoft">
//     Copyright (c) Microsoft Corporation. All rights reserved.
// </copyright>
// ---------------------------------------------------------------------------

namespace CoseX509;

/// <summary>
/// A set of error codes for known COSE signature validation failure types.
/// </summary>
public enum ValidationFailureCode
{
    /// <summary>
    /// An unknown failure occurred.
    /// </summary>
    Unknown = 0,

    /// <summary>
    /// The signing certificate did not have an RSA or ECDSA private key.
    /// </summary>
    NoPrivateKey,

    /// <summary>
    /// The signing certificate did not have an RSA or ECDSA public key.
    /// </summary>
    NoPublicKey,

    /// <summary>
    /// The signing certificate could not be parsed.
    /// </summary>
    SigningCertificateUnreadable,

    /// <summary>
    /// The certificates could not be read from the header.
    /// </summary>
    CertificateChainUnreadable,

    /// <summary>
    /// The certificate chain failed to build.
    /// </summary>
    CertificateChainInvalid,

    /// <summary>
    /// The supplied or embedded payload does not match the hash of the original payload.
    /// </summary>
    PayloadMismatch,

    /// <summary>
    /// The supplied or embedded payload could not be read.
    /// </summary>
    PayloadUnreadable,

    /// <summary>
    /// Required payload was not supplied for detached signature.
    /// </summary>
    PayloadMissing,

    /// <summary>
    /// Detached payload was supplied for an embedded signature.
    /// </summary>
    RedundantPayload,

    /// <summary>
    /// The COSE headers of the signature structure could not be resolved.
    /// </summary>
    CoseHeadersInvalid,
}