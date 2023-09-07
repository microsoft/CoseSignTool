// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseX509;

/// <summary>
/// Holds information about an error in COSE validation.
/// </summary>
public struct CoseValidationError
{
    /// <summary>
    /// Creates a new CoseValidationError instance.
    /// </summary>
    /// <param name="errorCode">A ValidationFailureCode value that represents the error type.</param>
    /// <param name="message">A text description of the error.</param>
    public CoseValidationError(ValidationFailureCode errorCode)
    {
        ErrorCode = errorCode;
        Message = ErrorMessages[errorCode];
    }

    /// <summary>
    /// Gets or sets a ValidationFailureCode value that represents the error type.
    /// </summary>
    public ValidationFailureCode ErrorCode { get; }

    /// <summary>
    /// Gets or sets a text description of the error.
    /// </summary>
    public string Message { get; }

    /// <summary>
    /// A dictionary that maps error messages to error codes.
    /// </summary>
    public static readonly Dictionary<ValidationFailureCode, string> ErrorMessages = new()
    {
        { ValidationFailureCode.SigningCertificateUnreadable, "The signing certificate was unreadable."},
        { ValidationFailureCode.NoPrivateKey, "The signing certificate does not have a valid RSA or ECDSA private key." },
        { ValidationFailureCode.NoPublicKey, "No public key could be found for the signing certificate."},
        { ValidationFailureCode.CertificateChainUnreadable, "One or more certificates in the certificate chain could not be read."},
        { ValidationFailureCode.CertificateChainInvalid, "Certificate chain validation failed." },
        { ValidationFailureCode.PayloadMismatch, "The supplied or embedded payload does not match the hash of the payload that was signed." },
        { ValidationFailureCode.PayloadMissing, "The detached signature could not be validated because the original payload was nut supplied."},
        { ValidationFailureCode.PayloadUnreadable, "The payload content could not be read."},
        { ValidationFailureCode.RedundantPayload, "The embedded signature was not validated because external payload was also specified."},
        { ValidationFailureCode.CoseHeadersInvalid, "The COSE headers in the signature could not be read." },
    };
}
