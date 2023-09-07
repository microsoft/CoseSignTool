// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Exceptions;

/// <summary>
/// An exception class for validation failures related to COSE signing.
/// </summary>
[Serializable]
[ExcludeFromCodeCoverage]
public class CoseValidationException : CoseSign1CertificateException
{

    /// <summary>
    /// Initializes an instance of the <see cref="CoseValidationException"/> class.
    /// </summary>
    public CoseValidationException() : base("COSE signature validation failed.") { }

    /// <summary>
    /// Initializes an instance of the <see cref="CoseValidationException"/> class and specifies an error message.
    /// </summary>
    /// <param name="message">The error text.</param>
    public CoseValidationException(string message) : base(message) { }

    /// <summary>
    /// Initializes an instance of the <see cref="CoseValidationException"/> class, specifies an error message, and passes the inner exception.
    /// </summary>
    /// <param name="message">The error text.</param>
    /// <param name="innerException">The source exception.</param>
    public CoseValidationException(string message, Exception innerException) : base(message, innerException) { }

    /// <summary>
    /// Initializes an instance of the <see cref="CoseValidationException"/> class.
    /// </summary>
    /// <param name="message">The message the exception should contain.</param>
    /// <param name="certificate">The <see cref="X509Certificate2"/> which this exception is associated with.</param>
    public CoseValidationException(string message, X509Certificate2 certificate) : base(message, certificate)
    {
    }

    /// <summary>
    /// Initializes an instance of the <see cref="CoseValidationException"/> class.
    /// </summary>
    /// <param name="message">The message the exception should contain.</param>
    /// <param name="certificate">The <see cref="X509Certificate2"/> which this exception is associated with.</param>
    /// <param name="chainStatus">The <see cref="X509ChainStatus"/> of the result of building the trust chain for this certificate if present.</param>
    public CoseValidationException(string message, X509Certificate2 certificate, X509ChainStatus[] chainStatus) : base(message, certificate, chainStatus)
    {
    }

    /// <summary>
    /// Initializes an instance of the <see cref="CoseValidationException"/> class.
    /// </summary>
    /// <param name="message">The message the exception should contain.</param>
    /// <param name="innerException">The inner exception for this exception.</param>
    /// <param name="certificate">The <see cref="X509Certificate2"/> which this exception is associated with.</param>
    public CoseValidationException(string message, Exception innerException, X509Certificate2 certificate)
        : base(message, innerException, certificate)
    {
    }

    /// <summary>
    /// Initializes an instance of the <see cref="CoseValidationException"/> class.
    /// </summary>
    /// <param name="message">The message the exception should contain.</param>
    /// <param name="innerException">The inner exception for this exception.</param>
    /// <param name="certificate">The <see cref="X509Certificate2"/> which this exception is associated with.</param>
    /// <param name="chainStatus">The <see cref="X509ChainStatus"/> of the result of building the trust chain for this certificate if present.</param>
    public CoseValidationException(string message, Exception innerException, X509Certificate2 certificate, X509ChainStatus[] chainStatus)
        : base(message, innerException, certificate, chainStatus)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="CoseValidationException"/> class.
    /// </summary>
    /// <param name="info">
    /// The System.Runtime.Serialization.SerializationInfo that holds the serialized
    /// object data about the exception being thrown.</param>
    /// <param name="context">
    /// The System.Runtime.Serialization.StreamingContext that contains contextual information
    /// about the source or destination.
    /// </param>
    /// <exception cref="ArgumentNullException">info is null.</exception>
    /// <exception cref="SerializationException">The class name is null or <see cref="Exception.HResult"/> is zero (0).</exception>
    protected CoseValidationException(SerializationInfo info, StreamingContext context) : base(info, context)
    {
    }
}
