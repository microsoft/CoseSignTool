// ---------------------------------------------------------------------------
// <copyright file="CoseSign1CertificateException.cs" company="Microsoft">
//     Copyright (c) Microsoft Corporation. All rights reserved.
// </copyright>
// ---------------------------------------------------------------------------

namespace CoseSign1.Certificates.Exceptions;

/// <summary>
/// Base class for any certificate exception.
/// </summary>
[ExcludeFromCodeCoverage]
public class CoseSign1CertificateException : CoseSign1Exception
{
    /// <summary>
    /// The certificate involved with the exception if any.
    /// </summary>
    public X509Certificate2? Certificate { get; }

    /// <summary>
    /// The chain status of any certificate exception if present.
    /// </summary>
    public X509ChainStatus[]? Status { get; }

    /// <summary>
    /// Default constructor
    /// </summary>
    public CoseSign1CertificateException() : base("There was a problem with one or more certificates.")
    {
    }

    /// <summary>
    /// Creates a new <see cref="CoseSign1CertificateException"/> with a specified message.
    /// </summary>
    /// <param name="message">The message the exception should contain.</param>
    public CoseSign1CertificateException(string message) : base(message)
    {
    }

    /// <summary>
    /// Creates a new <see cref="CoseSign1CertificateException"/> with a specified message and inner exception.
    /// </summary>
    /// <param name="message">The message the exception should contain.</param>
    /// <param name="innerException">The inner exception this exception should contain.</param>
    public CoseSign1CertificateException(string message, Exception innerException) : base(message, innerException)
    {
    }

    /// <summary>
    /// Creates a new <see cref="CoseSign1CertificateException"/> with a specified message and inner exception.
    /// </summary>
    /// <param name="message">The message the exception should contain.</param>
    /// <param name="certificate">The <see cref="X509Certificate2"/> which this exception is associated with.</param>
    /// <param name="chainStatus">The <see cref="X509ChainStatus"/> of the result of building the trust chain for this certificate if present.</param>
    public CoseSign1CertificateException(
        string message,
        X509Certificate2 certificate,
        X509ChainStatus[] chainStatus) : this(message, certificate)
    {
        Status = chainStatus;
    }

    /// <summary>
    /// Creates a new <see cref="CoseSign1CertificateException"/> with a specified message and inner exception.
    /// </summary>
    /// <param name="message">The message the exception should contain.</param>
    /// <param name="certificate">The <see cref="X509Certificate2"/> which this exception is associated with.</param>
    public CoseSign1CertificateException(
        string message,
        X509Certificate2 certificate) : this(message)
    {
        Certificate = certificate;
    }

    /// <summary>
    /// Creates a new <see cref="CoseSign1CertificateException"/> with a specified message and inner exception.
    /// </summary>
    /// <param name="message">The message the exception should contain.</param>
    /// <param name="innerException">The inner exception for this exception.</param>
    /// <param name="certificate">The <see cref="X509Certificate2"/> which this exception is associated with.</param>
    /// <param name="chainStatus">The <see cref="X509ChainStatus"/> of the result of building the trust chain for this certificate if present.</param>
    public CoseSign1CertificateException(
        string message,
        Exception innerException,
        X509Certificate2 certificate,
        X509ChainStatus[] chainStatus) : this(message, innerException, certificate)
    {
        Status = chainStatus;
    }

    /// <summary>
    /// Creates a new <see cref="CoseSign1CertificateException"/> with a specified message and inner exception.
    /// </summary>
    /// <param name="message">The message the exception should contain.</param>
    /// <param name="innerException">The inner exception for this exception.</param>
    /// <param name="certificate">The <see cref="X509Certificate2"/> which this exception is associated with.</param>
    public CoseSign1CertificateException(
        string message,
        Exception innerException,
        X509Certificate2 certificate) : this(message, innerException)
    {
        Certificate = certificate;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="CoseSign1CertificateException"/> class with serialized data.
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
    protected CoseSign1CertificateException(SerializationInfo info, StreamingContext context) : base(info, context)
    {
        if(info == null)
        {
            throw new ArgumentNullException(nameof(info));
        }
        if (Status is not null)
        {
            info.AddValue(nameof(Status), string.Join("\r\n", Status.Select(s => $"{s.Status}: {s.StatusInformation}")));
        }
        base.GetObjectData(info, context);
    }
}
