// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Abstractions.Exceptions;

/// <summary>
/// An exception class for failures in COSE signing.
/// </summary>
[Serializable]
public class CoseSigningException : CoseSign1Exception
{
    /// <summary>
    /// Initializes an instance of the <see cref="CoseSigningException"/> class.
    /// </summary>
    public CoseSigningException() : base("CoseSign1 signing failed.") { }

    /// <summary>
    /// Initializes an instance of the <see cref="CoseSigningException"/> class and specifies an error message.
    /// </summary>
    /// <param name="message">The error text.</param>
    public CoseSigningException(string message) : base(message) { }

    /// <summary>
    /// Initializes an instance of the <see cref="CoseSigningException"/> class, specifies an error message, and passes the inner exception.
    /// </summary>
    /// <param name="message">The error text.</param>
    /// <param name="innerException">The source exception.</param>
    public CoseSigningException(string message, Exception innerException) : base(message, innerException) { }

    /// <summary>
    /// Initializes a new instance of the <see cref="CoseSigningException"/> class with serialized data.
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
    protected CoseSigningException(SerializationInfo info, StreamingContext context) : base(info, context)
    {
    }
}
