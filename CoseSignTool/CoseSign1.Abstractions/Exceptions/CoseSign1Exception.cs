// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Abstractions.Exceptions;

/// <summary>
/// Generic base exception type for all exceptions thrown in CoseSign1 libraries.
/// </summary>
[ExcludeFromCodeCoverage]
public class CoseSign1Exception : Exception
{
    /// <summary>
    /// Default constructor
    /// </summary>
    public CoseSign1Exception() : base()
    {
    }

    /// <summary>
    /// Creates a new <see cref="CoseSign1Exception"/> with a specified message.
    /// </summary>
    /// <param name="message">The message the exception should contain.</param>
    public CoseSign1Exception(string message) : base(message)
    {
    }

    /// <summary>
    /// Creates a new <see cref="CoseSign1Exception"/> with a specified message and inner exception.
    /// </summary>
    /// <param name="message">The message the exception should contain.</param>
    /// <param name="innerException">The inner exception this exception should contain.</param>
    public CoseSign1Exception(string message, Exception innerException) : base(message, innerException)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="CoseSign1Exception"/> class with serialized data.
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
    protected CoseSign1Exception(SerializationInfo info, StreamingContext context) : base(info, context)
    {
    }
}
