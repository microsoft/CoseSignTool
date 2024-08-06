// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Ignore Spelling: Cose

namespace CoseIndirectSignature.Exceptions;

/// <summary>
/// Base exception class for the CoseIndirectSignature library.
/// </summary>
[Serializable]
[ExcludeFromCodeCoverage]
public class CoseIndirectSignatureException : CoseSign1Exception
{

    /// <summary>
    /// Default Constructor.
    /// </summary>
    public CoseIndirectSignatureException()
    {
    }

    /// <summary>
    /// Creates an instance of <see cref="CoseIndirectSignatureException"/> with a specified message.
    /// </summary>
    /// <param name="message">The message for the exception.</param>
    public CoseIndirectSignatureException(string message) : base(message)
    {
    }

    /// <summary>
    /// Creates an instance of <see cref="CoseIndirectSignatureException"/> with a specified message and inner exception.
    /// </summary>
    /// <param name="message">The message for the exception.</param>
    /// <param name="innerException">The inner exception for this exception.</param>
    public CoseIndirectSignatureException(string message, Exception innerException) : base(message, innerException)
    {
    }

    /// <summary>
    /// Creates an instance of <see cref="CoseIndirectSignatureException"/> with a specified message and inner context.
    /// </summary>
    /// <param name="info">The serialization info for this exception.</param>
    /// <param name="context">The streaming context for this exception.</param>
    protected CoseIndirectSignatureException(SerializationInfo info, StreamingContext context) : base(info, context)
    {
    }
}