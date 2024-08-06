// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Ignore Spelling: Cose

namespace CoseIndirectSignature.Exceptions;

/// <summary>
/// Exception thrown when the COSE data is invalid with Cose Indirect Signature library.
/// </summary>
[Serializable]
[ExcludeFromCodeCoverage]
public sealed class InvalidCoseDataException : CoseIndirectSignatureException
{
    /// <summary>
    /// The default constructor.
    /// </summary>
    public InvalidCoseDataException()
    {
    }

    /// <summary>
    /// Creates an instance of <see cref="InvalidCoseDataException"/> with a specified message.
    /// </summary>
    /// <param name="message">The message for the exception.</param>
    public InvalidCoseDataException(string message) : base(message)
    {
    }

    /// <summary>
    /// Creates an instance of <see cref="InvalidCoseDataException"/> with a specified message and inner exception.
    /// </summary>
    /// <param name="message">The message for the exception.</param>
    /// <param name="innerException">The inner exception for this exception.</param>
    public InvalidCoseDataException(string message, Exception innerException) : base(message, innerException)
    {
    }
}