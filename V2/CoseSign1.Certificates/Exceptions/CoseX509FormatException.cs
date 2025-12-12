// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Exceptions;

/// <summary>
/// Exception thrown when COSE X509 format requirements are not met.
/// </summary>
public class CoseX509FormatException : Exception
{
    /// <summary>
    /// Creates a default CoseX509FormatException.
    /// </summary>
    public CoseX509FormatException() : base("Failed to meet COSE X509 format requirements.")
    {
    }

    /// <summary>
    /// Creates a CoseX509FormatException with an error message.
    /// </summary>
    /// <param name="message">The error text.</param>
    public CoseX509FormatException(string message) : base(message)
    {
    }

    /// <summary>
    /// Creates a CoseX509FormatException with an error message and inner exception.
    /// </summary>
    /// <param name="message">The error text.</param>
    /// <param name="innerException">The source exception.</param>
    public CoseX509FormatException(string message, Exception innerException) : base(message, innerException)
    {
    }
}