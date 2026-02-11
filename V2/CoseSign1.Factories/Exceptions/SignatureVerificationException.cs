// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Factories.Exceptions;

using System;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

/// <summary>
/// Exception thrown when a signature created by a factory fails post-sign verification.
/// This indicates a critical failure - the signature produced cannot be verified.
/// </summary>
public class SignatureVerificationException : CryptographicException
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public static readonly string DefaultMessage = "The created signature failed verification.";
    }

    /// <summary>
    /// Gets the operation ID for correlation with logs.
    /// </summary>
    public string? OperationId { get; }

    /// <summary>
    /// Initializes a new instance of SignatureVerificationException.
    /// </summary>
    public SignatureVerificationException()
        : base(ClassStrings.DefaultMessage) { }

    /// <summary>
    /// Initializes a new instance with a message.
    /// </summary>
    /// <param name="message">The error message that explains the reason for the exception.</param>
    public SignatureVerificationException(string message)
        : base(message) { }

    /// <summary>
    /// Initializes a new instance with a message and operation ID.
    /// </summary>
    /// <param name="message">The error message that explains the reason for the exception.</param>
    /// <param name="operationId">The operation ID for correlation with logs.</param>
    public SignatureVerificationException(string message, string? operationId)
        : base(message)
    {
        this.OperationId = operationId;
    }

    /// <summary>
    /// Initializes a new instance with a message and inner exception.
    /// </summary>
    /// <param name="message">The error message that explains the reason for the exception.</param>
    /// <param name="innerException">The exception that is the cause of the current exception.</param>
    public SignatureVerificationException(string message, Exception innerException)
        : base(message, innerException) { }
}