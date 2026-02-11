// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Factories.Exceptions;

using System.Diagnostics.CodeAnalysis;

/// <summary>
/// Exception thrown when post-sign signature verification fails.
/// This indicates the signature created by the signing service could not be verified,
/// which may indicate a key mismatch, corruption, or signing service error.
/// </summary>
public class SignatureVerificationException : Exception
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string DefaultMessage = "Post-sign signature verification failed. The signature could not be verified after creation.";
    }

    /// <summary>
    /// Creates a default SignatureVerificationException.
    /// </summary>
    public SignatureVerificationException() : base(ClassStrings.DefaultMessage)
    {
    }

    /// <summary>
    /// Creates a SignatureVerificationException with an error message.
    /// </summary>
    /// <param name="message">The error text.</param>
    public SignatureVerificationException(string message) : base(message)
    {
    }

    /// <summary>
    /// Creates a SignatureVerificationException with an error message and inner exception.
    /// </summary>
    /// <param name="message">The error text.</param>
    /// <param name="innerException">The source exception.</param>
    public SignatureVerificationException(string message, Exception innerException) : base(message, innerException)
    {
    }
}