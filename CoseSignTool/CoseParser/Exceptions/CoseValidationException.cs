// ---------------------------------------------------------------------------
// <copyright file="CoseValidationException.cs" company="Microsoft">
//     Copyright (c) Microsoft Corporation. All rights reserved.
// </copyright>
// ---------------------------------------------------------------------------

namespace CoseX509
{
    using System;
    using System.Runtime.Serialization;

    /// <summary>
    /// An exception class for validation failures related to COSE signing.
    /// </summary>
    [Serializable]
    public class CoseValidationException : Exception
    {
        /// <summary>
        /// Creates a default CoseSignValidationException.
        /// </summary>
        public CoseValidationException() : base("COSE signature validation failed.") { }

        /// <summary>
        /// Creates a CoseSignValidationException with an error message.
        /// </summary>
        /// <param name="message">The error text.</param>
        public CoseValidationException(string message) : base(message) { }

        /// <summary>
        /// Creates a CoseSignValidationException with an error message and passes the inner exception.
        /// </summary>
        /// <param name="message">The error text.</param>
        /// <param name="innerException">The source exception.</param>
        public CoseValidationException(string message, Exception innerException) : base(message, innerException) { }

        /// <summary>
        /// Creates a CoseSignValidationException, passing the serialization info and streaming context.
        /// </summary>
        /// <param name="info">The serialization info</param>
        /// <param name="context">The streaming context</param>
        protected CoseValidationException(SerializationInfo info, StreamingContext context) : base(info, context) { }
    }
}
