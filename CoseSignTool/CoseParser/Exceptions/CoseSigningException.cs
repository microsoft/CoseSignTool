// ---------------------------------------------------------------------------
// <copyright file="CoseSigningException.cs" company="Microsoft">
//     Copyright (c) Microsoft Corporation. All rights reserved.
// </copyright>
// ---------------------------------------------------------------------------

namespace CoseX509
{
    using System;
    using System.Runtime.Serialization;

    /// <summary>
    /// An exception class for failures in COSE signing.
    /// </summary>
    [Serializable]
    public class CoseSigningException : Exception
    {
        /// <summary>
        /// Creates a default CoseSignSigningException.
        /// </summary>
        public CoseSigningException() : base("COSE signing failed.") { }

        /// <summary>
        /// Creates a CoseSignSigningException with an error message.
        /// </summary>
        /// <param name="message">The error text.</param>
        public CoseSigningException(string message) : base(message) { }

        /// <summary>
        /// Creates a CoseSignSigningException with an error message and passes the inner exception.
        /// </summary>
        /// <param name="message">The error text.</param>
        /// <param name="innerException">The source exception.</param>
        public CoseSigningException(string message, Exception innerException) : base(message, innerException) { }

        /// <summary>
        /// Creates a CoseSignSigningException, passing the serialization info and streaming context.
        /// </summary>
        /// <param name="info">The serialization info</param>
        /// <param name="context">The streaming context</param>
        protected CoseSigningException(SerializationInfo info, StreamingContext context) : base(info, context) { }
    }
}
