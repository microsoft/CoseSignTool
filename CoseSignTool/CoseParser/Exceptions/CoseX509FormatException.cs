// ---------------------------------------------------------------------------
// <copyright file="CoseX509FormatException.cs" company="Microsoft">
//     Copyright (c) Microsoft Corporation. All rights reserved.
// </copyright>
// ---------------------------------------------------------------------------

namespace CoseX509
{
    using System;
    using System.Runtime.Serialization;

    /// <summary>
    /// An exception class for format errors related to X509 COSE signing.
    /// </summary>
    [Serializable]
    public class CoseX509FormatException : Exception
    {
        /// <summary>
        /// Creates a default CoseX509FormatException.
        /// </summary>
        public CoseX509FormatException() : base("Failed to meet COSE X509 format requirements.") { }

        /// <summary>
        /// Creates a CoseX509FormatException with an error message.
        /// </summary>
        /// <param name="message">The error text.</param>
        public CoseX509FormatException(string message) : base(message) { }

        /// <summary>
        /// Creates a CoseX509FormatException with an error message and passes the inner exception.
        /// </summary>
        /// <param name="message">The error text.</param>
        /// <param name="innerException">The source exception.</param>
        public CoseX509FormatException(string message, Exception innerException) : base(message, innerException) { }

        /// <summary>
        /// Creates a CoseX509FormatException, passing the serialization info and streaming context.
        /// </summary>
        /// <param name="info">The serialization info</param>
        /// <param name="context">The streaming context</param>
        protected CoseX509FormatException(SerializationInfo info, StreamingContext context) : base(info, context) { }
    }
}
