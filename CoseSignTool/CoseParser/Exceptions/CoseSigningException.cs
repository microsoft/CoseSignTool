// ---------------------------------------------------------------------------
// <copyright file="CoseSigningException.cs" company="Microsoft">
//     Copyright (c) Microsoft Corporation. All rights reserved.
// </copyright>
// ---------------------------------------------------------------------------

namespace CoseX509
{
    using System;
    using System.Runtime.Serialization;
    using System.Security.Cryptography.X509Certificates;

    /// <summary>
    /// An exception class for failures in COSE signing.
    /// </summary>
    [Serializable]
    public class CoseSigningException : Exception, ICoseException
    {
        ///<Inheritdoc />
        public X509ChainStatus[]? Status { get; }

        /// <summary>
        /// Initializes an instance of the <see cref="CoseSignSigningException"/> class.
        /// </summary>
        public CoseSigningException() : base("COSE signing failed.") { }

        /// <summary>
        /// Initializes an instance of the <see cref="CoseSignSigningException"/> class and specifies an error message.
        /// </summary>
        /// <param name="message">The error text.</param>
        public CoseSigningException(string message) : base(message) { }

        /// <summary>
        /// Initializes an instance of the <see cref="CoseSignSigningException"/> class, specifies an error message, and passes the inner exception.
        /// </summary>
        /// <param name="message">The error text.</param>
        /// <param name="innerException">The source exception.</param>
        public CoseSigningException(string message, Exception innerException) : base(message, innerException) { }

        /// <summary>
        /// Initializes an instance of the <see cref="CoseSignSigningException"/> class and passes in the chain status caused by a failed X509CertificateChain operation.
        /// </summary>
        /// <param name="message">The error text.</param>
        /// <param name="status">The ChainStatus of an X509CertificateChain.</param>
        public CoseSigningException(string message, X509ChainStatus[] status) : base(message)
        {
            Status = status;
        }

        /// <summary>
        /// Initializes an instance of the <see cref="CoseSignSigningException"/> class and serializes the data.
        /// </summary>
        /// <param name="info">The serialization info</param>
        /// <param name="context">The streaming context</param>
        protected CoseSigningException(SerializationInfo info, StreamingContext context) : base(info, context)
        {
            ArgumentNullException.ThrowIfNull(nameof(info));
            if (Status is not null)
            {
                info.AddValue(nameof(Status), Status.GetJoinedStatusString());
            }
            base.GetObjectData(info, context);
        }
    }
}
