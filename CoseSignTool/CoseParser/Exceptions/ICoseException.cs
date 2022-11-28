// ---------------------------------------------------------------------------
// <copyright file="CoseSigningException.cs" company="Microsoft">
//     Copyright (c) Microsoft Corporation. All rights reserved.
// </copyright>
// ---------------------------------------------------------------------------

namespace CoseX509
{
    using System.Security.Cryptography.X509Certificates;

    public interface ICoseException
    {
        /// <summary>
        /// The status of the X509 Certificate Chain associated with the signature.
        /// </summary>
        public X509ChainStatus[]? Status { get; }
    }
}
