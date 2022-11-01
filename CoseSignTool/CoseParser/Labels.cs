// ----------------------------------------------------------------------------------------
// <copyright file="Labels.cs" company="Microsoft">
//      Copyright (c) Microsoft Corporation. All rights reserved.
// </copyright>
// ----------------------------------------------------------------------------------------

namespace CoseX509
{
    using System.Security.Cryptography.Cose;

    /// <summary>
    /// Cose header label values.
    /// </summary>
    internal class Labels
    {
        // Taken from https://www.iana.org/assignments/cose/cose.xhtml
        internal static readonly CoseHeaderLabel labelx5bag = new(32);
        internal static readonly CoseHeaderLabel labelx5chain = new(33);
        internal static readonly CoseHeaderLabel labelx5t = new(34);
    }
}
