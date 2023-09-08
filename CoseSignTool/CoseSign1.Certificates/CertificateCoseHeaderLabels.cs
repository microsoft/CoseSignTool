// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates;

/// <summary>
/// <see cref="CoseHeaderLabel"/> objects which are specific to certificate signed <see cref="CoseSign1Message"/> objects.
/// </summary>
internal class CertificateCoseHeaderLabels
{
    // Taken from https://www.iana.org/assignments/cose/cose.xhtml
    /// <summary>
    /// Represents an unordered list of certificates.
    /// </summary>
    internal static readonly CoseHeaderLabel X5Bag = new(32);
    /// <summary>
    /// Represents an ordered list (leaf first) of the certificate chain for the certificate used to sign the <see cref="CoseSign1Message"/> object.
    /// </summary>
    internal static readonly CoseHeaderLabel X5Chain = new(33);
    /// <summary>
    /// Represents the thumbprint for the certificate used to sign the <see cref="CoseSign1Message"/> object.
    /// </summary>
    internal static readonly CoseHeaderLabel X5T = new(34);
}
