// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Abstractions.Interfaces;

/// <summary>
/// Interface Exposing Methods to Add Custom Headers in the Protected and UnProtected Headers
/// </summary>
public interface ICoseHeaderExtender
{
    /// <summary>
    /// Adds Headers to the ProtectedHeaders
    /// </summary>
    /// <param name="protectedHeaders">The <see cref="CoseHeaderMap"/> to be extended.</param>
    /// <returns><see cref="CoseHeaderMap"/> which contains the input <paramref name="protectedHeaders"/> headers and any modifications.</returns>
    CoseHeaderMap ExtendProtectedHeaders(CoseHeaderMap protectedHeaders);

    /// <summary>
    /// Adds Headers to the UnProtectedHeaders
    /// </summary>
    /// <param name="unProtectedHeaders">The <see cref="CoseHeaderMap"/> to be extended.</param>
    /// <returns><see cref="CoseHeaderMap"/> which contains the input <paramref name="unProtectedHeaders"/> headers and any modifications.</returns>
    CoseHeaderMap ExtendUnProtectedHeaders(CoseHeaderMap? unProtectedHeaders);
}
