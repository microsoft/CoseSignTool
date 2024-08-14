// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Headers.Interfaces;

/// <summary>
/// An interface to manage the protected and unprotected headers.
/// </summary>
public interface ICoseHeaderFactory
{
    /// <summary>
    /// Add protected headers to the supplied header map.
    /// </summary>
    /// <param name="protectedHeaders">A collection of protected headers.</param>
    void ExtendProtectedHeaders(CoseHeaderMap protectedHeaders);

    /// <summary>
    /// Add unprotected headers to the supplied header map.
    /// </summary>
    /// <param name="unProtectedHeaders">A collection of unprotected headers.</param>
    void ExtendUnProtectedHeaders(CoseHeaderMap unProtectedHeaders);

    /// <summary>
    /// Adds the supplied headers to an internal collection representing the protected headers.
    /// The headers in this collection will be signed and added to the Cose envelop.
    /// </summary>
    /// <typeparam name="TypeV">Data type of the header value</typeparam>
    /// <param name="headers">A collection of protected headers.</param>
    void AddProtectedHeaders<TypeV>(IEnumerable<CoseHeader<TypeV>> headers);

    /// <summary>
    /// Adds the supplied headers to and internal collection representing the unprotected headers.
    /// The headers in this collection will be added to the Cose envelop.
    /// </summary>
    /// <typeparam name="TypeV">Data type of the header value</typeparam>
    /// <param name="headers">A collection of unprotected headers</param>
    void AddUnProtectedHeaders<TypeV>(IEnumerable<CoseHeader<TypeV>> headers);
}
