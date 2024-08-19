// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Headers;

/// <summary>
/// An implementation of the header extender.
/// </summary>
public class CoseHeaderExtender : ICoseHeaderExtender
{
    /// <summary>
    /// Add protected headers supplied by the user to the supplied header map.
    /// </summary>
    /// <param name="protectedHeaders">The header map where user supplied protected header(s) will be added.</param>
    /// <returns>A header map with user supplied protected headers.</returns>
    public CoseHeaderMap ExtendProtectedHeaders(CoseHeaderMap protectedHeaders)
    {
        CoseHeaderFactory.Instance().ExtendProtectedHeaders(protectedHeaders);
        return protectedHeaders;
    }

    /// <summary>
    /// Add unprotected headers supplied by the user to the supplied header map.
    /// </summary>
    /// <param name="unProtectedHeaders">The header map where user supplied unprotected header(s) will be added.</param>
    /// <returns>A header map with user supplied unprotected headers.</returns>
    public CoseHeaderMap ExtendUnProtectedHeaders(CoseHeaderMap? unProtectedHeaders)
    {
        CoseHeaderFactory.Instance().ExtendUnProtectedHeaders(unProtectedHeaders);
        return unProtectedHeaders;
    }
}
