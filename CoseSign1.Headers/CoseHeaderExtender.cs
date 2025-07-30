// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Headers;

/// <summary>
/// An implementation of the header extender.
/// </summary>
public class CoseHeaderExtender : ICoseHeaderExtender
{
    private readonly Func<CoseHeaderMap, CoseHeaderMap> ProtectedExtender;
    private readonly Func<CoseHeaderMap?, CoseHeaderMap> UnProtectedExtender;

    /// <summary>
    /// Creates a new instance of the <see cref="CoseHeaderExtender"/> class.
    /// </summary>
    /// <param name="protectedExtender">The function to extend protected headers.</param>
    /// <param name="unProtectedExtender">The function to extend unprotected headers.</param>
    public CoseHeaderExtender(Func<CoseHeaderMap, CoseHeaderMap> protectedExtender, Func<CoseHeaderMap?, CoseHeaderMap> unProtectedExtender)
    {
        this.ProtectedExtender = protectedExtender;
        this.UnProtectedExtender = unProtectedExtender;
    }

    /// <summary>
    /// Add protected headers supplied by the user to the supplied header map.
    /// </summary>
    /// <param name="protectedHeaders">The header map where user supplied protected header(s) will be added.</param>
    /// <returns>A header map with user supplied protected headers.</returns>
    public CoseHeaderMap ExtendProtectedHeaders(CoseHeaderMap protectedHeaders) => this.ProtectedExtender(protectedHeaders);

    /// <summary>
    /// Add unprotected headers supplied by the user to the supplied header map.
    /// </summary>
    /// <param name="unProtectedHeaders">The header map where user supplied unprotected header(s) will be added.</param>
    /// <returns>A header map with user supplied unprotected headers.</returns>
    public CoseHeaderMap ExtendUnProtectedHeaders(CoseHeaderMap? unProtectedHeaders) => this.UnProtectedExtender(unProtectedHeaders);
}
