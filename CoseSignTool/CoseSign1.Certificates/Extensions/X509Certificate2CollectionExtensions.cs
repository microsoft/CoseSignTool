// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Extensions;

/// <summary>
/// Extension methods for the X509Certificate2Collection object.
/// </summary>
public static class X509Certificate2CollectionExtensions
{
    /// <summary>
    /// Gets the first element in the current <see cref="X509Certificate2Collection"/>.
    /// </summary>
    /// <param name="collection"></param>
    /// <returns>The first element in the collection if found; null otherwise.</returns>
    public static X509Certificate2? FirstOrDefault(this X509Certificate2Collection? collection) => collection?.Count > 0 ? collection[0] : null;
}
