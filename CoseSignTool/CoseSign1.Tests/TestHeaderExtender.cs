// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Tests;

/// <summary>
/// Custom Class Created to Implement ICoseHeaderExtender interface for Tests purpose
/// </summary>
internal class TestHeaderExtender : ICoseHeaderExtender
{
    public TestHeaderExtender()
    { }

    /// <summary>
    /// Implementing ExtendProtectedHeaders of <see cref="ICoseHeaderExtender"/> for tests purpose
    /// Adds custom headers to the supplied ProtectedHeaders CoseHeaderMap
    /// </summary>
    /// <param name="protectedHeaders">protectedHeaders from Signing Key Providers</param>
    /// <returns>CoseHeaderMap with extended protectedHeaders</returns>
    public CoseHeaderMap ExtendProtectedHeaders(CoseHeaderMap? protectedHeaders)
    {
        protectedHeaders ??= new CoseHeaderMap();

        CoseHeaderLabel testHeaderLabel = new("test-header-label");
        protectedHeaders.Add(testHeaderLabel, "test-header-value");


        return protectedHeaders;
    }

    /// <summary>
    ///  Implementing ExtendUnProtectedHeaders of <see cref="ICoseHeaderExtender"/> for tests purpose
    ///  Adds custom headers to the supplied UnProtectedHeaders CoseHeaderMap
    /// </summary>
    /// <param name="unProtectedHeaders">unProtectedHeaders from Signing Key Providers</param>
    /// <returns>CoseHeaderMap with extended unprotectedHeaders</returns>
    public CoseHeaderMap ExtendUnProtectedHeaders(CoseHeaderMap? unProtectedHeaders)
    {
        unProtectedHeaders ??= new CoseHeaderMap();

        CoseHeaderLabel testHeaderLabel = new("test-header-label1");
        unProtectedHeaders.Add(testHeaderLabel, "test-header-value1");

        return unProtectedHeaders;
    }
}