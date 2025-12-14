// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Local;

/// <summary>
/// Common Enhanced Key Usage (EKU) OID constants.
/// </summary>
public static class EnhancedKeyUsageOids
{
    /// <summary>
    /// TLS Server Authentication (1.3.6.1.5.5.7.3.1)
    /// </summary>
    public const string ServerAuthentication = "1.3.6.1.5.5.7.3.1";

    /// <summary>
    /// TLS Client Authentication (1.3.6.1.5.5.7.3.2)
    /// </summary>
    public const string ClientAuthentication = "1.3.6.1.5.5.7.3.2";

    /// <summary>
    /// Code Signing (1.3.6.1.5.5.7.3.3)
    /// </summary>
    public const string CodeSigning = "1.3.6.1.5.5.7.3.3";

    /// <summary>
    /// Email Protection (1.3.6.1.5.5.7.3.4)
    /// </summary>
    public const string EmailProtection = "1.3.6.1.5.5.7.3.4";

    /// <summary>
    /// Time Stamping (1.3.6.1.5.5.7.3.8)
    /// </summary>
    public const string TimeStamping = "1.3.6.1.5.5.7.3.8";

    /// <summary>
    /// OCSP Signing (1.3.6.1.5.5.7.3.9)
    /// </summary>
    public const string OcspSigning = "1.3.6.1.5.5.7.3.9";

    /// <summary>
    /// Microsoft Lifetime Signing (1.3.6.1.4.1.311.10.3.13)
    /// Indicates signatures are valid beyond certificate expiration.
    /// </summary>
    public const string LifetimeSigning = "1.3.6.1.4.1.311.10.3.13";

    /// <summary>
    /// Document Signing (1.3.6.1.4.1.311.10.3.12)
    /// </summary>
    public const string DocumentSigning = "1.3.6.1.4.1.311.10.3.12";
}