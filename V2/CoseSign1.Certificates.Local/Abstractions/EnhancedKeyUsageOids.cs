// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Local;

/// <summary>
/// Common Enhanced Key Usage (EKU) OID constants.
/// </summary>
public static class EnhancedKeyUsageOids
{
    [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string ServerAuthentication = "1.3.6.1.5.5.7.3.1";
        public const string ClientAuthentication = "1.3.6.1.5.5.7.3.2";
        public const string CodeSigning = "1.3.6.1.5.5.7.3.3";
        public const string EmailProtection = "1.3.6.1.5.5.7.3.4";
        public const string TimeStamping = "1.3.6.1.5.5.7.3.8";
        public const string OcspSigning = "1.3.6.1.5.5.7.3.9";
        public const string LifetimeSigning = "1.3.6.1.4.1.311.10.3.13";
        public const string DocumentSigning = "1.3.6.1.4.1.311.10.3.12";
    }

    /// <summary>
    /// TLS Server Authentication (1.3.6.1.5.5.7.3.1)
    /// </summary>
    public const string ServerAuthentication = ClassStrings.ServerAuthentication;

    /// <summary>
    /// TLS Client Authentication (1.3.6.1.5.5.7.3.2)
    /// </summary>
    public const string ClientAuthentication = ClassStrings.ClientAuthentication;

    /// <summary>
    /// Code Signing (1.3.6.1.5.5.7.3.3)
    /// </summary>
    public const string CodeSigning = ClassStrings.CodeSigning;

    /// <summary>
    /// Email Protection (1.3.6.1.5.5.7.3.4)
    /// </summary>
    public const string EmailProtection = ClassStrings.EmailProtection;

    /// <summary>
    /// Time Stamping (1.3.6.1.5.5.7.3.8)
    /// </summary>
    public const string TimeStamping = ClassStrings.TimeStamping;

    /// <summary>
    /// OCSP Signing (1.3.6.1.5.5.7.3.9)
    /// </summary>
    public const string OcspSigning = ClassStrings.OcspSigning;

    /// <summary>
    /// Microsoft Lifetime Signing (1.3.6.1.4.1.311.10.3.13)
    /// Indicates signatures are valid beyond certificate expiration.
    /// </summary>
    public const string LifetimeSigning = ClassStrings.LifetimeSigning;

    /// <summary>
    /// Document Signing (1.3.6.1.4.1.311.10.3.12)
    /// </summary>
    public const string DocumentSigning = ClassStrings.DocumentSigning;
}