// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography.X509Certificates;

namespace CoseSign1.Certificates.Local;

/// <summary>
/// Utility methods for working with ML-DSA (Post-Quantum) certificates.
/// </summary>
public static class MLDsaCertificateUtils
{
    [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string MLDsa44Oid = "2.16.840.1.101.3.4.3.17";
        public const string MLDsa65Oid = "2.16.840.1.101.3.4.3.18";
        public const string MLDsa87Oid = "2.16.840.1.101.3.4.3.19";
        public const string ErrorMldsaParameterSetRange = "ML-DSA parameter set must be 44, 65, or 87";
    }

    /// <summary>
    /// ML-DSA-44 algorithm OID.
    /// </summary>
    public const string MLDsa44Oid = ClassStrings.MLDsa44Oid;

    /// <summary>
    /// ML-DSA-65 algorithm OID.
    /// </summary>
    public const string MLDsa65Oid = ClassStrings.MLDsa65Oid;

    /// <summary>
    /// ML-DSA-87 algorithm OID.
    /// </summary>
    public const string MLDsa87Oid = ClassStrings.MLDsa87Oid;

    /// <summary>
    /// Determines if a certificate uses the ML-DSA algorithm.
    /// </summary>
    /// <param name="certificate">The certificate to check.</param>
    /// <returns>True if the certificate uses ML-DSA algorithm, false otherwise.</returns>
    public static bool IsMLDsaCertificate(X509Certificate2 certificate)
    {
        if (certificate == null)
        {
            return false;
        }

        string? oid = certificate.PublicKey.Oid?.Value;
        return oid is MLDsa44Oid or MLDsa65Oid or MLDsa87Oid;
    }

    /// <summary>
    /// Extracts the ML-DSA parameter set from an ML-DSA certificate.
    /// </summary>
    /// <param name="certificate">The ML-DSA certificate.</param>
    /// <returns>The parameter set (44, 65, or 87) or null if not an ML-DSA certificate.</returns>
    public static int? GetParameterSet(X509Certificate2 certificate)
    {
        if (certificate == null)
        {
            return null;
        }

        string? oid = certificate.PublicKey.Oid?.Value;
        return oid switch
        {
            MLDsa44Oid => 44,
            MLDsa65Oid => 65,
            MLDsa87Oid => 87,
            _ => null
        };
    }

    /// <summary>
    /// Gets the ML-DSA algorithm OID for a given parameter set.
    /// </summary>
    /// <param name="parameterSet">The parameter set (44, 65, or 87).</param>
    /// <returns>The algorithm OID.</returns>
    /// <exception cref="ArgumentOutOfRangeException">If parameter set is not 44, 65, or 87.</exception>
    public static string GetAlgorithmOid(int parameterSet)
    {
        return parameterSet switch
        {
            44 => MLDsa44Oid,
            65 => MLDsa65Oid,
            87 => MLDsa87Oid,
            _ => throw new ArgumentOutOfRangeException(nameof(parameterSet),
                ClassStrings.ErrorMldsaParameterSetRange)
        };
    }
}