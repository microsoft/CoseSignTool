// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Diagnostics.CodeAnalysis;

namespace CoseSign1.Certificates.Local;

/// <summary>
/// Default software-based private key provider.
/// Generates keys in memory using .NET's built-in cryptographic primitives.
/// </summary>
/// <remarks>
/// <para>
/// This provider creates keys entirely in software memory. Keys are not persisted
/// and are disposed with the certificate. Suitable for:
/// </para>
/// <list type="bullet">
/// <item>Testing and development environments</item>
/// <item>Ephemeral signing operations</item>
/// <item>Scenarios where hardware key protection is not required</item>
/// </list>
/// <para>
/// For production scenarios requiring hardware-protected keys, implement
/// <see cref="IPrivateKeyProvider"/> to integrate with TPM, HSM, or cloud KMS.
/// </para>
/// </remarks>
public class SoftwareKeyProvider : IPrivateKeyProvider
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        // Provider name
        public static readonly string ProviderNameValue = "Software";

        // Error messages
        public static readonly string ErrorFormatAlgorithmNotSupported = "Algorithm {0} is not supported by {1} provider";
        public static readonly string ErrorRsaKeySizeRange = "RSA key size must be between 1024 and 16384 bits";
        public static readonly string ErrorEcdsaKeySizeRange = "ECDSA key size must be 256, 384, or 521 bits";
        public static readonly string ErrorMldsaParameterSetRange = "ML-DSA parameter set must be 44, 65, or 87";
    }

    /// <inheritdoc />
    public string ProviderName => ClassStrings.ProviderNameValue;

    /// <inheritdoc />
    public bool SupportsAlgorithm(KeyAlgorithm algorithm)
    {
        return algorithm == KeyAlgorithm.RSA
            || algorithm == KeyAlgorithm.ECDSA
            || algorithm == KeyAlgorithm.MLDSA;
    }

    /// <inheritdoc />
    public IGeneratedKey GenerateKey(KeyAlgorithm algorithm, int? keySize = null)
    {
        if (algorithm == KeyAlgorithm.RSA)
        {
            return new RsaGeneratedKey(GenerateRsaKey(keySize ?? 2048));
        }
        else if (algorithm == KeyAlgorithm.ECDSA)
        {
            return new EcdsaGeneratedKey(GenerateEcdsaKey(keySize ?? 256));
        }
        else if (algorithm == KeyAlgorithm.MLDSA)
        {
            return new MldsaGeneratedKey(GenerateMldsaKey(keySize ?? 65));
        }
        else
        {
            throw new NotSupportedException(string.Format(ClassStrings.ErrorFormatAlgorithmNotSupported, algorithm, ProviderName));
        }
    }

    /// <inheritdoc />
    public Task<IGeneratedKey> GenerateKeyAsync(
        KeyAlgorithm algorithm,
        int? keySize = null,
        CancellationToken cancellationToken = default)
    {
        // Software key generation is synchronous, but we wrap it for the async interface
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(GenerateKey(algorithm, keySize));
    }

    private static RSA GenerateRsaKey(int keySize)
    {
        if (keySize < 1024 || keySize > 16384)
        {
            throw new ArgumentOutOfRangeException(nameof(keySize), ClassStrings.ErrorRsaKeySizeRange);
        }

        var rsa = RSA.Create();
        rsa.KeySize = keySize;
        return rsa;
    }

    private static ECDsa GenerateEcdsaKey(int keySize)
    {
        ECCurve curve;
        if (keySize == 256)
        {
            curve = ECCurve.NamedCurves.nistP256;
        }
        else if (keySize == 384)
        {
            curve = ECCurve.NamedCurves.nistP384;
        }
        else if (keySize == 521)
        {
            curve = ECCurve.NamedCurves.nistP521;
        }
        else
        {
            throw new ArgumentOutOfRangeException(nameof(keySize), ClassStrings.ErrorEcdsaKeySizeRange);
        }

        return ECDsa.Create(curve);
    }

    private static MLDsa GenerateMldsaKey(int parameterSet)
    {
        MLDsaAlgorithm algorithm;
        if (parameterSet == 44)
        {
            algorithm = MLDsaAlgorithm.MLDsa44;
        }
        else if (parameterSet == 65)
        {
            algorithm = MLDsaAlgorithm.MLDsa65;
        }
        else if (parameterSet == 87)
        {
            algorithm = MLDsaAlgorithm.MLDsa87;
        }
        else
        {
            throw new ArgumentOutOfRangeException(nameof(parameterSet), ClassStrings.ErrorMldsaParameterSetRange);
        }

        return MLDsa.GenerateKey(algorithm);
    }
}