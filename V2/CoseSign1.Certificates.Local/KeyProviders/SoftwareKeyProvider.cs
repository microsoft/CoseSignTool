// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

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
    /// <inheritdoc />
    public string ProviderName => "Software";

    /// <inheritdoc />
    public bool SupportsAlgorithm(KeyAlgorithm algorithm)
    {
        return algorithm switch
        {
            KeyAlgorithm.RSA => true,
            KeyAlgorithm.ECDSA => true,
            KeyAlgorithm.MLDSA => true,
            _ => false
        };
    }

    /// <inheritdoc />
    public IGeneratedKey GenerateKey(KeyAlgorithm algorithm, int? keySize = null)
    {
        return algorithm switch
        {
            KeyAlgorithm.RSA => new RsaGeneratedKey(GenerateRsaKey(keySize ?? 2048)),
            KeyAlgorithm.ECDSA => new EcdsaGeneratedKey(GenerateEcdsaKey(keySize ?? 256)),
            KeyAlgorithm.MLDSA => new MldsaGeneratedKey(GenerateMldsaKey(keySize ?? 65)),
            _ => throw new NotSupportedException($"Algorithm {algorithm} is not supported by {ProviderName} provider")
        };
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
            throw new ArgumentOutOfRangeException(nameof(keySize),
                "RSA key size must be between 1024 and 16384 bits");
        }

        var rsa = RSA.Create();
        rsa.KeySize = keySize;
        return rsa;
    }

    private static ECDsa GenerateEcdsaKey(int keySize)
    {
        var curve = keySize switch
        {
            256 => ECCurve.NamedCurves.nistP256,
            384 => ECCurve.NamedCurves.nistP384,
            521 => ECCurve.NamedCurves.nistP521,
            _ => throw new ArgumentOutOfRangeException(nameof(keySize),
                "ECDSA key size must be 256, 384, or 521 bits")
        };

        return ECDsa.Create(curve);
    }

    private static MLDsa GenerateMldsaKey(int parameterSet)
    {
        var algorithm = parameterSet switch
        {
            44 => MLDsaAlgorithm.MLDsa44,
            65 => MLDsaAlgorithm.MLDsa65,
            87 => MLDsaAlgorithm.MLDsa87,
            _ => throw new ArgumentOutOfRangeException(nameof(parameterSet),
                "ML-DSA parameter set must be 44, 65, or 87")
        };

        return MLDsa.GenerateKey(algorithm);
    }
}