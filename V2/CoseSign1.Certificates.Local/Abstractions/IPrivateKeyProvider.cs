// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Local;

/// <summary>
/// Represents a generated cryptographic key with its signature generator.
/// Provides a uniform abstraction for RSA, ECDSA, and ML-DSA keys.
/// </summary>
/// <remarks>
/// <para>
/// This abstraction uses <see cref="X509SignatureGenerator"/> to provide consistent
/// behavior across all key types, including post-quantum algorithms like ML-DSA
/// that don't inherit from <see cref="AsymmetricAlgorithm"/>.
/// </para>
/// </remarks>
public interface IGeneratedKey : IDisposable
{
    /// <summary>
    /// Gets the key algorithm type.
    /// </summary>
    KeyAlgorithm Algorithm { get; }

    /// <summary>
    /// Gets the signature generator for creating certificate signatures.
    /// </summary>
    X509SignatureGenerator SignatureGenerator { get; }

    /// <summary>
    /// Creates a certificate request for this key.
    /// </summary>
    /// <param name="subjectName">The subject distinguished name.</param>
    /// <param name="hashAlgorithm">The hash algorithm for signing.</param>
    /// <returns>A configured certificate request.</returns>
    CertificateRequest CreateCertificateRequest(string subjectName, HashAlgorithmName hashAlgorithm);

    /// <summary>
    /// Copies the private key to a certificate that was created without one.
    /// </summary>
    /// <param name="certificate">The certificate to add the private key to.</param>
    /// <returns>A new certificate with the private key attached.</returns>
    X509Certificate2 CopyPrivateKeyTo(X509Certificate2 certificate);

    /// <summary>
    /// Gets the underlying ML-DSA key if this is an ML-DSA key.
    /// </summary>
    /// <returns>The <see cref="MLDsa"/> key if this is an ML-DSA key; otherwise, null.</returns>
    /// <remarks>
    /// This method is provided for scenarios that require direct access to the ML-DSA key,
    /// such as chain signing where the signature generator needs the issuer's private key.
    /// </remarks>
    MLDsa? GetMLDsa() => null;
}

/// <summary>
/// Provides cryptographic key generation functionality.
/// Implement this interface to customize key storage (TPM, HSM, Confidential Compute).
/// </summary>
/// <remarks>
/// <para>
/// The default implementation (<see cref="SoftwareKeyProvider"/>) generates keys in software memory.
/// For production scenarios requiring hardware-protected keys, implement this interface
/// to integrate with TPM, HSM, or cloud key management services.
/// </para>
/// <para>
/// Thread safety: Implementations should be thread-safe for concurrent key generation.
/// </para>
/// </remarks>
public interface IPrivateKeyProvider
{
    /// <summary>
    /// Gets a human-readable name for this key provider.
    /// Used in logging and diagnostics.
    /// </summary>
    string ProviderName { get; }

    /// <summary>
    /// Gets a value indicating whether the provider supports the specified algorithm.
    /// </summary>
    /// <param name="algorithm">The key algorithm to check.</param>
    /// <returns>True if the algorithm is supported; otherwise, false.</returns>
    bool SupportsAlgorithm(KeyAlgorithm algorithm);

    /// <summary>
    /// Generates a new cryptographic key.
    /// </summary>
    /// <param name="algorithm">The cryptographic algorithm to use.</param>
    /// <param name="keySize">
    /// Optional key size in bits. If null, uses algorithm defaults:
    /// RSA: 2048, ECDSA: 256, ML-DSA: 65 (parameter set).
    /// </param>
    /// <returns>
    /// The generated key wrapped in an <see cref="IGeneratedKey"/> abstraction.
    /// The caller is responsible for disposing the returned instance.
    /// </returns>
    /// <exception cref="NotSupportedException">
    /// Thrown when the requested algorithm is not supported by this provider.
    /// </exception>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown when the key size is invalid for the specified algorithm.
    /// </exception>
    IGeneratedKey GenerateKey(KeyAlgorithm algorithm, int? keySize = null);

    /// <summary>
    /// Asynchronously generates a new cryptographic key.
    /// Useful for providers that require remote calls (HSM, cloud KMS).
    /// </summary>
    /// <param name="algorithm">The cryptographic algorithm to use.</param>
    /// <param name="keySize">Optional key size in bits.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// A task representing the asynchronous operation.
    /// The task result is the generated key wrapped in an <see cref="IGeneratedKey"/> abstraction.
    /// </returns>
    Task<IGeneratedKey> GenerateKeyAsync(
        KeyAlgorithm algorithm,
        int? keySize = null,
        CancellationToken cancellationToken = default);
}