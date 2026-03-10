// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.AzureKeyVault.Validation;

using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using Azure;
using Azure.Security.KeyVault.Keys;
using CoseSign1.AzureKeyVault.Common;
using CoseSign1.Abstractions;
using CoseSign1.Validation.Interfaces;

/// <summary>
/// Resolves signing key material by fetching the public key from Azure Key Vault using the message <c>kid</c> header.
/// </summary>
/// <remarks>
/// <para>
/// This resolver enables online verification for signatures that include a Key Vault key identifier (kid) but do not
/// embed a COSE_Key.
/// </para>
/// <para>
/// For offline verification, prefer <see cref="AzureKeyVaultCoseKeySigningKeyResolver"/>.
/// </para>
/// </remarks>
public sealed class AzureKeyVaultOnlineSigningKeyResolver : ISigningKeyResolver
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public static readonly string ResolverName = nameof(AzureKeyVaultOnlineSigningKeyResolver);

        internal const string KeysSegment = "keys";
        internal const string CurveP521 = "P-521";
        internal const string CurveP384 = "P-384";
        internal const string CurveP256 = "P-256";

        public const string ErrorCodeNullInput = "NULL_INPUT";
        public const string ErrorCodeMissingOrInvalidKid = "KID_INVALID";
        public const string ErrorCodeVaultMismatch = "VAULT_MISMATCH";
        public const string ErrorCodeKeyFetchFailed = "KEY_FETCH_FAILED";
        public const string ErrorCodeUnsupportedKeyType = "KEY_TYPE_UNSUPPORTED";

        public const string ErrorMessageNullInput = "Input message is null";
        public const string ErrorMessageMissingOrInvalidKid = "Message does not contain a valid Azure Key Vault key identifier (kid)";
        public const string ErrorMessageVaultMismatch = "Message kid does not match the configured Key Vault";
        public const string ErrorMessageKeyFetchFailed = "Failed to fetch public key from Azure Key Vault";
        public const string ErrorMessageUnsupportedKeyType = "Azure Key Vault key type is not supported for COSE verification";
    }

    private readonly IKeyVaultClientFactory ClientFactory;

    /// <summary>
    /// Initializes a new instance of the <see cref="AzureKeyVaultOnlineSigningKeyResolver"/> class.
    /// </summary>
    /// <param name="clientFactory">Client factory used to access Key Vault.</param>
    public AzureKeyVaultOnlineSigningKeyResolver(IKeyVaultClientFactory clientFactory)
    {
        Guard.ThrowIfNull(clientFactory);
        ClientFactory = clientFactory;
    }

    /// <inheritdoc/>
    public SigningKeyResolutionResult Resolve(CoseSign1Message message)
    {
        return ResolveAsync(message, CancellationToken.None).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public async Task<SigningKeyResolutionResult> ResolveAsync(
        CoseSign1Message message,
        CancellationToken cancellationToken = default)
    {
        if (message is null)
        {
            return SigningKeyResolutionResult.Failure(ClassStrings.ErrorMessageNullInput, ClassStrings.ErrorCodeNullInput);
        }

        if (!AkvKidUtilities.TryGetKid(message, out var kid) || string.IsNullOrWhiteSpace(kid) || !Uri.TryCreate(kid, UriKind.Absolute, out var kidUri))
        {
            return SigningKeyResolutionResult.Failure(ClassStrings.ErrorMessageMissingOrInvalidKid, ClassStrings.ErrorCodeMissingOrInvalidKid);
        }

        if (!TryParseAkvKeyId(kidUri, out var vaultUri, out var keyName, out var keyVersion))
        {
            return SigningKeyResolutionResult.Failure(ClassStrings.ErrorMessageMissingOrInvalidKid, ClassStrings.ErrorCodeMissingOrInvalidKid);
        }

        if (!UriEqualsIgnoringTrailingSlash(ClientFactory.VaultUri, vaultUri))
        {
            return SigningKeyResolutionResult.Failure(ClassStrings.ErrorMessageVaultMismatch, ClassStrings.ErrorCodeVaultMismatch);
        }

        KeyVaultKey key;
        try
        {
            Response<KeyVaultKey> response = await ClientFactory.KeyClient
                .GetKeyAsync(keyName, keyVersion, cancellationToken)
                .ConfigureAwait(false);

            key = response.Value;
        }
        catch
        {
            return SigningKeyResolutionResult.Failure(ClassStrings.ErrorMessageKeyFetchFailed, ClassStrings.ErrorCodeKeyFetchFailed);
        }

        try
        {
            var signingKey = CreateSigningKeyFromKeyVaultKey(key);
            return SigningKeyResolutionResult.Success(signingKey, keyId: kid);
        }
        catch (NotSupportedException)
        {
            return SigningKeyResolutionResult.Failure(ClassStrings.ErrorMessageUnsupportedKeyType, ClassStrings.ErrorCodeUnsupportedKeyType);
        }
    }

    private static bool TryParseAkvKeyId(Uri kidUri, out Uri vaultUri, out string keyName, out string? keyVersion)
    {
        vaultUri = default!;
        keyName = string.Empty;
        keyVersion = null;

        // Expect: https://{vault}.vault.azure.net/keys/{name}/{version?}
        if (!kidUri.Host.EndsWith(AkvKidUtilities.ClassStrings.KeyVaultHostSuffix, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var path = kidUri.AbsolutePath.Trim('/');
        var segments = path.Split(new[] { '/' }, StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length < 2)
        {
            return false;
        }

        if (!string.Equals(segments[0], ClassStrings.KeysSegment, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        keyName = segments[1];
        if (string.IsNullOrWhiteSpace(keyName))
        {
            return false;
        }

        keyVersion = segments.Length >= 3 ? segments[2] : null;
        vaultUri = new Uri(kidUri.GetLeftPart(UriPartial.Authority));
        return true;
    }

    private static bool UriEqualsIgnoringTrailingSlash(Uri left, Uri right)
    {
        // Normalize to ensure https://host and https://host/ compare equal
        string l = left.AbsoluteUri.TrimEnd('/');
        string r = right.AbsoluteUri.TrimEnd('/');
        return string.Equals(l, r, StringComparison.OrdinalIgnoreCase);
    }

    private static ISigningKey CreateSigningKeyFromKeyVaultKey(KeyVaultKey key)
    {
        Guard.ThrowIfNull(key);

        var keyType = key.KeyType;

        if (keyType == KeyType.Rsa || keyType == KeyType.RsaHsm)
        {
            var modulus = key.Key.N;
            var exponent = key.Key.E;
            Guard.ThrowIfNull(modulus);
            Guard.ThrowIfNull(exponent);

            int keySizeBits = modulus.Length * 8;
            HashAlgorithmName hashAlgorithm = keySizeBits >= 4096 ? HashAlgorithmName.SHA512
                : keySizeBits >= 3072 ? HashAlgorithmName.SHA384
                : HashAlgorithmName.SHA256;

            var rsa = RSA.Create();
            rsa.ImportParameters(new RSAParameters { Modulus = modulus, Exponent = exponent });
            return new PublicKeySigningKey(rsa, new CoseKey(rsa, RSASignaturePadding.Pss, hashAlgorithm));
        }

        if (keyType == KeyType.Ec || keyType == KeyType.EcHsm)
        {
            var curveName = key.Key.CurveName?.ToString();
            ECCurve curve = curveName switch
            {
                ClassStrings.CurveP521 => ECCurve.NamedCurves.nistP521,
                ClassStrings.CurveP384 => ECCurve.NamedCurves.nistP384,
                _ => ECCurve.NamedCurves.nistP256,
            };

            HashAlgorithmName hashAlgorithm = curveName switch
            {
                ClassStrings.CurveP521 => HashAlgorithmName.SHA512,
                ClassStrings.CurveP384 => HashAlgorithmName.SHA384,
                _ => HashAlgorithmName.SHA256,
            };

            var x = key.Key.X;
            var y = key.Key.Y;
            Guard.ThrowIfNull(x);
            Guard.ThrowIfNull(y);

            var ecdsa = ECDsa.Create(new ECParameters
            {
                Curve = curve,
                Q = new ECPoint { X = x, Y = y }
            });

            return new PublicKeySigningKey(ecdsa, new CoseKey(ecdsa, hashAlgorithm));
        }

        throw new NotSupportedException();
    }

    private sealed class PublicKeySigningKey : ISigningKey
    {
        private readonly AsymmetricAlgorithm Algorithm;
        private readonly CoseKey CoseKey;
        private bool Disposed;

        public PublicKeySigningKey(AsymmetricAlgorithm algorithm, CoseKey coseKey)
        {
            Algorithm = algorithm;
            CoseKey = coseKey;
        }

        public CoseKey GetCoseKey()
        {
            Guard.ThrowIfDisposed(Disposed, this);
            return CoseKey;
        }

        public void Dispose()
        {
            if (Disposed)
            {
                return;
            }

            Disposed = true;
            Algorithm.Dispose();
        }
    }
}
