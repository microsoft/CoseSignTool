// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.AzureKeyVault.Validation;

using System.Formats.Cbor;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using CoseSign1.Abstractions;
using CoseSign1.Validation;
using CoseSign1.Validation.Interfaces;

/// <summary>
/// Resolves signing key material from a COSE_Key structure embedded in the COSE message headers.
/// </summary>
/// <remarks>
/// <para>
/// Azure Key Vault signing can optionally embed the public key as a COSE_Key using
/// <see cref="CoseKeyHeaderContributor"/>. This resolver enables fully offline verification by
/// reconstructing a <see cref="CoseKey"/> from that embedded COSE_Key.
/// </para>
/// <para>
/// This resolver does not perform any network calls.
/// </para>
/// </remarks>
public sealed class AzureKeyVaultCoseKeySigningKeyResolver : AkvValidationComponentBase, ISigningKeyResolver
{
    /// <inheritdoc/>
    public override string ComponentName => ClassStrings.ResolverName;

    [ExcludeFromCodeCoverage]
    internal static new class ClassStrings
    {
        public static readonly string ResolverName = nameof(AzureKeyVaultCoseKeySigningKeyResolver);

        public const string ErrorCodeNullInput = "NULL_INPUT";
        public const string ErrorCodeMissingCoseKey = "COSE_KEY_MISSING";
        public const string ErrorCodeInvalidCoseKey = "COSE_KEY_INVALID";
        public const string ErrorCodeUnsupportedCoseKey = "COSE_KEY_UNSUPPORTED";

        public const string ErrorMessageNullInput = "Input message is null";
        public const string ErrorMessageMissingCoseKey = "Message does not contain an embedded COSE_Key header";
        public const string ErrorMessageInvalidCoseKey = "Embedded COSE_Key header was not a valid COSE_Key structure";
        public const string ErrorMessageUnsupportedCoseKey = "Embedded COSE_Key uses an unsupported key type or algorithm";
    }

    /// <inheritdoc/>
    protected override bool ComputeApplicability(CoseSign1Message message, CoseSign1ValidationOptions? options = null)
    {
        if (message == null)
        {
            return false;
        }

        return message.ProtectedHeaders.ContainsKey(CoseKeyHeaderContributor.CoseKeyHeaderLabel)
            || message.UnprotectedHeaders.ContainsKey(CoseKeyHeaderContributor.CoseKeyHeaderLabel);
    }

    /// <inheritdoc/>
    public SigningKeyResolutionResult Resolve(CoseSign1Message message)
    {
        if (message is null)
        {
            return SigningKeyResolutionResult.Failure(ClassStrings.ErrorMessageNullInput, ClassStrings.ErrorCodeNullInput);
        }

        if (!TryGetCoseKeyEncodedValue(message, out var encodedCoseKey))
        {
            return SigningKeyResolutionResult.Failure(ClassStrings.ErrorMessageMissingCoseKey, ClassStrings.ErrorCodeMissingCoseKey);
        }

        try
        {
            if (!TryDecodeCoseKey(encodedCoseKey, out var signingKey, out var keyId))
            {
                return SigningKeyResolutionResult.Failure(ClassStrings.ErrorMessageInvalidCoseKey, ClassStrings.ErrorCodeInvalidCoseKey);
            }

            return SigningKeyResolutionResult.Success(signingKey, keyId: keyId);
        }
        catch (NotSupportedException)
        {
            return SigningKeyResolutionResult.Failure(ClassStrings.ErrorMessageUnsupportedCoseKey, ClassStrings.ErrorCodeUnsupportedCoseKey);
        }
        catch
        {
            return SigningKeyResolutionResult.Failure(ClassStrings.ErrorMessageInvalidCoseKey, ClassStrings.ErrorCodeInvalidCoseKey);
        }
    }

    /// <inheritdoc/>
    public Task<SigningKeyResolutionResult> ResolveAsync(
        CoseSign1Message message,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(Resolve(message));
    }

    private static bool TryGetCoseKeyEncodedValue(CoseSign1Message message, out ReadOnlyMemory<byte> encodedValue)
    {
        if (message.ProtectedHeaders.TryGetValue(CoseKeyHeaderContributor.CoseKeyHeaderLabel, out var protectedValue))
        {
            encodedValue = protectedValue.EncodedValue;
            return encodedValue.Length > 0;
        }

        if (message.UnprotectedHeaders.TryGetValue(CoseKeyHeaderContributor.CoseKeyHeaderLabel, out var unprotectedValue))
        {
            encodedValue = unprotectedValue.EncodedValue;
            return encodedValue.Length > 0;
        }

        encodedValue = default;
        return false;
    }

    private static bool TryDecodeCoseKey(ReadOnlyMemory<byte> encodedCoseKey, out ISigningKey signingKey, out string? keyId)
    {
        signingKey = null!;
        keyId = null;

        int? keyType = null;
        int? algorithm = null;
        int? curve = null;

        byte[]? rsaModulus = null;
        byte[]? rsaExponent = null;

        byte[]? ecX = null;
        byte[]? ecY = null;

        int? curveCandidate = null;
        byte[]? modulusCandidate = null;
        byte[]? minus2BytesCandidate = null;
        byte[]? minus3BytesCandidate = null;

        var reader = new CborReader(encodedCoseKey);
        int? mapLength = reader.ReadStartMap();

        for (int i = 0; mapLength == null || i < mapLength; i++)
        {
            if (reader.PeekState() == CborReaderState.EndMap)
            {
                break;
            }

            int label = reader.ReadInt32();
            switch (label)
            {
                case CoseKeyHeaderContributor.CoseKeyLabels.KeyType:
                    keyType = reader.ReadInt32();
                    break;

                case CoseKeyHeaderContributor.CoseKeyLabels.KeyId:
                    if (reader.PeekState() == CborReaderState.TextString)
                    {
                        keyId = reader.ReadTextString();
                    }
                    else if (reader.PeekState() == CborReaderState.ByteString)
                    {
                        keyId = System.Text.Encoding.UTF8.GetString(reader.ReadByteString());
                    }
                    else
                    {
                        reader.SkipValue();
                    }
                    break;

                case CoseKeyHeaderContributor.CoseKeyLabels.Algorithm:
                    algorithm = reader.ReadInt32();
                    break;

                case -1:
                    // -1 is used by both EC2(Crv) (int) and RSA(N) (bstr). Disambiguate by CBOR type.
                    if (reader.PeekState() == CborReaderState.UnsignedInteger
                        || reader.PeekState() == CborReaderState.NegativeInteger)
                    {
                        curveCandidate = reader.ReadInt32();
                    }
                    else if (reader.PeekState() == CborReaderState.ByteString)
                    {
                        modulusCandidate = reader.ReadByteString();
                    }
                    else
                    {
                        reader.SkipValue();
                    }

                    break;

                case -2:
                    // -2 is used by both EC2(X) and RSA(E). Disambiguate after we know kty.
                    if (reader.PeekState() == CborReaderState.ByteString)
                    {
                        minus2BytesCandidate = reader.ReadByteString();
                    }
                    else
                    {
                        reader.SkipValue();
                    }

                    break;

                case -3:
                    // EC2(Y)
                    if (reader.PeekState() == CborReaderState.ByteString)
                    {
                        minus3BytesCandidate = reader.ReadByteString();
                    }
                    else
                    {
                        reader.SkipValue();
                    }

                    break;

                default:
                    reader.SkipValue();
                    break;
            }
        }

        reader.ReadEndMap();

        if (keyType == null || algorithm == null)
        {
            return false;
        }

        if (keyType == CoseKeyHeaderContributor.CoseKeyTypes.RSA)
        {
            rsaModulus ??= modulusCandidate;
            rsaExponent ??= minus2BytesCandidate;
        }
        else if (keyType == CoseKeyHeaderContributor.CoseKeyTypes.EC2)
        {
            curve ??= curveCandidate;
            ecX ??= minus2BytesCandidate;
            ecY ??= minus3BytesCandidate;
        }

        if (keyType == CoseKeyHeaderContributor.CoseKeyTypes.RSA)
        {
            if (rsaModulus == null || rsaExponent == null)
            {
                return false;
            }

            var hashAlgorithm = MapCoseHashAlgorithm(algorithm.Value);

            var rsa = RSA.Create();
            rsa.ImportParameters(new RSAParameters { Modulus = rsaModulus, Exponent = rsaExponent });
            signingKey = new EmbeddedCoseKeySigningKey(rsa, new CoseKey(rsa, RSASignaturePadding.Pss, hashAlgorithm));
            return true;
        }

        if (keyType == CoseKeyHeaderContributor.CoseKeyTypes.EC2)
        {
            if (curve == null || ecX == null || ecY == null)
            {
                return false;
            }

            var hashAlgorithm = MapCoseHashAlgorithm(algorithm.Value);
            var ecCurve = MapCoseCurve(curve.Value);

            var ecdsa = ECDsa.Create(new ECParameters
            {
                Curve = ecCurve,
                Q = new ECPoint { X = ecX, Y = ecY }
            });

            signingKey = new EmbeddedCoseKeySigningKey(ecdsa, new CoseKey(ecdsa, hashAlgorithm));
            return true;
        }

        throw new NotSupportedException();
    }

    private static HashAlgorithmName MapCoseHashAlgorithm(int coseAlgorithm)
    {
        return coseAlgorithm switch
        {
            -37 => HashAlgorithmName.SHA256, // PS256
            -38 => HashAlgorithmName.SHA384, // PS384
            -39 => HashAlgorithmName.SHA512, // PS512
            -7 => HashAlgorithmName.SHA256,  // ES256
            -35 => HashAlgorithmName.SHA384, // ES384
            -36 => HashAlgorithmName.SHA512, // ES512
            _ => throw new NotSupportedException(),
        };
    }

    private static ECCurve MapCoseCurve(int coseCurve)
    {
        return coseCurve switch
        {
            CoseKeyHeaderContributor.CoseEllipticCurves.P256 => ECCurve.NamedCurves.nistP256,
            CoseKeyHeaderContributor.CoseEllipticCurves.P384 => ECCurve.NamedCurves.nistP384,
            CoseKeyHeaderContributor.CoseEllipticCurves.P521 => ECCurve.NamedCurves.nistP521,
            _ => throw new NotSupportedException(),
        };
    }

    private sealed class EmbeddedCoseKeySigningKey : ISigningKey
    {
        private readonly AsymmetricAlgorithm Algorithm;
        private readonly CoseKey CoseKey;
        private bool Disposed;

        public EmbeddedCoseKeySigningKey(AsymmetricAlgorithm algorithm, CoseKey coseKey)
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
