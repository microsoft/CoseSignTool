// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Diagnostics.CodeAnalysis;
using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using System.Text;
using CoseSign1.AzureKeyVault;
using CoseSign1.Validation;

namespace CoseSignTool.AzureKeyVault.Plugin;

/// <summary>
/// Verifies a COSE_Sign1 signature using an embedded COSE_Key public key produced by the
/// Azure Key Vault key-only signing flow.
/// </summary>
public sealed class AzureKeyVaultSignatureValidator : IValidator<CoseSign1Message>, IConditionalValidator<CoseSign1Message>, ISignatureValidator
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public static readonly string ValidatorName = nameof(AzureKeyVaultSignatureValidator);

        public static readonly string ErrorCodeNullInput = "NULL_INPUT";
        public static readonly string ErrorMessageNullInput = "Input message is null";

        public static readonly string ErrorCodeMissingDetachedPayload = "MISSING_DETACHED_PAYLOAD";
        public static readonly string ErrorMessageMissingDetachedPayload = "Message has detached content but no payload was provided.";

        public static readonly string ErrorCodeMissingCoseKey = "MISSING_COSE_KEY";
        public static readonly string ErrorMessageMissingCoseKey = "Message does not contain an embedded COSE_Key public key.";

        public static readonly string ErrorCodeInvalidCoseKey = "INVALID_COSE_KEY";
        public static readonly string ErrorMessageInvalidCoseKey = "Embedded COSE_Key could not be parsed.";

        public static readonly string ErrorCodeSignatureInvalid = "SIGNATURE_INVALID";
        public static readonly string ErrorMessageSignatureInvalid = "Signature verification failed.";
    }

    private readonly ReadOnlyMemory<byte>? DetachedPayload;

    public AzureKeyVaultSignatureValidator(ReadOnlyMemory<byte>? detachedPayload)
    {
        DetachedPayload = detachedPayload;
    }

    public bool IsApplicable(CoseSign1Message input)
    {
        if (input is null)
        {
            return false;
        }

        // Require embedded COSE_Key header.
        return input.ProtectedHeaders.ContainsKey(CoseKeyHeaderContributor.CoseKeyHeaderLabel)
            || input.UnprotectedHeaders.ContainsKey(CoseKeyHeaderContributor.CoseKeyHeaderLabel);
    }

    public ValidationResult Validate(CoseSign1Message input)
    {
        if (input is null)
        {
            return ValidationResult.Failure(ClassStrings.ValidatorName, ClassStrings.ErrorMessageNullInput, ClassStrings.ErrorCodeNullInput);
        }

        bool isEmbedded = input.Content != null;
        if (!isEmbedded && DetachedPayload is null)
        {
            return ValidationResult.Failure(
                ClassStrings.ValidatorName,
                ClassStrings.ErrorMessageMissingDetachedPayload,
                ClassStrings.ErrorCodeMissingDetachedPayload);
        }

        if (!TryGetEmbeddedCoseKeyBytes(input, out var coseKeyBytes))
        {
            return ValidationResult.Failure(
                ClassStrings.ValidatorName,
                ClassStrings.ErrorMessageMissingCoseKey,
                ClassStrings.ErrorCodeMissingCoseKey);
        }

        if (!TryCreatePublicKey(coseKeyBytes, out var rsa, out var ecdsa))
        {
            return ValidationResult.Failure(
                ClassStrings.ValidatorName,
                ClassStrings.ErrorMessageInvalidCoseKey,
                ClassStrings.ErrorCodeInvalidCoseKey);
        }

        try
        {
            bool verified;
            if (rsa != null)
            {
                verified = isEmbedded
                    ? input.VerifyEmbedded(rsa)
                    : input.VerifyDetached(rsa, DetachedPayload!.Value.Span);
            }
            else
            {
                verified = isEmbedded
                    ? input.VerifyEmbedded(ecdsa!)
                    : input.VerifyDetached(ecdsa!, DetachedPayload!.Value.Span);
            }

            if (!verified)
            {
                return ValidationResult.Failure(
                    ClassStrings.ValidatorName,
                    ClassStrings.ErrorMessageSignatureInvalid,
                    ClassStrings.ErrorCodeSignatureInvalid);
            }

            var metadata = new Dictionary<string, object>();

            if (TryGetKid(input, out var kidString))
            {
                metadata["kid"] = kidString;
                metadata["kidLooksLikeAkv"] = LooksLikeAzureKeyVaultKeyId(kidString);
            }

            metadata["KeyType"] = rsa != null ? "RSA" : "EC";
            return ValidationResult.Success(ClassStrings.ValidatorName, metadata);
        }
        catch (CryptographicException ex)
        {
            return ValidationResult.Failure(
                ClassStrings.ValidatorName,
                new ValidationFailure
                {
                    ErrorCode = ClassStrings.ErrorCodeSignatureInvalid,
                    Message = ex.Message,
                    Exception = ex
                });
        }
        finally
        {
            rsa?.Dispose();
            ecdsa?.Dispose();
        }
    }

    public Task<ValidationResult> ValidateAsync(CoseSign1Message input, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(Validate(input));
    }

    private static bool TryGetKid(CoseSign1Message input, out string kidString)
    {
        kidString = string.Empty;

        if (!input.ProtectedHeaders.TryGetValue(CoseHeaderLabel.KeyIdentifier, out var kidValue) &&
            !input.UnprotectedHeaders.TryGetValue(CoseHeaderLabel.KeyIdentifier, out kidValue))
        {
            return false;
        }

        try
        {
            var bytes = kidValue.GetValueAsBytes().ToArray();
            kidString = Encoding.UTF8.GetString(bytes);
            return !string.IsNullOrWhiteSpace(kidString);
        }
        catch
        {
            kidString = string.Empty;
            return false;
        }
    }

    private static bool LooksLikeAzureKeyVaultKeyId(string kid)
    {
        if (!Uri.TryCreate(kid, UriKind.Absolute, out var uri))
        {
            return false;
        }

        // Minimal heuristic: https://{vault}.vault.azure.net/keys/{name}/{version}
        if (!uri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (uri.Host == null || !uri.Host.EndsWith(".vault.azure.net", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return uri.AbsolutePath.Contains("/keys/", StringComparison.OrdinalIgnoreCase);
    }

    private static bool TryGetEmbeddedCoseKeyBytes(CoseSign1Message input, out ReadOnlyMemory<byte> encodedCoseKey)
    {
        if (input.ProtectedHeaders.TryGetValue(CoseKeyHeaderContributor.CoseKeyHeaderLabel, out var v) ||
            input.UnprotectedHeaders.TryGetValue(CoseKeyHeaderContributor.CoseKeyHeaderLabel, out v))
        {
            encodedCoseKey = v.EncodedValue;
            return true;
        }

        encodedCoseKey = default;
        return false;
    }

    private static bool TryCreatePublicKey(ReadOnlyMemory<byte> encodedCoseKey, out RSA? rsa, out ECDsa? ecdsa)
    {
        rsa = null;
        ecdsa = null;

        try
        {
            var reader = new CborReader(encodedCoseKey);

            int? mapLen = reader.ReadStartMap();
            int? kty = null;
            int? crv = null;
            byte[]? x = null;
            byte[]? y = null;
            byte[]? n = null;
            byte[]? e = null;

            // Note: COSE_Key labels overlap across key types:
            // -1 is 'crv' for EC2 but 'n' for RSA; -2 is 'x' for EC2 but 'e' for RSA.
            byte[]? bytesLabelMinus1 = null;
            byte[]? bytesLabelMinus2 = null;

            for (int i = 0; mapLen == null || i < mapLen; i++)
            {
                if (reader.PeekState() == CborReaderState.EndMap)
                {
                    break;
                }

                int label = reader.ReadInt32();
                switch (label)
                {
                    case CoseKeyHeaderContributor.CoseKeyLabels.KeyType:
                        kty = reader.ReadInt32();
                        break;
                    case -1:
                        {
                            var state = reader.PeekState();
                            if (state == CborReaderState.UnsignedInteger || state == CborReaderState.NegativeInteger)
                            {
                                crv = reader.ReadInt32();
                            }
                            else if (state == CborReaderState.ByteString)
                            {
                                bytesLabelMinus1 = reader.ReadByteString();
                            }
                            else
                            {
                                reader.SkipValue();
                            }

                            break;
                        }
                    case -2:
                        {
                            var state = reader.PeekState();
                            if (state == CborReaderState.ByteString)
                            {
                                bytesLabelMinus2 = reader.ReadByteString();
                            }
                            else
                            {
                                reader.SkipValue();
                            }

                            break;
                        }
                    case CoseKeyHeaderContributor.EC2Labels.Y:
                        y = reader.ReadByteString();
                        break;
                    default:
                        reader.SkipValue();
                        break;
                }
            }

            reader.ReadEndMap();

            if (kty == CoseKeyHeaderContributor.CoseKeyTypes.RSA)
            {
                n ??= bytesLabelMinus1;
                e ??= bytesLabelMinus2;
            }
            else if (kty == CoseKeyHeaderContributor.CoseKeyTypes.EC2)
            {
                x ??= bytesLabelMinus2;
            }

            if (kty == CoseKeyHeaderContributor.CoseKeyTypes.RSA)
            {
                if (n == null || e == null)
                {
                    return false;
                }

                rsa = RSA.Create();
                rsa.ImportParameters(new RSAParameters { Modulus = n, Exponent = e });
                return true;
            }

            if (kty == CoseKeyHeaderContributor.CoseKeyTypes.EC2)
            {
                if (crv == null || x == null || y == null)
                {
                    return false;
                }

                var curve = crv.Value switch
                {
                    CoseKeyHeaderContributor.CoseEllipticCurves.P256 => ECCurve.NamedCurves.nistP256,
                    CoseKeyHeaderContributor.CoseEllipticCurves.P384 => ECCurve.NamedCurves.nistP384,
                    CoseKeyHeaderContributor.CoseEllipticCurves.P521 => ECCurve.NamedCurves.nistP521,
                    _ => default
                };

                if (curve.Oid.Value == null)
                {
                    return false;
                }

                ecdsa = ECDsa.Create(new ECParameters
                {
                    Curve = curve,
                    Q = new ECPoint { X = x, Y = y }
                });

                return true;
            }

            return false;
        }
        catch
        {
            rsa?.Dispose();
            ecdsa?.Dispose();
            rsa = null;
            ecdsa = null;
            return false;
        }
    }
}
