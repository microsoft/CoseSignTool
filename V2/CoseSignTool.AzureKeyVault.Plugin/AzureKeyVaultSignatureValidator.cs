// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Diagnostics.CodeAnalysis;
using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using System.Text;
using Azure.Core;
using Azure.Identity;
using Azure.Security.KeyVault.Keys;
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

        public static readonly string ErrorCodeAkvKeyExpected = "AKV_KEY_EXPECTED";
        public static readonly string ErrorMessageAkvKeyExpected = "An Azure Key Vault key-only signature was expected, but required headers are missing.";

        public static readonly string ErrorCodeKidMismatch = "KID_MISMATCH";
        public static readonly string ErrorMessageKidMismatch = "The kid in the COSE_Sign1 header does not match the kid in the embedded COSE_Key; online verification is required.";

        public static readonly string ErrorCodeOnlineVerifyNotAllowed = "ONLINE_VERIFY_NOT_ALLOWED";
        public static readonly string ErrorMessageOnlineVerifyNotAllowed = "Online verification is required but was not enabled. Re-run with --allow-online-verify to permit network access.";

        public static readonly string ErrorCodeOnlineVerifyFailed = "ONLINE_VERIFY_FAILED";
        public static readonly string ErrorMessageOnlineVerifyFailed = "Online verification failed.";

        public static readonly string ErrorCodeMissingKid = "MISSING_KID";
        public static readonly string ErrorMessageMissingKid = "Message does not contain a kid header required for online verification.";

        public static readonly string ErrorCodeInvalidCoseKey = "INVALID_COSE_KEY";
        public static readonly string ErrorMessageInvalidCoseKey = "Embedded COSE_Key could not be parsed.";

        public static readonly string ErrorCodeSignatureInvalid = "SIGNATURE_INVALID";
        public static readonly string ErrorMessageSignatureInvalid = "Signature verification failed.";
    }

    private readonly ReadOnlyMemory<byte>? DetachedPayload;
    private readonly bool RequireAzureKey;
    private readonly bool AllowOnlineVerify;

    private readonly TokenCredential? Credential;
    private readonly Func<Uri, TokenCredential, KeyClient>? KeyClientFactory;

    public AzureKeyVaultSignatureValidator(
        ReadOnlyMemory<byte>? detachedPayload,
        bool requireAzureKey = false,
        bool allowOnlineVerify = false)
    {
        DetachedPayload = detachedPayload;
        RequireAzureKey = requireAzureKey;
        AllowOnlineVerify = allowOnlineVerify;
    }

    internal AzureKeyVaultSignatureValidator(
        ReadOnlyMemory<byte>? detachedPayload,
        bool requireAzureKey,
        bool allowOnlineVerify,
        TokenCredential credential,
        Func<Uri, TokenCredential, KeyClient> keyClientFactory)
        : this(detachedPayload, requireAzureKey, allowOnlineVerify)
    {
        Credential = credential ?? throw new ArgumentNullException(nameof(credential));
        KeyClientFactory = keyClientFactory ?? throw new ArgumentNullException(nameof(keyClientFactory));
    }

    public bool IsApplicable(CoseSign1Message input)
    {
        if (input is null)
        {
            return false;
        }

        if (RequireAzureKey)
        {
            // When the caller expects an AKV key-only signature, the validator must run even
            // when the message is missing headers so we can report a failure.
            return true;
        }

        // Require embedded COSE_Key header.
        return input.ProtectedHeaders.ContainsKey(CoseKeyHeaderContributor.CoseKeyHeaderLabel)
            || input.UnprotectedHeaders.ContainsKey(CoseKeyHeaderContributor.CoseKeyHeaderLabel);
    }

    public ValidationResult Validate(CoseSign1Message input)
    {
        // Keep synchronous path (used by some callers) working; online verification will
        // execute synchronously when enabled.
        return ValidateAsync(input, CancellationToken.None).GetAwaiter().GetResult();
    }

    public Task<ValidationResult> ValidateAsync(CoseSign1Message input, CancellationToken cancellationToken = default)
    {
        return ValidateCoreAsync(input, cancellationToken);
    }

    private async Task<ValidationResult> ValidateCoreAsync(CoseSign1Message input, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

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

        var metadata = new Dictionary<string, object>();
        _ = TryGetKid(input, out var messageKid);
        if (!string.IsNullOrWhiteSpace(messageKid))
        {
            metadata["kid"] = messageKid;
            metadata["kidLooksLikeAkv"] = LooksLikeAzureKeyVaultKeyId(messageKid);
        }

        if (RequireAzureKey)
        {
            // In the key-only flow we expect at least a kid that points at Key Vault.
            if (string.IsNullOrWhiteSpace(messageKid) || !LooksLikeAzureKeyVaultKeyId(messageKid))
            {
                return ValidationResult.Failure(
                    ClassStrings.ValidatorName,
                    ClassStrings.ErrorMessageAkvKeyExpected,
                    ClassStrings.ErrorCodeAkvKeyExpected);
            }
        }

        bool hasEmbeddedCoseKey = TryGetEmbeddedCoseKeyBytes(input, out var coseKeyBytes);

        // If we have an embedded COSE_Key, enforce kid match when the COSE_Key includes a kid.
        string coseKeyKid = string.Empty;
        bool hasCoseKeyKid = false;
        if (hasEmbeddedCoseKey)
        {
            hasCoseKeyKid = TryGetCoseKeyKid(coseKeyBytes, out coseKeyKid);
            if (hasCoseKeyKid)
            {
                metadata["coseKeyKid"] = coseKeyKid;
                if (string.IsNullOrWhiteSpace(messageKid) || !StringEqualsOrdinal(messageKid, coseKeyKid))
                {
                    metadata["requiresOnlineVerification"] = true;

                    if (!AllowOnlineVerify)
                    {
                        return ValidationResult.Failure(
                            ClassStrings.ValidatorName,
                            ClassStrings.ErrorMessageOnlineVerifyNotAllowed,
                            ClassStrings.ErrorCodeOnlineVerifyNotAllowed);
                    }

                    // Fall back to online verification to ensure the kid corresponds to the public key.
                    var online = await VerifyOnlineAsync(input, isEmbedded, messageKid, coseKeyKid, cancellationToken).ConfigureAwait(false);
                    if (!online.IsValid)
                    {
                        return online;
                    }

                    foreach (var kvp in online.Metadata)
                    {
                        metadata[kvp.Key] = kvp.Value;
                    }

                    return ValidationResult.Success(ClassStrings.ValidatorName, metadata);
                }
            }
        }

        // If there's no embedded COSE_Key, treat it as a failure unless online verify is enabled.
        if (!hasEmbeddedCoseKey)
        {
            if (AllowOnlineVerify)
            {
                var online = await VerifyOnlineAsync(input, isEmbedded, messageKid, coseKeyKid: string.Empty, cancellationToken).ConfigureAwait(false);
                if (!online.IsValid)
                {
                    return online;
                }

                foreach (var kvp in online.Metadata)
                {
                    metadata[kvp.Key] = kvp.Value;
                }

                return ValidationResult.Success(ClassStrings.ValidatorName, metadata);
            }

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
                metadata["KeyType"] = "RSA";
            }
            else
            {
                verified = isEmbedded
                    ? input.VerifyEmbedded(ecdsa!)
                    : input.VerifyDetached(ecdsa!, DetachedPayload!.Value.Span);
                metadata["KeyType"] = "EC";
            }

            if (!verified)
            {
                return ValidationResult.Failure(
                    ClassStrings.ValidatorName,
                    ClassStrings.ErrorMessageSignatureInvalid,
                    ClassStrings.ErrorCodeSignatureInvalid);
            }

            metadata["verificationMode"] = "offline";
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

    private async Task<ValidationResult> VerifyOnlineAsync(
        CoseSign1Message input,
        bool isEmbedded,
        string messageKid,
        string coseKeyKid,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        // Prefer the COSE_Sign1 kid header; fall back to COSE_Key kid if needed.
        var kidToUse = !string.IsNullOrWhiteSpace(messageKid) ? messageKid : coseKeyKid;
        if (string.IsNullOrWhiteSpace(kidToUse))
        {
            return ValidationResult.Failure(
                ClassStrings.ValidatorName,
                ClassStrings.ErrorMessageMissingKid,
                ClassStrings.ErrorCodeMissingKid);
        }

        if (!LooksLikeAzureKeyVaultKeyId(kidToUse) || !TryParseKeyVaultKeyId(kidToUse, out var vaultUri, out var keyName, out var keyVersion))
        {
            return ValidationResult.Failure(
                ClassStrings.ValidatorName,
                $"{ClassStrings.ErrorMessageOnlineVerifyFailed} kid is not a valid Azure Key Vault key id.",
                ClassStrings.ErrorCodeOnlineVerifyFailed);
        }

        try
        {
            var credential = Credential ?? new DefaultAzureCredential(new DefaultAzureCredentialOptions
            {
                ExcludeInteractiveBrowserCredential = true
            });

            var keyClient = KeyClientFactory != null
                ? KeyClientFactory(vaultUri, credential)
                : new KeyClient(vaultUri, credential);

            var response = await keyClient.GetKeyAsync(keyName, keyVersion, cancellationToken).ConfigureAwait(false);
            var key = response.Value;

            if (!TryCreatePublicKeyFromKeyVaultKey(key, out var rsa, out var ecdsa))
            {
                return ValidationResult.Failure(
                    ClassStrings.ValidatorName,
                    $"{ClassStrings.ErrorMessageOnlineVerifyFailed} Unsupported key type.",
                    ClassStrings.ErrorCodeOnlineVerifyFailed);
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

                return ValidationResult.Success(ClassStrings.ValidatorName, new Dictionary<string, object>
                {
                    ["verificationMode"] = "online",
                    ["onlineKid"] = kidToUse
                });
            }
            finally
            {
                rsa?.Dispose();
                ecdsa?.Dispose();
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return ValidationResult.Failure(
                ClassStrings.ValidatorName,
                new ValidationFailure
                {
                    ErrorCode = ClassStrings.ErrorCodeOnlineVerifyFailed,
                    Message = ex.Message,
                    Exception = ex
                });
        }
    }

    private static bool TryGetCoseKeyKid(ReadOnlyMemory<byte> encodedCoseKey, out string kidString)
    {
        kidString = string.Empty;

        try
        {
            var reader = new CborReader(encodedCoseKey);
            bool found = false;
            _ = reader.ReadStartMap();

            while (reader.PeekState() != CborReaderState.EndMap)
            {
                int label = reader.ReadInt32();
                if (label == CoseKeyHeaderContributor.CoseKeyLabels.KeyId)
                {
                    var bytes = reader.ReadByteString();
                    kidString = Encoding.UTF8.GetString(bytes);
                    found = !string.IsNullOrWhiteSpace(kidString);
                }
                else
                {
                    reader.SkipValue();
                }
            }

            reader.ReadEndMap();
            return found;
        }
        catch
        {
            kidString = string.Empty;
            return false;
        }
    }

    private static bool TryParseKeyVaultKeyId(string kid, out Uri vaultUri, out string keyName, out string? keyVersion)
    {
        vaultUri = null!;
        keyName = string.Empty;
        keyVersion = null;

        if (!Uri.TryCreate(kid, UriKind.Absolute, out var uri))
        {
            return false;
        }

        // https://{vault}.vault.azure.net/keys/{name}/{version}
        var segments = uri.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length < 3)
        {
            return false;
        }

        if (!segments[0].Equals("keys", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        keyName = segments[1];
        keyVersion = segments[2];

        if (string.IsNullOrWhiteSpace(keyName) || string.IsNullOrWhiteSpace(keyVersion))
        {
            return false;
        }

        vaultUri = new Uri(uri.GetLeftPart(UriPartial.Authority));
        return true;
    }

    private static bool TryCreatePublicKeyFromKeyVaultKey(KeyVaultKey key, out RSA? rsa, out ECDsa? ecdsa)
    {
        rsa = null;
        ecdsa = null;

        try
        {
            var jwk = key.Key;
            if (jwk == null)
            {
                return false;
            }

            if (key.KeyType == KeyType.Rsa || key.KeyType == KeyType.RsaHsm)
            {
                if (jwk.N == null || jwk.E == null)
                {
                    return false;
                }

                rsa = RSA.Create();
                rsa.ImportParameters(new RSAParameters
                {
                    Modulus = jwk.N,
                    Exponent = jwk.E
                });
                return true;
            }

            if (key.KeyType == KeyType.Ec || key.KeyType == KeyType.EcHsm)
            {
                if (jwk.X == null || jwk.Y == null)
                {
                    return false;
                }

                var curveName = jwk.CurveName?.ToString();
                var curve = curveName switch
                {
                    "P-256" => ECCurve.NamedCurves.nistP256,
                    "P-384" => ECCurve.NamedCurves.nistP384,
                    "P-521" => ECCurve.NamedCurves.nistP521,
                    _ => default
                };

                if (curve.Oid.Value == null)
                {
                    return false;
                }

                ecdsa = ECDsa.Create(new ECParameters
                {
                    Curve = curve,
                    Q = new ECPoint { X = jwk.X, Y = jwk.Y }
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

    private static bool StringEqualsOrdinal(string a, string b) => string.Equals(a, b, StringComparison.Ordinal);

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
