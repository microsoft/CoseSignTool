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
using CoseSign1.Validation.Interfaces;
using CoseSign1.Validation.Results;

namespace CoseSign1.AzureKeyVault.Validation;

/// <summary>
/// Verifies a COSE_Sign1 signature using an embedded COSE_Key public key produced by the
/// Azure Key Vault key-only signing flow.
/// </summary>
public sealed class AzureKeyVaultSignatureValidator : IConditionalValidator
{
    private static readonly IReadOnlyCollection<ValidationStage> StagesField = new[] { ValidationStage.Signature };

    /// <inheritdoc/>
    public IReadOnlyCollection<ValidationStage> Stages => StagesField;

    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public static readonly string ValidatorName = nameof(AzureKeyVaultSignatureValidator);

        public const string ErrorFormatUnsupportedValidationStage = "Unsupported validation stage: {0}";

        public const string MetadataKeyKid = "kid";
        public const string MetadataKeyKidLooksLikeAkv = "kidLooksLikeAkv";
        public const string MetadataKeyCoseKeyKid = "coseKeyKid";
        public const string MetadataKeyRequiresOnlineVerification = "requiresOnlineVerification";
        public const string MetadataKeyKeyType = "KeyType";
        public const string MetadataKeyVerificationMode = "verificationMode";
        public const string MetadataKeyOnlineKid = "onlineKid";

        public const string KeyTypeRsa = "RSA";
        public const string KeyTypeEc = "EC";

        public const string VerificationModeOnline = "online";
        public const string VerificationModeOffline = "offline";

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

        public static readonly string ErrorMessageOnlineVerifyFailedInvalidKid = "Online verification failed. kid is not a valid Azure Key Vault key id.";
        public static readonly string ErrorMessageOnlineVerifyFailedUnsupportedKeyType = "Online verification failed. Unsupported key type.";

        public static readonly string ErrorCodeMissingKid = "MISSING_KID";
        public static readonly string ErrorMessageMissingKid = "Message does not contain a kid header required for online verification.";

        public static readonly string ErrorCodeInvalidCoseKey = "INVALID_COSE_KEY";
        public static readonly string ErrorMessageInvalidCoseKey = "Embedded COSE_Key could not be parsed.";

        public static readonly string ErrorCodeSignatureInvalid = "SIGNATURE_INVALID";
        public static readonly string ErrorMessageSignatureInvalid = "Signature verification failed.";

        public const string KeyVaultPathSegmentKeys = "keys";
        public const string KeyVaultUriSchemeHttps = "https";
        public const string KeyVaultHostSuffix = ".vault.azure.net";
        public const string KeyVaultKeysPathFragment = "/keys/";

        public const string CurveNameP256 = "P-256";
        public const string CurveNameP384 = "P-384";
        public const string CurveNameP521 = "P-521";
    }

    private readonly ReadOnlyMemory<byte>? DetachedPayload;
    private readonly bool RequireAzureKey;
    private readonly bool AllowOnlineVerify;

    private readonly TokenCredential? Credential;
    private readonly Func<Uri, TokenCredential, KeyClient>? KeyClientFactory;

    /// <summary>
    /// Initializes a new instance of the <see cref="AzureKeyVaultSignatureValidator"/> class.
    /// </summary>
    /// <param name="detachedPayload">The detached payload, if verifying a detached signature.</param>
    /// <param name="requireAzureKey">Whether to require the signature to be an AKV key-only signature.</param>
    /// <param name="allowOnlineVerify">Whether to allow network calls to Key Vault when needed to verify.</param>
    public AzureKeyVaultSignatureValidator(
        ReadOnlyMemory<byte>? detachedPayload,
        bool requireAzureKey = false,
        bool allowOnlineVerify = false)
    {
        DetachedPayload = detachedPayload;
        RequireAzureKey = requireAzureKey;
        AllowOnlineVerify = allowOnlineVerify;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="AzureKeyVaultSignatureValidator"/> class
    /// with injectable Key Vault dependencies (primarily for testing).
    /// </summary>
    /// <param name="detachedPayload">The detached payload, if verifying a detached signature.</param>
    /// <param name="requireAzureKey">Whether to require the signature to be an AKV key-only signature.</param>
    /// <param name="allowOnlineVerify">Whether to allow network calls to Key Vault when needed to verify.</param>
    /// <param name="credential">The Azure credential used for online key retrieval.</param>
    /// <param name="keyClientFactory">Factory to create a <see cref="KeyClient"/> for a given vault URI.</param>
    public AzureKeyVaultSignatureValidator(
        ReadOnlyMemory<byte>? detachedPayload,
        bool requireAzureKey,
        bool allowOnlineVerify,
        TokenCredential credential,
        Func<Uri, TokenCredential, KeyClient> keyClientFactory)
        : this(detachedPayload, requireAzureKey, allowOnlineVerify)
    {
        ArgumentNullException.ThrowIfNull(credential);
        ArgumentNullException.ThrowIfNull(keyClientFactory);

        Credential = credential;
        KeyClientFactory = keyClientFactory;
    }

    /// <inheritdoc/>
    public bool IsApplicable(CoseSign1Message input, ValidationStage stage)
    {
        if (input is null)
        {
            return false;
        }

        if (stage != ValidationStage.Signature)
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

    /// <inheritdoc/>
    public ValidationResult Validate(CoseSign1Message input, ValidationStage stage)
    {
        if (stage != ValidationStage.Signature)
        {
            return ValidationResult.NotApplicable(
                ClassStrings.ValidatorName,
                stage,
                string.Format(ClassStrings.ErrorFormatUnsupportedValidationStage, stage));
        }

        // Keep synchronous path (used by some callers) working; online verification will
        // execute synchronously when enabled.
        return ValidateAsync(input, stage, CancellationToken.None).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public Task<ValidationResult> ValidateAsync(CoseSign1Message input, ValidationStage stage, CancellationToken cancellationToken = default)
    {
        if (stage != ValidationStage.Signature)
        {
            return Task.FromResult(ValidationResult.NotApplicable(
                ClassStrings.ValidatorName,
                stage,
                string.Format(ClassStrings.ErrorFormatUnsupportedValidationStage, stage)));
        }

        return ValidateCoreAsync(input, stage, cancellationToken);
    }

    private async Task<ValidationResult> ValidateCoreAsync(CoseSign1Message input, ValidationStage stage, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (input is null)
        {
            return ValidationResult.Failure(ClassStrings.ValidatorName, stage, ClassStrings.ErrorMessageNullInput, ClassStrings.ErrorCodeNullInput);
        }

        bool isEmbedded = input.Content != null;
        if (!isEmbedded && DetachedPayload is null)
        {
            return ValidationResult.Failure(
                ClassStrings.ValidatorName,
                stage,
                ClassStrings.ErrorMessageMissingDetachedPayload,
                ClassStrings.ErrorCodeMissingDetachedPayload);
        }

        var metadata = new Dictionary<string, object>();
        _ = TryGetKid(input, out var messageKid);
        if (!string.IsNullOrWhiteSpace(messageKid))
        {
            metadata[ClassStrings.MetadataKeyKid] = messageKid;
            metadata[ClassStrings.MetadataKeyKidLooksLikeAkv] = LooksLikeAzureKeyVaultKeyId(messageKid);
        }

        if (RequireAzureKey)
        {
            // In the key-only flow we expect at least a kid that points at Key Vault.
            if (string.IsNullOrWhiteSpace(messageKid) || !LooksLikeAzureKeyVaultKeyId(messageKid))
            {
                return ValidationResult.Failure(
                    ClassStrings.ValidatorName,
                    stage,
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
                metadata[ClassStrings.MetadataKeyCoseKeyKid] = coseKeyKid;
                if (string.IsNullOrWhiteSpace(messageKid) || !StringEqualsOrdinal(messageKid, coseKeyKid))
                {
                    metadata[ClassStrings.MetadataKeyRequiresOnlineVerification] = true;

                    if (!AllowOnlineVerify)
                    {
                        return ValidationResult.Failure(
                            ClassStrings.ValidatorName,
                            stage,
                            ClassStrings.ErrorMessageOnlineVerifyNotAllowed,
                            ClassStrings.ErrorCodeOnlineVerifyNotAllowed);
                    }

                    // Fall back to online verification to ensure the kid corresponds to the public key.
                    var online = await VerifyOnlineAsync(input, stage, isEmbedded, messageKid, coseKeyKid, cancellationToken).ConfigureAwait(false);
                    if (!online.IsValid)
                    {
                        return online;
                    }

                    foreach (var kvp in online.Metadata)
                    {
                        metadata[kvp.Key] = kvp.Value;
                    }

                    return ValidationResult.Success(ClassStrings.ValidatorName, stage, metadata);
                }
            }
        }

        // If there's no embedded COSE_Key, treat it as a failure unless online verify is enabled.
        if (!hasEmbeddedCoseKey)
        {
            if (AllowOnlineVerify)
            {
                var online = await VerifyOnlineAsync(input, stage, isEmbedded, messageKid, coseKeyKid: string.Empty, cancellationToken).ConfigureAwait(false);
                if (!online.IsValid)
                {
                    return online;
                }

                foreach (var kvp in online.Metadata)
                {
                    metadata[kvp.Key] = kvp.Value;
                }

                return ValidationResult.Success(ClassStrings.ValidatorName, stage, metadata);
            }

            return ValidationResult.Failure(
                ClassStrings.ValidatorName,
                stage,
                ClassStrings.ErrorMessageMissingCoseKey,
                ClassStrings.ErrorCodeMissingCoseKey);
        }

        if (!TryCreatePublicKey(coseKeyBytes, out var rsa, out var ecdsa))
        {
            return ValidationResult.Failure(
                ClassStrings.ValidatorName,
                stage,
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
                metadata[ClassStrings.MetadataKeyKeyType] = ClassStrings.KeyTypeRsa;
            }
            else
            {
                verified = isEmbedded
                    ? input.VerifyEmbedded(ecdsa!)
                    : input.VerifyDetached(ecdsa!, DetachedPayload!.Value.Span);
                metadata[ClassStrings.MetadataKeyKeyType] = ClassStrings.KeyTypeEc;
            }

            if (!verified)
            {
                return ValidationResult.Failure(
                    ClassStrings.ValidatorName,
                    stage,
                    ClassStrings.ErrorMessageSignatureInvalid,
                    ClassStrings.ErrorCodeSignatureInvalid);
            }

            metadata[ClassStrings.MetadataKeyVerificationMode] = ClassStrings.VerificationModeOffline;
            return ValidationResult.Success(ClassStrings.ValidatorName, stage, metadata);
        }
        catch (CryptographicException ex)
        {
            return ValidationResult.Failure(
                ClassStrings.ValidatorName,
                stage,
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
        ValidationStage stage,
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
                stage,
                ClassStrings.ErrorMessageMissingKid,
                ClassStrings.ErrorCodeMissingKid);
        }

        if (!LooksLikeAzureKeyVaultKeyId(kidToUse) || !TryParseKeyVaultKeyId(kidToUse, out var vaultUri, out var keyName, out var keyVersion))
        {
            return ValidationResult.Failure(
                ClassStrings.ValidatorName,
                stage,
                ClassStrings.ErrorMessageOnlineVerifyFailedInvalidKid,
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
                    stage,
                    ClassStrings.ErrorMessageOnlineVerifyFailedUnsupportedKeyType,
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
                        stage,
                        ClassStrings.ErrorMessageSignatureInvalid,
                        ClassStrings.ErrorCodeSignatureInvalid);
                }

                return ValidationResult.Success(ClassStrings.ValidatorName, stage, new Dictionary<string, object>
                {
                    [ClassStrings.MetadataKeyVerificationMode] = ClassStrings.VerificationModeOnline,
                    [ClassStrings.MetadataKeyOnlineKid] = kidToUse
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
                stage,
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

        if (!segments[0].Equals(ClassStrings.KeyVaultPathSegmentKeys, StringComparison.OrdinalIgnoreCase))
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
                    ClassStrings.CurveNameP256 => ECCurve.NamedCurves.nistP256,
                    ClassStrings.CurveNameP384 => ECCurve.NamedCurves.nistP384,
                    ClassStrings.CurveNameP521 => ECCurve.NamedCurves.nistP521,
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
        if (!uri.Scheme.Equals(ClassStrings.KeyVaultUriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (uri.Host == null || !uri.Host.EndsWith(ClassStrings.KeyVaultHostSuffix, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return uri.AbsolutePath.Contains(ClassStrings.KeyVaultKeysPathFragment, StringComparison.OrdinalIgnoreCase);
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
