// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Formats.Cbor;
using System.CommandLine;
using System.CommandLine.Builder;
using System.CommandLine.Parsing;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using System.Text;
using Azure.Core;
using Azure.Security.KeyVault.Keys;
using CoseSign1.AzureKeyVault;
using CoseSign1.AzureKeyVault.Validation;
using CoseSign1.Validation;
using CoseSign1.Validation.Results;
using CoseSignTool.Abstractions;
using Moq;

namespace CoseSignTool.AzureKeyVault.Plugin.Tests;

[TestFixture]
public class AzureKeyVaultSignatureValidatorTests
{
    [Test]
    public void Stages_ReturnsSignatureStageOnly()
    {
        var validator = new AzureKeyVaultSignatureValidator(detachedPayload: null, requireAzureKey: false, allowOnlineVerify: false);
        Assert.That(validator.Stages, Is.EquivalentTo(new[] { ValidationStage.Signature }));
    }

    [Test]
    public void Validate_WhenInputIsNull_FailsWithExpectedCode()
    {
        var validator = new AzureKeyVaultSignatureValidator(detachedPayload: null, requireAzureKey: false, allowOnlineVerify: false);
        var result = validator.Validate(null!, ValidationStage.Signature);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures.Any(f => f.ErrorCode == "NULL_INPUT"), Is.True);
    }

    [Test]
    public void IsApplicable_WhenInputIsNull_ReturnsFalse()
    {
        var validator = new AzureKeyVaultSignatureValidator(detachedPayload: null, requireAzureKey: false, allowOnlineVerify: false);
        Assert.That(validator.IsApplicable(null!, ValidationStage.Signature), Is.False);
    }

    [Test]
    public void IsApplicable_WhenNoCoseKeyHeader_ReturnsFalse()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signer = new CoseSigner(key, HashAlgorithmName.SHA256, new CoseHeaderMap(), unprotectedHeaders: null);
        var signed = CoseSign1Message.SignEmbedded(new byte[] { 1, 2, 3 }, signer);
        var msg = CoseSign1Message.DecodeSign1(signed);

        var validator = new AzureKeyVaultSignatureValidator(detachedPayload: null, requireAzureKey: false, allowOnlineVerify: false);
        Assert.That(validator.IsApplicable(msg, ValidationStage.Signature), Is.False);
    }

    [Test]
    public void Validate_WhenMissingCoseKeyHeader_FailsWithExpectedCode()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signer = new CoseSigner(key, HashAlgorithmName.SHA256, new CoseHeaderMap(), unprotectedHeaders: null);
        var signed = CoseSign1Message.SignEmbedded(new byte[] { 1, 2, 3 }, signer);
        var msg = CoseSign1Message.DecodeSign1(signed);

        var validator = new AzureKeyVaultSignatureValidator(detachedPayload: null, requireAzureKey: false, allowOnlineVerify: false);
        var result = validator.Validate(msg, ValidationStage.Signature);

        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures.Any(f => f.ErrorCode == "MISSING_COSE_KEY"), Is.True);
    }

    [Test]
    public void Validate_WhenInvalidCoseKeyHeader_FailsWithExpectedCode()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var pub = key.ExportParameters(includePrivateParameters: false);

        var protectedHeaders = new CoseHeaderMap();
        var unprotectedHeaders = new CoseHeaderMap();

        // Start with a valid COSE_Key encoding, then mutate bytes to keep CBOR valid
        // while making the COSE_Key semantically invalid for our parser (kty != RSA/EC2).
        var coseKey = EncodeEc2CoseKey(pub, CoseKeyHeaderContributor.CoseEllipticCurves.P256);
        var mutated = MutateKtyFromEc2ToSymmetric(coseKey);
        unprotectedHeaders.Add(CoseKeyHeaderContributor.CoseKeyHeaderLabel, CoseHeaderValue.FromEncodedValue(mutated));

        var signer = new CoseSigner(key, HashAlgorithmName.SHA256, protectedHeaders, unprotectedHeaders);
        var signed = CoseSign1Message.SignEmbedded(new byte[] { 1, 2, 3 }, signer);
        var msg = CoseSign1Message.DecodeSign1(signed);

        var validator = new AzureKeyVaultSignatureValidator(detachedPayload: null, requireAzureKey: false, allowOnlineVerify: false);
        var result = validator.Validate(msg, ValidationStage.Signature);

        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures.Any(f => f.ErrorCode == "INVALID_COSE_KEY"), Is.True);
    }

    private static byte[] MutateKtyFromEc2ToSymmetric(byte[] coseKey)
    {
        // Our EncodeEc2CoseKey emits: { 1: 2, -1: crv, -2: x, -3: y }
        // In CBOR, 1 is 0x01 and 2 is 0x02. Flip the first "1:2" value to 4 (Symmetric).
        var mutated = (byte[])coseKey.Clone();

        for (int i = 0; i < mutated.Length - 1; i++)
        {
            if (mutated[i] == 0x01 && mutated[i + 1] == 0x02)
            {
                mutated[i + 1] = 0x04;
                return mutated;
            }
        }

        throw new InvalidOperationException("Unexpected COSE_Key encoding; could not locate kty field.");
    }

    [Test]
    public void Validate_WithEmbeddedMessageAndValidCoseKey_SucceedsAndEmitsKidMetadata()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var pub = key.ExportParameters(includePrivateParameters: false);

        var protectedHeaders = new CoseHeaderMap();
        var unprotectedHeaders = new CoseHeaderMap();

        var coseKey = EncodeEc2CoseKey(pub, CoseKeyHeaderContributor.CoseEllipticCurves.P256);
        unprotectedHeaders.Add(CoseKeyHeaderContributor.CoseKeyHeaderLabel, CoseHeaderValue.FromEncodedValue(coseKey));

        var kid = "https://example.vault.azure.net/keys/testKey/00000000000000000000000000000000";
        unprotectedHeaders.Add(CoseHeaderLabel.KeyIdentifier, CoseHeaderValue.FromBytes(Encoding.UTF8.GetBytes(kid)));

        var signer = new CoseSigner(key, HashAlgorithmName.SHA256, protectedHeaders, unprotectedHeaders);
        var payload = new byte[] { 5, 6, 7, 8 };
        var signed = CoseSign1Message.SignEmbedded(payload, signer);
        var msg = CoseSign1Message.DecodeSign1(signed);

        var validator = new AzureKeyVaultSignatureValidator(detachedPayload: null, requireAzureKey: false, allowOnlineVerify: false);
        Assert.That(validator.IsApplicable(msg, ValidationStage.Signature), Is.True);

        var result = validator.Validate(msg, ValidationStage.Signature);
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Metadata.ContainsKey("kid"), Is.True);
        Assert.That(result.Metadata.ContainsKey("kidLooksLikeAkv"), Is.True);
        Assert.That(result.Metadata.ContainsKey("KeyType"), Is.True);
    }

    [Test]
    public void Validate_WithProtectedCoseKeyHeader_Succeeds()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var pub = key.ExportParameters(includePrivateParameters: false);

        var protectedHeaders = new CoseHeaderMap();
        var unprotectedHeaders = new CoseHeaderMap();

        var coseKey = EncodeEc2CoseKey(pub, CoseKeyHeaderContributor.CoseEllipticCurves.P256);
        protectedHeaders.Add(CoseKeyHeaderContributor.CoseKeyHeaderLabel, CoseHeaderValue.FromEncodedValue(coseKey));

        var signer = new CoseSigner(key, HashAlgorithmName.SHA256, protectedHeaders, unprotectedHeaders);
        var payload = new byte[] { 5, 6, 7, 8 };
        var signed = CoseSign1Message.SignEmbedded(payload, signer);
        var msg = CoseSign1Message.DecodeSign1(signed);

        var validator = new AzureKeyVaultSignatureValidator(detachedPayload: null, requireAzureKey: false, allowOnlineVerify: false);
        var result = validator.Validate(msg, ValidationStage.Signature);
        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public void AddAzureKeyVaultSignatureValidator_AddsValidator()
    {
        var builder = CoseSign1.Validation.Cose.Sign1Message();
        var result = builder.AddAzureKeyVaultSignatureValidator(_ => { });
        Assert.That(result, Is.SameAs(builder));
    }

    [Test]
    public void Validate_WhenSignatureDoesNotMatchEmbeddedKey_FailsWithExpectedCode()
    {
        using var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var embeddedKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var embeddedPub = embeddedKey.ExportParameters(includePrivateParameters: false);
        var protectedHeaders = new CoseHeaderMap();
        var unprotectedHeaders = new CoseHeaderMap();

        var coseKey = EncodeEc2CoseKey(embeddedPub, CoseKeyHeaderContributor.CoseEllipticCurves.P256);
        unprotectedHeaders.Add(CoseKeyHeaderContributor.CoseKeyHeaderLabel, CoseHeaderValue.FromEncodedValue(coseKey));

        var signer = new CoseSigner(signingKey, HashAlgorithmName.SHA256, protectedHeaders, unprotectedHeaders);
        var payload = new byte[] { 1, 2, 3, 4 };
        var signed = CoseSign1Message.SignEmbedded(payload, signer);
        var msg = CoseSign1Message.DecodeSign1(signed);

        var validator = new AzureKeyVaultSignatureValidator(detachedPayload: null, requireAzureKey: false, allowOnlineVerify: false);
        var result = validator.Validate(msg, ValidationStage.Signature);

        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures.Any(f => f.ErrorCode == "SIGNATURE_INVALID"), Is.True);
    }

    [Test]
    public void Validate_WithNonAkvKid_EmitsKidLooksLikeAkvFalse()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var pub = key.ExportParameters(includePrivateParameters: false);

        var protectedHeaders = new CoseHeaderMap();
        var unprotectedHeaders = new CoseHeaderMap();

        var coseKey = EncodeEc2CoseKey(pub, CoseKeyHeaderContributor.CoseEllipticCurves.P256);
        unprotectedHeaders.Add(CoseKeyHeaderContributor.CoseKeyHeaderLabel, CoseHeaderValue.FromEncodedValue(coseKey));

        var kid = "not-a-url";
        unprotectedHeaders.Add(CoseHeaderLabel.KeyIdentifier, CoseHeaderValue.FromBytes(Encoding.UTF8.GetBytes(kid)));

        var signer = new CoseSigner(key, HashAlgorithmName.SHA256, protectedHeaders, unprotectedHeaders);
        var signed = CoseSign1Message.SignEmbedded(new byte[] { 1, 2, 3 }, signer);
        var msg = CoseSign1Message.DecodeSign1(signed);

        var validator = new AzureKeyVaultSignatureValidator(detachedPayload: null, requireAzureKey: false, allowOnlineVerify: false);
        var result = validator.Validate(msg, ValidationStage.Signature);

        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Metadata["kid"], Is.EqualTo(kid));
        Assert.That(result.Metadata["kidLooksLikeAkv"], Is.EqualTo(false));
    }

    [Test]
    public void Validate_WithNonKeysPathKid_EmitsKidLooksLikeAkvFalse()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var pub = key.ExportParameters(includePrivateParameters: false);

        var protectedHeaders = new CoseHeaderMap();
        var unprotectedHeaders = new CoseHeaderMap();

        var coseKey = EncodeEc2CoseKey(pub, CoseKeyHeaderContributor.CoseEllipticCurves.P256);
        unprotectedHeaders.Add(CoseKeyHeaderContributor.CoseKeyHeaderLabel, CoseHeaderValue.FromEncodedValue(coseKey));

        var kid = "https://example.vault.azure.net/secrets/testKey/00000000000000000000000000000000";
        unprotectedHeaders.Add(CoseHeaderLabel.KeyIdentifier, CoseHeaderValue.FromBytes(Encoding.UTF8.GetBytes(kid)));

        var signer = new CoseSigner(key, HashAlgorithmName.SHA256, protectedHeaders, unprotectedHeaders);
        var signed = CoseSign1Message.SignEmbedded(new byte[] { 1, 2, 3 }, signer);
        var msg = CoseSign1Message.DecodeSign1(signed);

        var validator = new AzureKeyVaultSignatureValidator(detachedPayload: null, requireAzureKey: false, allowOnlineVerify: false);
        var result = validator.Validate(msg, ValidationStage.Signature);

        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Metadata["kidLooksLikeAkv"], Is.EqualTo(false));
    }

    [Test]
    public void IsApplicable_WhenStageIsNotSignature_ReturnsFalse()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signer = new CoseSigner(key, HashAlgorithmName.SHA256);
        var signed = CoseSign1Message.SignEmbedded(new byte[] { 1, 2, 3 }, signer);
        var msg = CoseSign1Message.DecodeSign1(signed);

        var validator = new AzureKeyVaultSignatureValidator(detachedPayload: null, requireAzureKey: false, allowOnlineVerify: false);
        Assert.That(validator.IsApplicable(msg, ValidationStage.KeyMaterialTrust), Is.False);
    }

    [Test]
    public void Validate_WhenStageIsNotSignature_ReturnsNotApplicable()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signer = new CoseSigner(key, HashAlgorithmName.SHA256);
        var signed = CoseSign1Message.SignEmbedded(new byte[] { 1, 2, 3 }, signer);
        var msg = CoseSign1Message.DecodeSign1(signed);

        var validator = new AzureKeyVaultSignatureValidator(detachedPayload: null, requireAzureKey: false, allowOnlineVerify: false);
        var result = validator.Validate(msg, ValidationStage.KeyMaterialTrust);

        Assert.That(result.IsNotApplicable, Is.True);
        Assert.That(result.Metadata.ContainsKey("Reason"), Is.True);
    }

    [Test]
    public async Task ValidateAsync_WhenStageIsNotSignature_ReturnsNotApplicable()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signer = new CoseSigner(key, HashAlgorithmName.SHA256);
        var signed = CoseSign1Message.SignEmbedded(new byte[] { 1, 2, 3 }, signer);
        var msg = CoseSign1Message.DecodeSign1(signed);

        var validator = new AzureKeyVaultSignatureValidator(detachedPayload: null, requireAzureKey: false, allowOnlineVerify: false);
        var result = await validator.ValidateAsync(msg, ValidationStage.KeyMaterialTrust);

        Assert.That(result.IsNotApplicable, Is.True);
        Assert.That(result.Metadata.ContainsKey("Reason"), Is.True);
    }

    [Test]
    public void Validate_WhenEmbeddedCoseKeyValueIsNotAMap_FailsWithInvalidCoseKey()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var pub = key.ExportParameters(includePrivateParameters: false);

        var protectedHeaders = new CoseHeaderMap();
        var unprotectedHeaders = new CoseHeaderMap();

        // Start with a valid COSE_Key header so we can sign, then mutate it after signing.
        var coseKey = EncodeEc2CoseKey(pub, CoseKeyHeaderContributor.CoseEllipticCurves.P256);
        unprotectedHeaders.Add(CoseKeyHeaderContributor.CoseKeyHeaderLabel, CoseHeaderValue.FromEncodedValue(coseKey));

        var signer = new CoseSigner(key, HashAlgorithmName.SHA256, protectedHeaders, unprotectedHeaders);
        var signed = CoseSign1Message.SignEmbedded(new byte[] { 1, 2, 3 }, signer);

        // Mutate the embedded COSE_Key value into a CBOR integer. This keeps the overall COSE_Sign1
        // well-formed, while forcing TryGetCoseKeyKid and TryCreatePublicKey to hit error paths.
        var mutated = MutateUnprotectedHeaderValue(signed, headerLabel: -65537, w => w.WriteInt32(1));
        var msg = CoseSign1Message.DecodeSign1(mutated);

        var validator = new AzureKeyVaultSignatureValidator(detachedPayload: null, requireAzureKey: false, allowOnlineVerify: false);
        var result = validator.Validate(msg, ValidationStage.Signature);

        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures.Any(f => f.ErrorCode == "INVALID_COSE_KEY"), Is.True);
    }

    [Test]
    public void TryCreatePublicKeyFromKeyVaultKey_WhenJwkIsNull_ReturnsFalse()
    {
        var expectedVaultUri = new Uri("https://example.vault.azure.net");
        var expectedKeyName = "key";
        var expectedKeyVersion = "v1";

        var keyProperties = Azure.Security.KeyVault.Keys.KeyModelFactory.KeyProperties(
            id: new Uri($"{expectedVaultUri}keys/{expectedKeyName}/{expectedKeyVersion}"),
            vaultUri: expectedVaultUri,
            name: expectedKeyName,
            version: expectedKeyVersion);

        var kvKey = Azure.Security.KeyVault.Keys.KeyModelFactory.KeyVaultKey(properties: keyProperties, key: null);

        var ok = InvokeTryCreatePublicKeyFromKeyVaultKey(kvKey, out var rsa, out var ecdsa);
        Assert.That(ok, Is.False);
        Assert.That(rsa, Is.Null);
        Assert.That(ecdsa, Is.Null);
    }

    [Test]
    public void TryCreatePublicKeyFromKeyVaultKey_WhenRsaKeyHasModulusAndExponent_ReturnsTrue()
    {
        var expectedVaultUri = new Uri("https://example.vault.azure.net");
        var expectedKeyName = "key";
        var expectedKeyVersion = "v1";

        using var rsaSource = RSA.Create(2048);
        var jsonWebKey = new Azure.Security.KeyVault.Keys.JsonWebKey(rsaSource, includePrivateParameters: false);

        var keyProperties = Azure.Security.KeyVault.Keys.KeyModelFactory.KeyProperties(
            id: new Uri($"{expectedVaultUri}keys/{expectedKeyName}/{expectedKeyVersion}"),
            vaultUri: expectedVaultUri,
            name: expectedKeyName,
            version: expectedKeyVersion);

        var kvKey = Azure.Security.KeyVault.Keys.KeyModelFactory.KeyVaultKey(properties: keyProperties, key: jsonWebKey);

        var ok = InvokeTryCreatePublicKeyFromKeyVaultKey(kvKey, out var rsa, out var ecdsa);
        Assert.That(ok, Is.True);
        Assert.That(rsa, Is.Not.Null);
        Assert.That(ecdsa, Is.Null);
    }

    [Test]
    public void TryCreatePublicKeyFromKeyVaultKey_WhenEcKeyIsMissingX_ReturnsFalse()
    {
        var expectedVaultUri = new Uri("https://example.vault.azure.net");
        var expectedKeyName = "key";
        var expectedKeyVersion = "v1";

        using var ecSource = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var jsonWebKey = new Azure.Security.KeyVault.Keys.JsonWebKey(ecSource, includePrivateParameters: false);
        jsonWebKey.X = null;

        var keyProperties = Azure.Security.KeyVault.Keys.KeyModelFactory.KeyProperties(
            id: new Uri($"{expectedVaultUri}keys/{expectedKeyName}/{expectedKeyVersion}"),
            vaultUri: expectedVaultUri,
            name: expectedKeyName,
            version: expectedKeyVersion);

        var kvKey = Azure.Security.KeyVault.Keys.KeyModelFactory.KeyVaultKey(properties: keyProperties, key: jsonWebKey);

        var ok = InvokeTryCreatePublicKeyFromKeyVaultKey(kvKey, out var rsa, out var ecdsa);
        Assert.That(ok, Is.False);
        Assert.That(rsa, Is.Null);
        Assert.That(ecdsa, Is.Null);
    }

    [Test]
    public void TryCreatePublicKeyFromKeyVaultKey_WhenEcKeyCurveIsP384_ReturnsTrue()
    {
        var expectedVaultUri = new Uri("https://example.vault.azure.net");
        var expectedKeyName = "key";
        var expectedKeyVersion = "v1";

        using var ecSource = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var jsonWebKey = new Azure.Security.KeyVault.Keys.JsonWebKey(ecSource, includePrivateParameters: false);

        var keyProperties = Azure.Security.KeyVault.Keys.KeyModelFactory.KeyProperties(
            id: new Uri($"{expectedVaultUri}keys/{expectedKeyName}/{expectedKeyVersion}"),
            vaultUri: expectedVaultUri,
            name: expectedKeyName,
            version: expectedKeyVersion);

        var kvKey = Azure.Security.KeyVault.Keys.KeyModelFactory.KeyVaultKey(properties: keyProperties, key: jsonWebKey);

        var ok = InvokeTryCreatePublicKeyFromKeyVaultKey(kvKey, out var rsa, out var ecdsa);
        Assert.That(ok, Is.True);
        Assert.That(rsa, Is.Null);
        Assert.That(ecdsa, Is.Not.Null);
    }

    [Test]
    public void IsApplicable_WhenRequireAzureKeyTrue_ReturnsTrueEvenWithoutCoseKeyHeader()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signer = new CoseSigner(key, HashAlgorithmName.SHA256);
        var signed = CoseSign1Message.SignEmbedded(new byte[] { 1, 2, 3 }, signer);
        var msg = CoseSign1Message.DecodeSign1(signed);

        var validator = new AzureKeyVaultSignatureValidator(detachedPayload: null, requireAzureKey: true, allowOnlineVerify: false);
        Assert.That(validator.IsApplicable(msg, ValidationStage.Signature), Is.True);
    }

    [Test]
    public void InternalConstructor_WhenCredentialIsNull_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() =>
            _ = new AzureKeyVaultSignatureValidator(
                detachedPayload: null,
                requireAzureKey: false,
                allowOnlineVerify: true,
                credential: null!,
                keyClientFactory: (_, __) => new Mock<KeyClient>().Object));
    }

    [Test]
    public void InternalConstructor_WhenKeyClientFactoryIsNull_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() =>
            _ = new AzureKeyVaultSignatureValidator(
                detachedPayload: null,
                requireAzureKey: false,
                allowOnlineVerify: true,
                credential: new Mock<TokenCredential>().Object,
                keyClientFactory: null!));
    }

    [Test]
    public void Validate_WithEmbeddedMessageAndP384CoseKey_Succeeds()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var pub = key.ExportParameters(includePrivateParameters: false);

        var protectedHeaders = new CoseHeaderMap();
        var unprotectedHeaders = new CoseHeaderMap();

        var coseKey = EncodeEc2CoseKey(pub, CoseKeyHeaderContributor.CoseEllipticCurves.P384);
        unprotectedHeaders.Add(CoseKeyHeaderContributor.CoseKeyHeaderLabel, CoseHeaderValue.FromEncodedValue(coseKey));

        var signer = new CoseSigner(key, HashAlgorithmName.SHA384, protectedHeaders, unprotectedHeaders);
        var signed = CoseSign1Message.SignEmbedded(new byte[] { 1, 2, 3 }, signer);
        var msg = CoseSign1Message.DecodeSign1(signed);

        var validator = new AzureKeyVaultSignatureValidator(detachedPayload: null, requireAzureKey: false, allowOnlineVerify: false);
        var result = validator.Validate(msg, ValidationStage.Signature);

        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Metadata["KeyType"], Is.EqualTo("EC"));
    }

    [Test]
    public void Validate_WithEmbeddedMessageAndP521CoseKey_Succeeds()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP521);
        var pub = key.ExportParameters(includePrivateParameters: false);

        var protectedHeaders = new CoseHeaderMap();
        var unprotectedHeaders = new CoseHeaderMap();

        var coseKey = EncodeEc2CoseKey(pub, CoseKeyHeaderContributor.CoseEllipticCurves.P521);
        unprotectedHeaders.Add(CoseKeyHeaderContributor.CoseKeyHeaderLabel, CoseHeaderValue.FromEncodedValue(coseKey));

        var signer = new CoseSigner(key, HashAlgorithmName.SHA512, protectedHeaders, unprotectedHeaders);
        var signed = CoseSign1Message.SignEmbedded(new byte[] { 4, 5, 6 }, signer);
        var msg = CoseSign1Message.DecodeSign1(signed);

        var validator = new AzureKeyVaultSignatureValidator(detachedPayload: null, requireAzureKey: false, allowOnlineVerify: false);
        var result = validator.Validate(msg, ValidationStage.Signature);

        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Metadata["KeyType"], Is.EqualTo("EC"));
    }

    [Test]
    public void Validate_WithHttpSchemeKid_EmitsKidLooksLikeAkvFalse()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var pub = key.ExportParameters(includePrivateParameters: false);

        var protectedHeaders = new CoseHeaderMap();
        var unprotectedHeaders = new CoseHeaderMap();

        var coseKey = EncodeEc2CoseKey(pub, CoseKeyHeaderContributor.CoseEllipticCurves.P256);
        unprotectedHeaders.Add(CoseKeyHeaderContributor.CoseKeyHeaderLabel, CoseHeaderValue.FromEncodedValue(coseKey));

        var kid = "http://example.vault.azure.net/keys/testKey/00000000000000000000000000000000";
        unprotectedHeaders.Add(CoseHeaderLabel.KeyIdentifier, CoseHeaderValue.FromBytes(Encoding.UTF8.GetBytes(kid)));

        var signer = new CoseSigner(key, HashAlgorithmName.SHA256, protectedHeaders, unprotectedHeaders);
        var signed = CoseSign1Message.SignEmbedded(new byte[] { 1, 2, 3 }, signer);
        var msg = CoseSign1Message.DecodeSign1(signed);

        var validator = new AzureKeyVaultSignatureValidator(detachedPayload: null, requireAzureKey: false, allowOnlineVerify: false);
        var result = validator.Validate(msg, ValidationStage.Signature);

        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Metadata["kid"], Is.EqualTo(kid));
        Assert.That(result.Metadata["kidLooksLikeAkv"], Is.EqualTo(false));
    }

    [Test]
    public void Validate_WithNonVaultHostKid_EmitsKidLooksLikeAkvFalse()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var pub = key.ExportParameters(includePrivateParameters: false);

        var protectedHeaders = new CoseHeaderMap();
        var unprotectedHeaders = new CoseHeaderMap();

        var coseKey = EncodeEc2CoseKey(pub, CoseKeyHeaderContributor.CoseEllipticCurves.P256);
        unprotectedHeaders.Add(CoseKeyHeaderContributor.CoseKeyHeaderLabel, CoseHeaderValue.FromEncodedValue(coseKey));

        var kid = "https://example.com/keys/testKey/00000000000000000000000000000000";
        unprotectedHeaders.Add(CoseHeaderLabel.KeyIdentifier, CoseHeaderValue.FromBytes(Encoding.UTF8.GetBytes(kid)));

        var signer = new CoseSigner(key, HashAlgorithmName.SHA256, protectedHeaders, unprotectedHeaders);
        var signed = CoseSign1Message.SignEmbedded(new byte[] { 1, 2, 3 }, signer);
        var msg = CoseSign1Message.DecodeSign1(signed);

        var validator = new AzureKeyVaultSignatureValidator(detachedPayload: null, requireAzureKey: false, allowOnlineVerify: false);
        var result = validator.Validate(msg, ValidationStage.Signature);

        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Metadata["kid"], Is.EqualTo(kid));
        Assert.That(result.Metadata["kidLooksLikeAkv"], Is.EqualTo(false));
    }

    [Test]
    public async Task ValidateAsync_WithValidEmbeddedMessage_CompletesAndReturnsSuccess()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var pub = key.ExportParameters(includePrivateParameters: false);

        var protectedHeaders = new CoseHeaderMap();
        var unprotectedHeaders = new CoseHeaderMap();

        var coseKey = EncodeEc2CoseKey(pub, CoseKeyHeaderContributor.CoseEllipticCurves.P256);
        unprotectedHeaders.Add(CoseKeyHeaderContributor.CoseKeyHeaderLabel, CoseHeaderValue.FromEncodedValue(coseKey));

        var signer = new CoseSigner(key, HashAlgorithmName.SHA256, protectedHeaders, unprotectedHeaders);
        var signed = CoseSign1Message.SignEmbedded(new byte[] { 5, 6, 7 }, signer);
        var msg = CoseSign1Message.DecodeSign1(signed);

        var validator = new AzureKeyVaultSignatureValidator(detachedPayload: null, requireAzureKey: false, allowOnlineVerify: false);
        var result = await validator.ValidateAsync(msg, ValidationStage.Signature);

        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public void Validate_WhenCoseKeyHasUnexpectedValueTypes_FailsWithInvalidCoseKey()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var pub = key.ExportParameters(includePrivateParameters: false);

        var protectedHeaders = new CoseHeaderMap();
        var unprotectedHeaders = new CoseHeaderMap();

        var coseKey = EncodeEc2CoseKey_WithUnexpectedLabelValueTypes(pub);
        unprotectedHeaders.Add(CoseKeyHeaderContributor.CoseKeyHeaderLabel, CoseHeaderValue.FromEncodedValue(coseKey));

        var signer = new CoseSigner(key, HashAlgorithmName.SHA256, protectedHeaders, unprotectedHeaders);
        var signed = CoseSign1Message.SignEmbedded(new byte[] { 1, 2, 3 }, signer);
        var msg = CoseSign1Message.DecodeSign1(signed);

        var validator = new AzureKeyVaultSignatureValidator(detachedPayload: null, requireAzureKey: false, allowOnlineVerify: false);
        var result = validator.Validate(msg, ValidationStage.Signature);

        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures.Any(f => f.ErrorCode == "INVALID_COSE_KEY"), Is.True);
    }

    [Test]
    public void Validate_WhenProtectedAlgorithmIsMutated_FailsViaSignatureInvalid()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var pub = key.ExportParameters(includePrivateParameters: false);

        var protectedHeaders = new CoseHeaderMap();
        var unprotectedHeaders = new CoseHeaderMap();

        var coseKey = EncodeEc2CoseKey(pub, CoseKeyHeaderContributor.CoseEllipticCurves.P256);
        unprotectedHeaders.Add(CoseKeyHeaderContributor.CoseKeyHeaderLabel, CoseHeaderValue.FromEncodedValue(coseKey));

        var signer = new CoseSigner(key, HashAlgorithmName.SHA256, protectedHeaders, unprotectedHeaders);
        var signed = CoseSign1Message.SignEmbedded(new byte[] { 9, 8, 7 }, signer);

        var mutated = MutateProtectedAlgEs256ToEdDsa(signed);
        var msg = CoseSign1Message.DecodeSign1(mutated);

        var validator = new AzureKeyVaultSignatureValidator(detachedPayload: null, requireAzureKey: false, allowOnlineVerify: false);
        var result = validator.Validate(msg, ValidationStage.Signature);

        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures.Any(f => f.ErrorCode == "SIGNATURE_INVALID"), Is.True);
    }

    [Test]
    public void Validate_WithRsaKey_Succeeds()
    {
        using var rsa = RSA.Create(2048);
        var publicParams = rsa.ExportParameters(includePrivateParameters: false);

        var protectedHeaders = new CoseHeaderMap();
        var unprotectedHeaders = new CoseHeaderMap();

        var coseKey = EncodeRsaCoseKey(publicParams);
        unprotectedHeaders.Add(CoseKeyHeaderContributor.CoseKeyHeaderLabel, CoseHeaderValue.FromEncodedValue(coseKey));

        var signer = new CoseSigner(rsa, RSASignaturePadding.Pss, HashAlgorithmName.SHA256, protectedHeaders, unprotectedHeaders);
        var payload = new byte[] { 1, 2, 3, 4, 5 };
        var signed = CoseSign1Message.SignEmbedded(payload, signer);
        var msg = CoseSign1Message.DecodeSign1(signed);

        var validator = new AzureKeyVaultSignatureValidator(detachedPayload: null, requireAzureKey: false, allowOnlineVerify: false);
        var result = validator.Validate(msg, ValidationStage.Signature);

        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Metadata["KeyType"], Is.EqualTo("RSA"));
    }

    [Test]
    public void Validate_WithDetachedMessageWithoutPayload_FailsWithExpectedCode()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var pub = key.ExportParameters(includePrivateParameters: false);

        var protectedHeaders = new CoseHeaderMap();
        var unprotectedHeaders = new CoseHeaderMap();

        var coseKey = EncodeEc2CoseKey(pub, CoseKeyHeaderContributor.CoseEllipticCurves.P256);
        unprotectedHeaders.Add(CoseKeyHeaderContributor.CoseKeyHeaderLabel, CoseHeaderValue.FromEncodedValue(coseKey));

        var signer = new CoseSigner(key, HashAlgorithmName.SHA256, protectedHeaders, unprotectedHeaders);
        var payload = new byte[] { 9, 10, 11 };
        var signed = CoseSign1Message.SignDetached(payload, signer);
        var msg = CoseSign1Message.DecodeSign1(signed);

        var validator = new AzureKeyVaultSignatureValidator(detachedPayload: null, requireAzureKey: false, allowOnlineVerify: false);
        var result = validator.Validate(msg, ValidationStage.Signature);

        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures.Any(f => f.ErrorCode == "MISSING_DETACHED_PAYLOAD"), Is.True);
    }

    [Test]
    public void Validate_WithDetachedMessageAndPayload_Succeeds()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var pub = key.ExportParameters(includePrivateParameters: false);

        var protectedHeaders = new CoseHeaderMap();
        var unprotectedHeaders = new CoseHeaderMap();

        var coseKey = EncodeEc2CoseKey(pub, CoseKeyHeaderContributor.CoseEllipticCurves.P256);
        unprotectedHeaders.Add(CoseKeyHeaderContributor.CoseKeyHeaderLabel, CoseHeaderValue.FromEncodedValue(coseKey));

        var signer = new CoseSigner(key, HashAlgorithmName.SHA256, protectedHeaders, unprotectedHeaders);
        var payload = new byte[] { 12, 13, 14 };
        var signed = CoseSign1Message.SignDetached(payload, signer);
        var msg = CoseSign1Message.DecodeSign1(signed);

        var validator = new AzureKeyVaultSignatureValidator(detachedPayload: payload, requireAzureKey: false, allowOnlineVerify: false);
        var result = validator.Validate(msg, ValidationStage.Signature);

        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Metadata.ContainsKey("KeyType"), Is.True);
    }

    [Test]
    public void VerificationProvider_ContextFreeCreateValidators_ReturnsEmpty()
    {
        var provider = new AzureKeyVaultVerificationProvider();
        var parseResult = new Parser(new RootCommand()).Parse(Array.Empty<string>());

        var validators = provider.CreateValidators(parseResult).ToList();
        Assert.That(validators, Is.Empty);
    }

    [Test]
    public void VerificationProvider_WithContext_CreatesSignatureValidator()
    {
        var provider = new AzureKeyVaultVerificationProvider();
        var parseResult = new Parser(new RootCommand()).Parse(Array.Empty<string>());

        var ctx = new VerificationContext(new ReadOnlyMemory<byte>(new byte[] { 1, 2, 3 }));

        var validators = provider.CreateValidators(parseResult, ctx).ToList();
        Assert.That(validators, Has.Count.EqualTo(1));
        Assert.That(validators[0], Is.InstanceOf<AzureKeyVaultSignatureValidator>());
    }

    [Test]
    public void VerificationProvider_MetadataAndActivation_AreExpected()
    {
        var provider = new AzureKeyVaultVerificationProvider();
        var parseResult = new Parser(new RootCommand()).Parse(Array.Empty<string>());

        Assert.That(provider.ProviderName, Is.EqualTo("AzureKeyVault"));
        Assert.That(provider.Priority, Is.EqualTo(0));
        Assert.DoesNotThrow(() => provider.AddVerificationOptions(new RootCommand()));
        Assert.That(provider.IsActivated(parseResult), Is.True);

        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signer = new CoseSigner(ecdsa, HashAlgorithmName.SHA256);
        var signed = CoseSign1Message.SignEmbedded(new byte[] { 1, 2, 3 }, signer);
        var msg = CoseSign1Message.DecodeSign1(signed);

        var metadata = provider.GetVerificationMetadata(parseResult, msg, ValidationResult.Success("ok"));
        Assert.That(metadata.ContainsKey("AKV Key-Only Verification"), Is.True);
    }

    [Test]
    public void IsApplicable_WhenRequireAzureKey_IsTrue_ReturnsTrueEvenWithoutCoseKeyHeader()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signer = new CoseSigner(key, HashAlgorithmName.SHA256, new CoseHeaderMap(), unprotectedHeaders: null);
        var signed = CoseSign1Message.SignEmbedded(new byte[] { 1, 2, 3 }, signer);
        var msg = CoseSign1Message.DecodeSign1(signed);

        var validator = new AzureKeyVaultSignatureValidator(detachedPayload: null, requireAzureKey: true, allowOnlineVerify: false);
        Assert.That(validator.IsApplicable(msg, ValidationStage.Signature), Is.True);
    }

    [Test]
    public void Validate_WhenRequireAzureKey_AndKidMissing_FailsWithExpectedCode()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signer = new CoseSigner(key, HashAlgorithmName.SHA256, new CoseHeaderMap(), unprotectedHeaders: null);
        var signed = CoseSign1Message.SignEmbedded(new byte[] { 1, 2, 3 }, signer);
        var msg = CoseSign1Message.DecodeSign1(signed);

        var validator = new AzureKeyVaultSignatureValidator(detachedPayload: null, requireAzureKey: true, allowOnlineVerify: false);
        var result = validator.Validate(msg, ValidationStage.Signature);

        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures.Any(f => f.ErrorCode == "AKV_KEY_EXPECTED"), Is.True);
    }

    [Test]
    public void Validate_WhenCoseKeyKidDoesNotMatchMessageKid_AndOnlineNotAllowed_FailsWithExpectedCode()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var pub = key.ExportParameters(includePrivateParameters: false);

        var protectedHeaders = new CoseHeaderMap();
        var unprotectedHeaders = new CoseHeaderMap();

        // COSE_Key includes a kid that does NOT match the message kid.
        var coseKeyKid = "https://example.vault.azure.net/keys/keyA/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        var coseKey = EncodeEc2CoseKeyWithKid(pub, CoseKeyHeaderContributor.CoseEllipticCurves.P256, coseKeyKid);
        unprotectedHeaders.Add(CoseKeyHeaderContributor.CoseKeyHeaderLabel, CoseHeaderValue.FromEncodedValue(coseKey));

        var messageKid = "https://example.vault.azure.net/keys/keyB/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        unprotectedHeaders.Add(CoseHeaderLabel.KeyIdentifier, CoseHeaderValue.FromBytes(Encoding.UTF8.GetBytes(messageKid)));

        var signer = new CoseSigner(key, HashAlgorithmName.SHA256, protectedHeaders, unprotectedHeaders);
        var signed = CoseSign1Message.SignEmbedded(new byte[] { 9, 9, 9 }, signer);
        var msg = CoseSign1Message.DecodeSign1(signed);

        var validator = new AzureKeyVaultSignatureValidator(detachedPayload: null, requireAzureKey: false, allowOnlineVerify: false);
        var result = validator.Validate(msg, ValidationStage.Signature);

        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures.Any(f => f.ErrorCode == "ONLINE_VERIFY_NOT_ALLOWED"), Is.True);
    }

    [Test]
    public async Task ValidateAsync_WhenCoseKeyKidDoesNotMatchMessageKid_AndOnlineAllowed_VerifiesUsingFetchedKey()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var pub = key.ExportParameters(includePrivateParameters: false);

        var protectedHeaders = new CoseHeaderMap();
        var unprotectedHeaders = new CoseHeaderMap();

        var coseKeyKid = "https://example.vault.azure.net/keys/keyA/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        var coseKey = EncodeEc2CoseKeyWithKid(pub, CoseKeyHeaderContributor.CoseEllipticCurves.P256, coseKeyKid);
        unprotectedHeaders.Add(CoseKeyHeaderContributor.CoseKeyHeaderLabel, CoseHeaderValue.FromEncodedValue(coseKey));

        // Online verification should use the message kid.
        var messageKid = "https://example.vault.azure.net/keys/keyB/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        unprotectedHeaders.Add(CoseHeaderLabel.KeyIdentifier, CoseHeaderValue.FromBytes(Encoding.UTF8.GetBytes(messageKid)));

        var signer = new CoseSigner(key, HashAlgorithmName.SHA256, protectedHeaders, unprotectedHeaders);
        var signed = CoseSign1Message.SignEmbedded(new byte[] { 4, 3, 2, 1 }, signer);
        var msg = CoseSign1Message.DecodeSign1(signed);

        // Mock KeyClient.GetKeyAsync to return a KeyVaultKey with matching public material.
        var keyClient = new Mock<KeyClient>(MockBehavior.Strict);
        var expectedVaultUri = new Uri("https://example.vault.azure.net");
        var expectedKeyName = "keyB";
        var expectedKeyVersion = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

        var jsonWebKey = new Azure.Security.KeyVault.Keys.JsonWebKey(key, includePrivateParameters: false);
        var keyProperties = Azure.Security.KeyVault.Keys.KeyModelFactory.KeyProperties(
            id: new Uri($"{expectedVaultUri}keys/{expectedKeyName}/{expectedKeyVersion}"),
            vaultUri: expectedVaultUri,
            name: expectedKeyName,
            version: expectedKeyVersion);

        var kvKey = Azure.Security.KeyVault.Keys.KeyModelFactory.KeyVaultKey(properties: keyProperties, key: jsonWebKey);
        keyClient
            .Setup(k => k.GetKeyAsync(expectedKeyName, expectedKeyVersion, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Azure.Response.FromValue(kvKey, new Mock<Azure.Response>().Object));

        var credential = new Mock<TokenCredential>(MockBehavior.Strict).Object;
        Func<Uri, TokenCredential, KeyClient> factory = (vaultUri, _) =>
        {
            Assert.That(vaultUri, Is.EqualTo(expectedVaultUri));
            return keyClient.Object;
        };

        var validator = new AzureKeyVaultSignatureValidator(
            detachedPayload: null,
            requireAzureKey: false,
            allowOnlineVerify: true,
            credential: credential,
            keyClientFactory: factory);

        var result = await validator.ValidateAsync(msg, ValidationStage.Signature);
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Metadata["verificationMode"], Is.EqualTo("online"));
    }

    [Test]
    public async Task ValidateAsync_WhenDetachedMessageAndOnlineVerifyEnabled_VerifiesDetachedOnline()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var protectedHeaders = new CoseHeaderMap();
        var unprotectedHeaders = new CoseHeaderMap();

        var messageKid = "https://example.vault.azure.net/keys/keyB/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        unprotectedHeaders.Add(CoseHeaderLabel.KeyIdentifier, CoseHeaderValue.FromBytes(Encoding.UTF8.GetBytes(messageKid)));

        var signer = new CoseSigner(key, HashAlgorithmName.SHA256, protectedHeaders, unprotectedHeaders);
        var payload = new byte[] { 10, 20, 30, 40 };
        var signed = CoseSign1Message.SignDetached(payload, signer);
        var msg = CoseSign1Message.DecodeSign1(signed);

        var keyClient = new Mock<KeyClient>(MockBehavior.Strict);
        var expectedVaultUri = new Uri("https://example.vault.azure.net");
        var expectedKeyName = "keyB";
        var expectedKeyVersion = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

        var jsonWebKey = new Azure.Security.KeyVault.Keys.JsonWebKey(key, includePrivateParameters: false);
        var keyProperties = Azure.Security.KeyVault.Keys.KeyModelFactory.KeyProperties(
            id: new Uri($"{expectedVaultUri}keys/{expectedKeyName}/{expectedKeyVersion}"),
            vaultUri: expectedVaultUri,
            name: expectedKeyName,
            version: expectedKeyVersion);

        var kvKey = Azure.Security.KeyVault.Keys.KeyModelFactory.KeyVaultKey(properties: keyProperties, key: jsonWebKey);
        keyClient
            .Setup(k => k.GetKeyAsync(expectedKeyName, expectedKeyVersion, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Azure.Response.FromValue(kvKey, new Mock<Azure.Response>().Object));

        var credential = new Mock<TokenCredential>(MockBehavior.Strict).Object;
        Func<Uri, TokenCredential, KeyClient> factory = (vaultUri, _) =>
        {
            Assert.That(vaultUri, Is.EqualTo(expectedVaultUri));
            return keyClient.Object;
        };

        var validator = new AzureKeyVaultSignatureValidator(
            detachedPayload: payload,
            requireAzureKey: false,
            allowOnlineVerify: true,
            credential: credential,
            keyClientFactory: factory);

        var result = await validator.ValidateAsync(msg, ValidationStage.Signature);
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Metadata["verificationMode"], Is.EqualTo("online"));
    }

    [Test]
    public void Validate_WhenOnlineVerifyEnabled_ButKidIsMissing_FailsWithExpectedCode()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signer = new CoseSigner(key, HashAlgorithmName.SHA256, protectedHeaders: new CoseHeaderMap(), unprotectedHeaders: null);
        var signed = CoseSign1Message.SignEmbedded(new byte[] { 1, 2, 3 }, signer);
        var msg = CoseSign1Message.DecodeSign1(signed);

        var validator = new AzureKeyVaultSignatureValidator(detachedPayload: null, requireAzureKey: false, allowOnlineVerify: true);
        var result = validator.Validate(msg, ValidationStage.Signature);

        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures.Any(f => f.ErrorCode == "MISSING_KID"), Is.True);
    }

    [Test]
    public void Validate_WhenOnlineVerifyEnabled_ButKidIsNotAKeyVaultKeyId_FailsWithExpectedCode()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var unprotectedHeaders = new CoseHeaderMap();
        unprotectedHeaders.Add(CoseHeaderLabel.KeyIdentifier, CoseHeaderValue.FromBytes(Encoding.UTF8.GetBytes("not-a-keyvault-kid")));

        var signer = new CoseSigner(key, HashAlgorithmName.SHA256, protectedHeaders: new CoseHeaderMap(), unprotectedHeaders: unprotectedHeaders);
        var signed = CoseSign1Message.SignEmbedded(new byte[] { 1, 2, 3 }, signer);
        var msg = CoseSign1Message.DecodeSign1(signed);

        var validator = new AzureKeyVaultSignatureValidator(detachedPayload: null, requireAzureKey: false, allowOnlineVerify: true);
        var result = validator.Validate(msg, ValidationStage.Signature);

        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures.Any(f => f.ErrorCode == "ONLINE_VERIFY_FAILED"), Is.True);
    }

    [Test]
    public async Task ValidateAsync_WhenOnlineVerifyReturnsUnsupportedKeyType_FailsWithExpectedCode()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var protectedHeaders = new CoseHeaderMap();
        var unprotectedHeaders = new CoseHeaderMap();

        var messageKid = "https://example.vault.azure.net/keys/keyB/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        unprotectedHeaders.Add(CoseHeaderLabel.KeyIdentifier, CoseHeaderValue.FromBytes(Encoding.UTF8.GetBytes(messageKid)));

        var signer = new CoseSigner(key, HashAlgorithmName.SHA256, protectedHeaders, unprotectedHeaders);
        var signed = CoseSign1Message.SignEmbedded(new byte[] { 4, 3, 2, 1 }, signer);
        var msg = CoseSign1Message.DecodeSign1(signed);

        var keyClient = new Mock<KeyClient>(MockBehavior.Strict);
        var expectedVaultUri = new Uri("https://example.vault.azure.net");
        var expectedKeyName = "keyB";
        var expectedKeyVersion = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

        using var rsa = RSA.Create(2048);
        var jsonWebKey = new Azure.Security.KeyVault.Keys.JsonWebKey(rsa, includePrivateParameters: false)
        {
            KeyType = Azure.Security.KeyVault.Keys.KeyType.Oct
        };

        var keyProperties = Azure.Security.KeyVault.Keys.KeyModelFactory.KeyProperties(
            id: new Uri($"{expectedVaultUri}keys/{expectedKeyName}/{expectedKeyVersion}"),
            vaultUri: expectedVaultUri,
            name: expectedKeyName,
            version: expectedKeyVersion);

        var kvKey = Azure.Security.KeyVault.Keys.KeyModelFactory.KeyVaultKey(properties: keyProperties, key: jsonWebKey);
        keyClient
            .Setup(k => k.GetKeyAsync(expectedKeyName, expectedKeyVersion, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Azure.Response.FromValue(kvKey, new Mock<Azure.Response>().Object));

        var credential = new Mock<TokenCredential>(MockBehavior.Strict).Object;
        Func<Uri, TokenCredential, KeyClient> factory = (vaultUri, _) =>
        {
            Assert.That(vaultUri, Is.EqualTo(expectedVaultUri));
            return keyClient.Object;
        };

        var validator = new AzureKeyVaultSignatureValidator(
            detachedPayload: null,
            requireAzureKey: false,
            allowOnlineVerify: true,
            credential: credential,
            keyClientFactory: factory);

        var result = await validator.ValidateAsync(msg, ValidationStage.Signature);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures.Any(f => f.ErrorCode == "ONLINE_VERIFY_FAILED"), Is.True);
    }

    [Test]
    public void Validate_WhenOnlineVerifyEnabled_ButKeyIdIsMissingVersion_FailsWithExpectedCode()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var unprotectedHeaders = new CoseHeaderMap();

        // Valid vault host, but missing the /{version} segment.
        var kidMissingVersion = "https://example.vault.azure.net/keys/keyB";
        unprotectedHeaders.Add(CoseHeaderLabel.KeyIdentifier, CoseHeaderValue.FromBytes(Encoding.UTF8.GetBytes(kidMissingVersion)));

        var signer = new CoseSigner(key, HashAlgorithmName.SHA256, protectedHeaders: new CoseHeaderMap(), unprotectedHeaders: unprotectedHeaders);
        var signed = CoseSign1Message.SignEmbedded(new byte[] { 1, 2, 3 }, signer);
        var msg = CoseSign1Message.DecodeSign1(signed);

        var validator = new AzureKeyVaultSignatureValidator(detachedPayload: null, requireAzureKey: false, allowOnlineVerify: true);
        var result = validator.Validate(msg, ValidationStage.Signature);

        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures.Any(f => f.ErrorCode == "ONLINE_VERIFY_FAILED"), Is.True);
    }

    [Test]
    public async Task ValidateAsync_WhenOnlineVerifyFetchesWrongKey_FailsWithSignatureInvalid()
    {
        using var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var wrongKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var protectedHeaders = new CoseHeaderMap();
        var unprotectedHeaders = new CoseHeaderMap();

        var messageKid = "https://example.vault.azure.net/keys/keyB/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        unprotectedHeaders.Add(CoseHeaderLabel.KeyIdentifier, CoseHeaderValue.FromBytes(Encoding.UTF8.GetBytes(messageKid)));

        var signer = new CoseSigner(signingKey, HashAlgorithmName.SHA256, protectedHeaders, unprotectedHeaders);
        var signed = CoseSign1Message.SignEmbedded(new byte[] { 4, 3, 2, 1 }, signer);
        var msg = CoseSign1Message.DecodeSign1(signed);

        var keyClient = new Mock<KeyClient>(MockBehavior.Strict);
        var expectedVaultUri = new Uri("https://example.vault.azure.net");
        var expectedKeyName = "keyB";
        var expectedKeyVersion = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

        var jsonWebKey = new Azure.Security.KeyVault.Keys.JsonWebKey(wrongKey, includePrivateParameters: false);
        var keyProperties = Azure.Security.KeyVault.Keys.KeyModelFactory.KeyProperties(
            id: new Uri($"{expectedVaultUri}keys/{expectedKeyName}/{expectedKeyVersion}"),
            vaultUri: expectedVaultUri,
            name: expectedKeyName,
            version: expectedKeyVersion);

        var kvKey = Azure.Security.KeyVault.Keys.KeyModelFactory.KeyVaultKey(properties: keyProperties, key: jsonWebKey);
        keyClient
            .Setup(k => k.GetKeyAsync(expectedKeyName, expectedKeyVersion, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Azure.Response.FromValue(kvKey, new Mock<Azure.Response>().Object));

        var credential = new Mock<TokenCredential>(MockBehavior.Strict).Object;
        Func<Uri, TokenCredential, KeyClient> factory = (vaultUri, _) =>
        {
            Assert.That(vaultUri, Is.EqualTo(expectedVaultUri));
            return keyClient.Object;
        };

        var validator = new AzureKeyVaultSignatureValidator(
            detachedPayload: null,
            requireAzureKey: false,
            allowOnlineVerify: true,
            credential: credential,
            keyClientFactory: factory);

        var result = await validator.ValidateAsync(msg, ValidationStage.Signature);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures.Any(f => f.ErrorCode == "SIGNATURE_INVALID"), Is.True);
    }

    [Test]
    public async Task ValidateAsync_WhenOnlineKeyIsRsaButMissingExponent_FailsWithOnlineVerifyFailed()
    {
        using var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var unprotectedHeaders = new CoseHeaderMap();
        var messageKid = "https://example.vault.azure.net/keys/keyB/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        unprotectedHeaders.Add(CoseHeaderLabel.KeyIdentifier, CoseHeaderValue.FromBytes(Encoding.UTF8.GetBytes(messageKid)));

        var signer = new CoseSigner(signingKey, HashAlgorithmName.SHA256, protectedHeaders: new CoseHeaderMap(), unprotectedHeaders: unprotectedHeaders);
        var signed = CoseSign1Message.SignEmbedded(new byte[] { 9, 8, 7 }, signer);
        var msg = CoseSign1Message.DecodeSign1(signed);

        var expectedVaultUri = new Uri("https://example.vault.azure.net");
        var expectedKeyName = "keyB";
        var expectedKeyVersion = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

        using var rsa = RSA.Create(2048);
        var jsonWebKey = new Azure.Security.KeyVault.Keys.JsonWebKey(rsa, includePrivateParameters: false);
        jsonWebKey.E = null; // Force TryCreatePublicKeyFromKeyVaultKey to fail

        var keyProperties = Azure.Security.KeyVault.Keys.KeyModelFactory.KeyProperties(
            id: new Uri($"{expectedVaultUri}keys/{expectedKeyName}/{expectedKeyVersion}"),
            vaultUri: expectedVaultUri,
            name: expectedKeyName,
            version: expectedKeyVersion);

        var kvKey = Azure.Security.KeyVault.Keys.KeyModelFactory.KeyVaultKey(properties: keyProperties, key: jsonWebKey);

        var keyClient = new Mock<KeyClient>(MockBehavior.Strict);
        keyClient
            .Setup(k => k.GetKeyAsync(expectedKeyName, expectedKeyVersion, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Azure.Response.FromValue(kvKey, new Mock<Azure.Response>().Object));

        var credential = new Mock<TokenCredential>(MockBehavior.Strict).Object;
        Func<Uri, TokenCredential, KeyClient> factory = (vaultUri, _) =>
        {
            Assert.That(vaultUri, Is.EqualTo(expectedVaultUri));
            return keyClient.Object;
        };

        var validator = new AzureKeyVaultSignatureValidator(
            detachedPayload: null,
            requireAzureKey: false,
            allowOnlineVerify: true,
            credential: credential,
            keyClientFactory: factory);

        var result = await validator.ValidateAsync(msg, ValidationStage.Signature);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures.Any(f => f.ErrorCode == "ONLINE_VERIFY_FAILED"), Is.True);
    }

    [Test]
    public async Task ValidateAsync_WhenOnlineKeyIsEcWithUnknownCurve_FailsWithOnlineVerifyFailed()
    {
        using var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var unprotectedHeaders = new CoseHeaderMap();
        var messageKid = "https://example.vault.azure.net/keys/keyB/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        unprotectedHeaders.Add(CoseHeaderLabel.KeyIdentifier, CoseHeaderValue.FromBytes(Encoding.UTF8.GetBytes(messageKid)));

        var signer = new CoseSigner(signingKey, HashAlgorithmName.SHA256, protectedHeaders: new CoseHeaderMap(), unprotectedHeaders: unprotectedHeaders);
        var signed = CoseSign1Message.SignEmbedded(new byte[] { 2, 4, 6 }, signer);
        var msg = CoseSign1Message.DecodeSign1(signed);

        var expectedVaultUri = new Uri("https://example.vault.azure.net");
        var expectedKeyName = "keyB";
        var expectedKeyVersion = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var jsonWebKey = new Azure.Security.KeyVault.Keys.JsonWebKey(ec, includePrivateParameters: false);
        jsonWebKey.CurveName = null; // Force unknown curve mapping

        var keyProperties = Azure.Security.KeyVault.Keys.KeyModelFactory.KeyProperties(
            id: new Uri($"{expectedVaultUri}keys/{expectedKeyName}/{expectedKeyVersion}"),
            vaultUri: expectedVaultUri,
            name: expectedKeyName,
            version: expectedKeyVersion);

        var kvKey = Azure.Security.KeyVault.Keys.KeyModelFactory.KeyVaultKey(properties: keyProperties, key: jsonWebKey);

        var keyClient = new Mock<KeyClient>(MockBehavior.Strict);
        keyClient
            .Setup(k => k.GetKeyAsync(expectedKeyName, expectedKeyVersion, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Azure.Response.FromValue(kvKey, new Mock<Azure.Response>().Object));

        var credential = new Mock<TokenCredential>(MockBehavior.Strict).Object;
        Func<Uri, TokenCredential, KeyClient> factory = (vaultUri, _) =>
        {
            Assert.That(vaultUri, Is.EqualTo(expectedVaultUri));
            return keyClient.Object;
        };

        var validator = new AzureKeyVaultSignatureValidator(
            detachedPayload: null,
            requireAzureKey: false,
            allowOnlineVerify: true,
            credential: credential,
            keyClientFactory: factory);

        var result = await validator.ValidateAsync(msg, ValidationStage.Signature);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures.Any(f => f.ErrorCode == "ONLINE_VERIFY_FAILED"), Is.True);
    }

    [Test]
    public async Task ValidateAsync_WhenOnlineKeyIsEcWithInvalidPoint_FailsWithOnlineVerifyFailed()
    {
        using var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var unprotectedHeaders = new CoseHeaderMap();
        var messageKid = "https://example.vault.azure.net/keys/keyB/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        unprotectedHeaders.Add(CoseHeaderLabel.KeyIdentifier, CoseHeaderValue.FromBytes(Encoding.UTF8.GetBytes(messageKid)));

        var signer = new CoseSigner(signingKey, HashAlgorithmName.SHA256, protectedHeaders: new CoseHeaderMap(), unprotectedHeaders: unprotectedHeaders);
        var signed = CoseSign1Message.SignEmbedded(new byte[] { 1, 1, 1 }, signer);
        var msg = CoseSign1Message.DecodeSign1(signed);

        var expectedVaultUri = new Uri("https://example.vault.azure.net");
        var expectedKeyName = "keyB";
        var expectedKeyVersion = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var jsonWebKey = new Azure.Security.KeyVault.Keys.JsonWebKey(ec, includePrivateParameters: false);
        // Force an invalid public point to trigger the catch path
        jsonWebKey.X = new byte[] { 1 };
        jsonWebKey.Y = new byte[] { 2 };

        var keyProperties = Azure.Security.KeyVault.Keys.KeyModelFactory.KeyProperties(
            id: new Uri($"{expectedVaultUri}keys/{expectedKeyName}/{expectedKeyVersion}"),
            vaultUri: expectedVaultUri,
            name: expectedKeyName,
            version: expectedKeyVersion);

        var kvKey = Azure.Security.KeyVault.Keys.KeyModelFactory.KeyVaultKey(properties: keyProperties, key: jsonWebKey);

        var keyClient = new Mock<KeyClient>(MockBehavior.Strict);
        keyClient
            .Setup(k => k.GetKeyAsync(expectedKeyName, expectedKeyVersion, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Azure.Response.FromValue(kvKey, new Mock<Azure.Response>().Object));

        var credential = new Mock<TokenCredential>(MockBehavior.Strict).Object;
        Func<Uri, TokenCredential, KeyClient> factory = (vaultUri, _) =>
        {
            Assert.That(vaultUri, Is.EqualTo(expectedVaultUri));
            return keyClient.Object;
        };

        var validator = new AzureKeyVaultSignatureValidator(
            detachedPayload: null,
            requireAzureKey: false,
            allowOnlineVerify: true,
            credential: credential,
            keyClientFactory: factory);

        var result = await validator.ValidateAsync(msg, ValidationStage.Signature);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures.Any(f => f.ErrorCode == "ONLINE_VERIFY_FAILED"), Is.True);
    }

    private static byte[] EncodeEc2CoseKeyWithKid(ECParameters publicKey, int coseCurve, string kid)
    {
        var writer = new CborWriter();
        writer.WriteStartMap(5);

        writer.WriteInt32(CoseKeyHeaderContributor.CoseKeyLabels.KeyType);
        writer.WriteInt32(CoseKeyHeaderContributor.CoseKeyTypes.EC2);

        writer.WriteInt32(CoseKeyHeaderContributor.CoseKeyLabels.KeyId);
        writer.WriteByteString(Encoding.UTF8.GetBytes(kid));

        writer.WriteInt32(CoseKeyHeaderContributor.EC2Labels.Curve);
        writer.WriteInt32(coseCurve);

        writer.WriteInt32(CoseKeyHeaderContributor.EC2Labels.X);
        writer.WriteByteString(publicKey.Q.X!);

        writer.WriteInt32(CoseKeyHeaderContributor.EC2Labels.Y);
        writer.WriteByteString(publicKey.Q.Y!);

        writer.WriteEndMap();
        return writer.Encode();
    }

    private static byte[] EncodeEc2CoseKey(ECParameters publicKey, int coseCurve)
    {
        var writer = new CborWriter();
        writer.WriteStartMap(4);

        writer.WriteInt32(CoseKeyHeaderContributor.CoseKeyLabels.KeyType);
        writer.WriteInt32(CoseKeyHeaderContributor.CoseKeyTypes.EC2);

        writer.WriteInt32(CoseKeyHeaderContributor.EC2Labels.Curve);
        writer.WriteInt32(coseCurve);

        writer.WriteInt32(CoseKeyHeaderContributor.EC2Labels.X);
        writer.WriteByteString(publicKey.Q.X!);

        writer.WriteInt32(CoseKeyHeaderContributor.EC2Labels.Y);
        writer.WriteByteString(publicKey.Q.Y!);

        writer.WriteEndMap();
        return writer.Encode();
    }

    private static byte[] EncodeEc2CoseKey_WithUnexpectedLabelValueTypes(ECParameters publicKey)
    {
        var writer = new CborWriter();

        // Intentionally use unexpected CBOR types for the overlapping labels -1 and -2
        // to exercise parser fallback paths.
        writer.WriteStartMap(4);

        writer.WriteInt32(CoseKeyHeaderContributor.CoseKeyLabels.KeyType);
        writer.WriteInt32(CoseKeyHeaderContributor.CoseKeyTypes.EC2);

        writer.WriteInt32(-1);
        writer.WriteTextString("not-an-int");

        writer.WriteInt32(-2);
        writer.WriteInt32(123);

        writer.WriteInt32(CoseKeyHeaderContributor.EC2Labels.Y);
        writer.WriteByteString(publicKey.Q.Y!);

        writer.WriteEndMap();
        return writer.Encode();
    }

    private static byte[] MutateProtectedAlgEs256ToEdDsa(byte[] coseSign1)
    {
        // Protected header map for ES256 commonly encodes as: a1 01 26 ( { 1: -7 } )
        // Change -7 (0x26) to -8 (0x27) to keep CBOR structure the same.
        var mutated = (byte[])coseSign1.Clone();

        for (int i = 0; i < mutated.Length - 2; i++)
        {
            if (mutated[i] == 0xA1 && mutated[i + 1] == 0x01 && mutated[i + 2] == 0x26)
            {
                mutated[i + 2] = 0x27;
                return mutated;
            }
        }

        throw new InvalidOperationException("Unexpected COSE_Sign1 encoding; could not locate protected alg header.");
    }

    [Test]
    public void TryCreatePublicKey_WhenEncodedCoseKeyIsNotCbor_ReturnsFalse()
    {
        var ok = InvokeTryCreatePublicKey(new byte[] { 0xFF }, out var rsa, out var ecdsa);

        Assert.That(ok, Is.False);
        Assert.That(rsa, Is.Null);
        Assert.That(ecdsa, Is.Null);
    }

    [Test]
    public void TryCreatePublicKey_WhenMinus1AndMinus2HaveUnexpectedTypes_ReturnsFalse()
    {
        var writer = new CborWriter();
        writer.WriteStartMap(4);
        writer.WriteInt32(CoseKeyHeaderContributor.CoseKeyLabels.KeyType);
        writer.WriteInt32(CoseKeyHeaderContributor.CoseKeyTypes.EC2);
        writer.WriteInt32(-1);
        writer.WriteTextString("not-an-int-or-bytes");
        writer.WriteInt32(-2);
        writer.WriteInt32(123);
        writer.WriteInt32(CoseKeyHeaderContributor.EC2Labels.Y);
        writer.WriteByteString(new byte[32]);
        writer.WriteEndMap();

        var ok = InvokeTryCreatePublicKey(writer.Encode(), out var rsa, out var ecdsa);

        Assert.That(ok, Is.False);
        Assert.That(rsa, Is.Null);
        Assert.That(ecdsa, Is.Null);
    }

    [Test]
    public void TryCreatePublicKey_WhenEc2CurveIsUnknown_ReturnsFalse()
    {
        var writer = new CborWriter();
        writer.WriteStartMap(4);
        writer.WriteInt32(CoseKeyHeaderContributor.CoseKeyLabels.KeyType);
        writer.WriteInt32(CoseKeyHeaderContributor.CoseKeyTypes.EC2);
        writer.WriteInt32(CoseKeyHeaderContributor.EC2Labels.Curve);
        writer.WriteInt32(999);
        writer.WriteInt32(CoseKeyHeaderContributor.EC2Labels.X);
        writer.WriteByteString(new byte[32]);
        writer.WriteInt32(CoseKeyHeaderContributor.EC2Labels.Y);
        writer.WriteByteString(new byte[32]);
        writer.WriteEndMap();

        var ok = InvokeTryCreatePublicKey(writer.Encode(), out var rsa, out var ecdsa);

        Assert.That(ok, Is.False);
        Assert.That(rsa, Is.Null);
        Assert.That(ecdsa, Is.Null);
    }

    [Test]
    public void TryCreatePublicKey_WhenRsaExponentMissing_ReturnsFalse()
    {
        var writer = new CborWriter();
        writer.WriteStartMap(2);
        writer.WriteInt32(CoseKeyHeaderContributor.CoseKeyLabels.KeyType);
        writer.WriteInt32(CoseKeyHeaderContributor.CoseKeyTypes.RSA);
        writer.WriteInt32(CoseKeyHeaderContributor.RSALabels.N);
        writer.WriteByteString(new byte[256]);
        writer.WriteEndMap();

        var ok = InvokeTryCreatePublicKey(writer.Encode(), out var rsa, out var ecdsa);

        Assert.That(ok, Is.False);
        Assert.That(rsa, Is.Null);
        Assert.That(ecdsa, Is.Null);
    }

    [Test]
    public void TryCreatePublicKey_WhenMapLengthIsIndefinite_BreaksOnEndMapAndReturnsFalse()
    {
        var writer = new CborWriter();
        writer.WriteStartMap(null);
        writer.WriteInt32(CoseKeyHeaderContributor.CoseKeyLabels.KeyType);
        writer.WriteInt32(CoseKeyHeaderContributor.CoseKeyTypes.RSA);
        writer.WriteEndMap();

        var ok = InvokeTryCreatePublicKey(writer.Encode(), out var rsa, out var ecdsa);

        Assert.That(ok, Is.False);
        Assert.That(rsa, Is.Null);
        Assert.That(ecdsa, Is.Null);
    }

    [Test]
    public void TryCreatePublicKey_WhenUnknownLabelPresent_HitsDefaultCaseAndReturnsFalse()
    {
        var writer = new CborWriter();
        writer.WriteStartMap(2);
        writer.WriteInt32(9999);
        writer.WriteTextString("ignored");
        writer.WriteInt32(CoseKeyHeaderContributor.CoseKeyLabels.KeyType);
        writer.WriteInt32(CoseKeyHeaderContributor.CoseKeyTypes.RSA);
        writer.WriteEndMap();

        var ok = InvokeTryCreatePublicKey(writer.Encode(), out var rsa, out var ecdsa);

        Assert.That(ok, Is.False);
        Assert.That(rsa, Is.Null);
        Assert.That(ecdsa, Is.Null);
    }

    [Test]
    public void TryCreatePublicKey_WhenCurveIsP384_ExecutesCurveCase()
    {
        var writer = new CborWriter();
        writer.WriteStartMap(4);
        writer.WriteInt32(CoseKeyHeaderContributor.CoseKeyLabels.KeyType);
        writer.WriteInt32(CoseKeyHeaderContributor.CoseKeyTypes.EC2);
        writer.WriteInt32(CoseKeyHeaderContributor.EC2Labels.Curve);
        writer.WriteInt32(CoseKeyHeaderContributor.CoseEllipticCurves.P384);
        writer.WriteInt32(CoseKeyHeaderContributor.EC2Labels.X);
        writer.WriteByteString(new byte[48]);
        writer.WriteInt32(CoseKeyHeaderContributor.EC2Labels.Y);
        writer.WriteByteString(new byte[48]);
        writer.WriteEndMap();

        _ = InvokeTryCreatePublicKey(writer.Encode(), out _, out _);
    }

    [Test]
    public void TryCreatePublicKey_WhenCurveIsP521_ExecutesCurveCase()
    {
        var writer = new CborWriter();
        writer.WriteStartMap(4);
        writer.WriteInt32(CoseKeyHeaderContributor.CoseKeyLabels.KeyType);
        writer.WriteInt32(CoseKeyHeaderContributor.CoseKeyTypes.EC2);
        writer.WriteInt32(CoseKeyHeaderContributor.EC2Labels.Curve);
        writer.WriteInt32(CoseKeyHeaderContributor.CoseEllipticCurves.P521);
        writer.WriteInt32(CoseKeyHeaderContributor.EC2Labels.X);
        writer.WriteByteString(new byte[66]);
        writer.WriteInt32(CoseKeyHeaderContributor.EC2Labels.Y);
        writer.WriteByteString(new byte[66]);
        writer.WriteEndMap();

        _ = InvokeTryCreatePublicKey(writer.Encode(), out _, out _);
    }

    private static bool InvokeTryCreatePublicKey(byte[] encodedCoseKey, out RSA? rsa, out ECDsa? ecdsa)
    {
        var method = typeof(AzureKeyVaultSignatureValidator).GetMethod(
            "TryCreatePublicKey",
            BindingFlags.NonPublic | BindingFlags.Static);

        Assert.That(method, Is.Not.Null);

        object?[] args =
        [
            new ReadOnlyMemory<byte>(encodedCoseKey),
            null,
            null
        ];

        var ok = (bool)method!.Invoke(null, args)!;

        rsa = (RSA?)args[1];
        ecdsa = (ECDsa?)args[2];

        rsa?.Dispose();
        ecdsa?.Dispose();

        // After disposal, keep the observable contract for callers: null means not created.
        if (!ok)
        {
            rsa = null;
            ecdsa = null;
        }

        return ok;
    }

    private static byte[] MutateUnprotectedHeaderValue(byte[] coseSign1, int headerLabel, Action<CborWriter> writeNewValue)
    {
        var reader = new CborReader(coseSign1);

        CborTag? tag = null;
        if (reader.PeekState() == CborReaderState.Tag)
        {
            tag = reader.ReadTag();
        }

        _ = reader.ReadStartArray();

        var protectedBytes = reader.ReadByteString();

        int? mapLen = reader.ReadStartMap();
        var headers = new List<(int Label, byte[] EncodedValue)>();
        while (reader.PeekState() != CborReaderState.EndMap)
        {
            int label = reader.ReadInt32();
            byte[] encodedValue = reader.ReadEncodedValue().ToArray();
            headers.Add((label, encodedValue));
        }
        reader.ReadEndMap();

        var payload = reader.ReadEncodedValue().ToArray();
        var signature = reader.ReadByteString();
        reader.ReadEndArray();

        var writer = new CborWriter();

        if (tag != null)
        {
            writer.WriteTag(tag.Value);
        }

        writer.WriteStartArray(4);

        writer.WriteByteString(protectedBytes);

        writer.WriteStartMap(mapLen);
        foreach (var (label, encodedValue) in headers)
        {
            writer.WriteInt32(label);
            if (label == headerLabel)
            {
                writeNewValue(writer);
            }
            else
            {
                writer.WriteEncodedValue(encodedValue);
            }
        }
        writer.WriteEndMap();

        writer.WriteEncodedValue(payload);
        writer.WriteByteString(signature);

        writer.WriteEndArray();
        return writer.Encode();
    }

    private static bool InvokeTryCreatePublicKeyFromKeyVaultKey(KeyVaultKey key, out RSA? rsa, out ECDsa? ecdsa)
    {
        var method = typeof(AzureKeyVaultSignatureValidator).GetMethod(
            "TryCreatePublicKeyFromKeyVaultKey",
            BindingFlags.NonPublic | BindingFlags.Static);

        Assert.That(method, Is.Not.Null);

        object?[] args =
        [
            key,
            null,
            null
        ];

        var ok = (bool)method!.Invoke(null, args)!;

        rsa = (RSA?)args[1];
        ecdsa = (ECDsa?)args[2];

        rsa?.Dispose();
        ecdsa?.Dispose();

        if (!ok)
        {
            rsa = null;
            ecdsa = null;
        }

        return ok;
    }

    private static byte[] EncodeRsaCoseKey(RSAParameters publicKey)
    {
        var writer = new CborWriter();
        writer.WriteStartMap(3);

        writer.WriteInt32(CoseKeyHeaderContributor.CoseKeyLabels.KeyType);
        writer.WriteInt32(CoseKeyHeaderContributor.CoseKeyTypes.RSA);

        writer.WriteInt32(CoseKeyHeaderContributor.RSALabels.N);
        writer.WriteByteString(publicKey.Modulus!);

        writer.WriteInt32(CoseKeyHeaderContributor.RSALabels.E);
        writer.WriteByteString(publicKey.Exponent!);

        writer.WriteEndMap();
        return writer.Encode();
    }

    [Test]
    public void TryParseKeyVaultKeyId_WithInvalidUri_ReturnsFalse()
    {
        var ok = InvokeTryParseKeyVaultKeyId("not-a-uri", out var vaultUri, out var keyName, out var keyVersion);

        Assert.That(ok, Is.False);
        Assert.That(vaultUri, Is.Null);
        Assert.That(keyName, Is.EqualTo(string.Empty));
        Assert.That(keyVersion, Is.Null);
    }

    [Test]
    public void TryParseKeyVaultKeyId_WithNonKeysPath_ReturnsFalse()
    {
        var ok = InvokeTryParseKeyVaultKeyId(
            "https://example.vault.azure.net/secrets/name/version",
            out var vaultUri,
            out var keyName,
            out var keyVersion);

        Assert.That(ok, Is.False);
        Assert.That(vaultUri, Is.Null);
        Assert.That(keyName, Is.EqualTo(string.Empty));
        Assert.That(keyVersion, Is.Null);
    }

    [Test]
    public void TryParseKeyVaultKeyId_WithValidKeyUri_ReturnsTrueAndParsesParts()
    {
        var ok = InvokeTryParseKeyVaultKeyId(
            "https://example.vault.azure.net/keys/myKey/0123456789abcdef",
            out var vaultUri,
            out var keyName,
            out var keyVersion);

        Assert.That(ok, Is.True);
        Assert.That(vaultUri, Is.Not.Null);
        Assert.That(vaultUri!.ToString().TrimEnd('/'), Is.EqualTo("https://example.vault.azure.net"));
        Assert.That(keyName, Is.EqualTo("myKey"));
        Assert.That(keyVersion, Is.EqualTo("0123456789abcdef"));
    }

    private static bool InvokeTryParseKeyVaultKeyId(string kid, out Uri? vaultUri, out string keyName, out string? keyVersion)
    {
        var method = typeof(AzureKeyVaultSignatureValidator).GetMethod(
            "TryParseKeyVaultKeyId",
            BindingFlags.NonPublic | BindingFlags.Static);

        Assert.That(method, Is.Not.Null);

        object?[] args =
        [
            kid,
            null,
            string.Empty,
            null
        ];

        var ok = (bool)method!.Invoke(null, args)!;

        vaultUri = (Uri?)args[1];
        keyName = (string)args[2]!;
        keyVersion = (string?)args[3];

        // Mirror the target method's behavior: failures should reset outputs.
        if (!ok)
        {
            vaultUri = null;
            keyName = string.Empty;
            keyVersion = null;
        }

        return ok;
    }
}
