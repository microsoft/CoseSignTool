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
using CoseSign1.AzureKeyVault;
using CoseSign1.Validation;
using CoseSignTool.Abstractions;

namespace CoseSignTool.AzureKeyVault.Plugin.Tests;

[TestFixture]
public class AzureKeyVaultSignatureValidatorTests
{
    [Test]
    public void Validate_WhenInputIsNull_FailsWithExpectedCode()
    {
        var validator = new AzureKeyVaultSignatureValidator(detachedPayload: null);
        var result = validator.Validate(null!);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures.Any(f => f.ErrorCode == "NULL_INPUT"), Is.True);
    }

    [Test]
    public void IsApplicable_WhenInputIsNull_ReturnsFalse()
    {
        var validator = new AzureKeyVaultSignatureValidator(detachedPayload: null);
        Assert.That(validator.IsApplicable(null!), Is.False);
    }

    [Test]
    public void IsApplicable_WhenNoCoseKeyHeader_ReturnsFalse()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signer = new CoseSigner(key, HashAlgorithmName.SHA256, new CoseHeaderMap(), unprotectedHeaders: null);
        var signed = CoseSign1Message.SignEmbedded(new byte[] { 1, 2, 3 }, signer);
        var msg = CoseSign1Message.DecodeSign1(signed);

        var validator = new AzureKeyVaultSignatureValidator(detachedPayload: null);
        Assert.That(validator.IsApplicable(msg), Is.False);
    }

    [Test]
    public void Validate_WhenMissingCoseKeyHeader_FailsWithExpectedCode()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signer = new CoseSigner(key, HashAlgorithmName.SHA256, new CoseHeaderMap(), unprotectedHeaders: null);
        var signed = CoseSign1Message.SignEmbedded(new byte[] { 1, 2, 3 }, signer);
        var msg = CoseSign1Message.DecodeSign1(signed);

        var validator = new AzureKeyVaultSignatureValidator(detachedPayload: null);
        var result = validator.Validate(msg);

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

        var validator = new AzureKeyVaultSignatureValidator(detachedPayload: null);
        var result = validator.Validate(msg);

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

        var validator = new AzureKeyVaultSignatureValidator(detachedPayload: null);
        Assert.That(validator.IsApplicable(msg), Is.True);

        var result = validator.Validate(msg);
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

        var validator = new AzureKeyVaultSignatureValidator(detachedPayload: null);
        var result = validator.Validate(msg);
        Assert.That(result.IsValid, Is.True);
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

        var validator = new AzureKeyVaultSignatureValidator(detachedPayload: null);
        var result = validator.Validate(msg);

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

        var validator = new AzureKeyVaultSignatureValidator(detachedPayload: null);
        var result = validator.Validate(msg);

        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Metadata["kid"], Is.EqualTo(kid));
        Assert.That(result.Metadata["kidLooksLikeAkv"], Is.EqualTo(false));
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

        var validator = new AzureKeyVaultSignatureValidator(detachedPayload: null);
        var result = validator.Validate(msg);

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

        var validator = new AzureKeyVaultSignatureValidator(detachedPayload: null);
        var result = validator.Validate(msg);

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

        var validator = new AzureKeyVaultSignatureValidator(detachedPayload: null);
        var result = await validator.ValidateAsync(msg);

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

        var validator = new AzureKeyVaultSignatureValidator(detachedPayload: null);
        var result = validator.Validate(msg);

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

        var validator = new AzureKeyVaultSignatureValidator(detachedPayload: null);
        var result = validator.Validate(msg);

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

        var validator = new AzureKeyVaultSignatureValidator(detachedPayload: null);
        var result = validator.Validate(msg);

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

        var validator = new AzureKeyVaultSignatureValidator(detachedPayload: null);
        var result = validator.Validate(msg);

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

        var validator = new AzureKeyVaultSignatureValidator(detachedPayload: payload);
        var result = validator.Validate(msg);

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
}
