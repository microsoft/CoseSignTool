// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.AzureKeyVault.Tests.Validation;

using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using System.Text;
using CoseSign1.AzureKeyVault;
using CoseSign1.AzureKeyVault.Validation;
using NUnit.Framework;

[TestFixture]
[Category("AzureKeyVault")]
[Category("Validation")]
public class AzureKeyVaultCoseKeySigningKeyResolverTests
{
    [Test]
    public void Resolve_WithNullMessage_ReturnsFailure()
    {
        var resolver = new AzureKeyVaultCoseKeySigningKeyResolver();

        var result = resolver.Resolve(null!);

        Assert.That(result.IsSuccess, Is.False);
        Assert.That(result.ErrorCode, Is.EqualTo("NULL_INPUT"));
    }

    [Test]
    public void Resolve_WithMissingCoseKeyHeader_ReturnsFailure()
    {
        using var rsa = RSA.Create();
        var signer = new CoseSigner(rsa, RSASignaturePadding.Pss, HashAlgorithmName.SHA256);

        var bytes = CoseSign1Message.SignEmbedded(new byte[] { 1, 2, 3 }, signer);
        var message = CoseSign1Message.DecodeSign1(bytes);

        var resolver = new AzureKeyVaultCoseKeySigningKeyResolver();
        var result = resolver.Resolve(message);

        Assert.That(result.IsSuccess, Is.False);
        Assert.That(result.ErrorCode, Is.EqualTo("COSE_KEY_MISSING"));
    }

    [Test]
    public void Resolve_WithInvalidCoseKeyHeader_ReturnsFailure()
    {
        using var rsa = RSA.Create(2048);

        // Invalid CBOR for COSE_Key (not a map)
        var writer = new CborWriter();
        writer.WriteInt32(123);
        var invalidCoseKey = writer.Encode();

        CoseHeaderMap protectedHeaders = new();
        CoseHeaderMap unprotectedHeaders = new();
        unprotectedHeaders.Add(CoseKeyHeaderContributor.CoseKeyHeaderLabel, CoseHeaderValue.FromEncodedValue(invalidCoseKey));

        var signer = new CoseSigner(rsa, RSASignaturePadding.Pss, HashAlgorithmName.SHA256, protectedHeaders, unprotectedHeaders);
        var bytes = CoseSign1Message.SignEmbedded(new byte[] { 1, 2, 3 }, signer);
        var message = CoseSign1Message.DecodeSign1(bytes);

        var resolver = new AzureKeyVaultCoseKeySigningKeyResolver();
        var result = resolver.Resolve(message);

        Assert.That(result.IsSuccess, Is.False);
        Assert.That(result.ErrorCode, Is.EqualTo("COSE_KEY_INVALID"));
    }

    [Test]
    public void Resolve_WithUnsupportedKeyTypeInCoseKeyHeader_ReturnsFailure()
    {
        using var rsa = RSA.Create(2048);

        var coseKeyEncoded = EncodeUnsupportedCoseKey(keyType: 999, coseAlgorithm: -37);

        CoseHeaderMap protectedHeaders = new();
        CoseHeaderMap unprotectedHeaders = new();
        unprotectedHeaders.Add(CoseKeyHeaderContributor.CoseKeyHeaderLabel, CoseHeaderValue.FromEncodedValue(coseKeyEncoded));

        var signer = new CoseSigner(rsa, RSASignaturePadding.Pss, HashAlgorithmName.SHA256, protectedHeaders, unprotectedHeaders);
        var bytes = CoseSign1Message.SignEmbedded(new byte[] { 1, 2, 3 }, signer);
        var message = CoseSign1Message.DecodeSign1(bytes);

        var resolver = new AzureKeyVaultCoseKeySigningKeyResolver();
        var result = resolver.Resolve(message);

        Assert.That(result.IsSuccess, Is.False);
        Assert.That(result.ErrorCode, Is.EqualTo("COSE_KEY_UNSUPPORTED"));
    }

    [Test]
    public void Resolve_WithUnsupportedAlgorithmInCoseKeyHeader_ReturnsFailure()
    {
        using var rsa = RSA.Create(2048);
        var rsaParams = rsa.ExportParameters(false);

        // Unsupported COSE alg -> MapCoseHashAlgorithm throws NotSupportedException
        var coseKeyEncoded = EncodeRsaCoseKey(rsaParams, coseAlgorithm: -999, keyId: "https://myvault.vault.azure.net/keys/mykey/abc");

        CoseHeaderMap protectedHeaders = new();
        CoseHeaderMap unprotectedHeaders = new();
        unprotectedHeaders.Add(CoseKeyHeaderContributor.CoseKeyHeaderLabel, CoseHeaderValue.FromEncodedValue(coseKeyEncoded));

        var signer = new CoseSigner(rsa, RSASignaturePadding.Pss, HashAlgorithmName.SHA256, protectedHeaders, unprotectedHeaders);
        var bytes = CoseSign1Message.SignEmbedded(new byte[] { 1, 2, 3 }, signer);
        var message = CoseSign1Message.DecodeSign1(bytes);

        var resolver = new AzureKeyVaultCoseKeySigningKeyResolver();
        var result = resolver.Resolve(message);

        Assert.That(result.IsSuccess, Is.False);
        Assert.That(result.ErrorCode, Is.EqualTo("COSE_KEY_UNSUPPORTED"));
    }

    [Test]
    public void Resolve_WithEmbeddedRsaCoseKeyHeader_ResolvesAndVerifiesSignature()
    {
        using var rsa = RSA.Create(2048);

        var coseKeyEncoded = EncodeRsaCoseKey(rsa.ExportParameters(false), coseAlgorithm: -37, keyId: "https://myvault.vault.azure.net/keys/mykey/abc");

        CoseHeaderMap protectedHeaders = new();
        CoseHeaderMap unprotectedHeaders = new();
        unprotectedHeaders.Add(CoseKeyHeaderContributor.CoseKeyHeaderLabel, CoseHeaderValue.FromEncodedValue(coseKeyEncoded));

        var signer = new CoseSigner(rsa, RSASignaturePadding.Pss, HashAlgorithmName.SHA256, protectedHeaders, unprotectedHeaders);
        var bytes = CoseSign1Message.SignEmbedded(new byte[] { 1, 2, 3 }, signer);
        var message = CoseSign1Message.DecodeSign1(bytes);

        var resolver = new AzureKeyVaultCoseKeySigningKeyResolver();
        var result = resolver.Resolve(message);

        Assert.That(result.IsSuccess, Is.True);
        Assert.That(result.SigningKey, Is.Not.Null);

        using (result.SigningKey)
        {
            Assert.That(message.VerifyEmbedded(result.SigningKey!.GetCoseKey()), Is.True);
        }
    }

    [Test]
    public void Resolve_WithRsaCoseKeyHeader_PS384_Succeeds()
    {
        using var rsa = RSA.Create(2048);

        var coseKeyEncoded = EncodeRsaCoseKey(rsa.ExportParameters(false), coseAlgorithm: -38, keyId: null);

        CoseHeaderMap protectedHeaders = new();
        CoseHeaderMap unprotectedHeaders = new();
        unprotectedHeaders.Add(CoseKeyHeaderContributor.CoseKeyHeaderLabel, CoseHeaderValue.FromEncodedValue(coseKeyEncoded));

        var signer = new CoseSigner(rsa, RSASignaturePadding.Pss, HashAlgorithmName.SHA256, protectedHeaders, unprotectedHeaders);
        var bytes = CoseSign1Message.SignEmbedded(new byte[] { 1, 2, 3 }, signer);
        var message = CoseSign1Message.DecodeSign1(bytes);

        var resolver = new AzureKeyVaultCoseKeySigningKeyResolver();
        var result = resolver.Resolve(message);

        Assert.That(result.IsSuccess, Is.True);
        Assert.That(result.SigningKey, Is.Not.Null);
    }

    [Test]
    public void Resolve_WithRsaCoseKeyHeader_PS512_Succeeds()
    {
        using var rsa = RSA.Create(2048);

        var coseKeyEncoded = EncodeRsaCoseKey(rsa.ExportParameters(false), coseAlgorithm: -39, keyId: null);

        CoseHeaderMap protectedHeaders = new();
        CoseHeaderMap unprotectedHeaders = new();
        unprotectedHeaders.Add(CoseKeyHeaderContributor.CoseKeyHeaderLabel, CoseHeaderValue.FromEncodedValue(coseKeyEncoded));

        var signer = new CoseSigner(rsa, RSASignaturePadding.Pss, HashAlgorithmName.SHA256, protectedHeaders, unprotectedHeaders);
        var bytes = CoseSign1Message.SignEmbedded(new byte[] { 1, 2, 3 }, signer);
        var message = CoseSign1Message.DecodeSign1(bytes);

        var resolver = new AzureKeyVaultCoseKeySigningKeyResolver();
        var result = resolver.Resolve(message);

        Assert.That(result.IsSuccess, Is.True);
        Assert.That(result.SigningKey, Is.Not.Null);
    }

    [Test]
    public void Resolve_WithEmbeddedEc2CoseKeyHeader_ResolvesAndVerifiesSignature()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var ecParams = ecdsa.ExportParameters(false);

        var keyId = "https://myvault.vault.azure.net/keys/myec/abc";
        var coseKeyEncoded = EncodeEc2CoseKey(ecParams, coseAlgorithm: -35, keyIdBytes: Encoding.UTF8.GetBytes(keyId));

        CoseHeaderMap protectedHeaders = new();
        CoseHeaderMap unprotectedHeaders = new();
        unprotectedHeaders.Add(CoseKeyHeaderContributor.CoseKeyHeaderLabel, CoseHeaderValue.FromEncodedValue(coseKeyEncoded));

        var signer = new CoseSigner(ecdsa, HashAlgorithmName.SHA384, protectedHeaders, unprotectedHeaders);
        var bytes = CoseSign1Message.SignEmbedded(new byte[] { 1, 2, 3 }, signer);
        var message = CoseSign1Message.DecodeSign1(bytes);

        var resolver = new AzureKeyVaultCoseKeySigningKeyResolver();
        var result = resolver.Resolve(message);

        Assert.That(result.IsSuccess, Is.True);
        Assert.That(result.SigningKey, Is.Not.Null);
        Assert.That(result.KeyId, Is.EqualTo(keyId));

        using (result.SigningKey)
        {
            Assert.That(message.VerifyEmbedded(result.SigningKey!.GetCoseKey()), Is.True);
        }
    }

    [Test]
    public void Resolve_WithEc2CoseKeyHeader_ES256_P256_Succeeds()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var ecParams = ecdsa.ExportParameters(false);

        var coseKeyEncoded = EncodeEc2CoseKeyWithCurve(ecParams, coseAlgorithm: -7, coseCurve: CoseKeyHeaderContributor.CoseEllipticCurves.P256);

        CoseHeaderMap protectedHeaders = new();
        CoseHeaderMap unprotectedHeaders = new();
        unprotectedHeaders.Add(CoseKeyHeaderContributor.CoseKeyHeaderLabel, CoseHeaderValue.FromEncodedValue(coseKeyEncoded));

        var signer = new CoseSigner(ecdsa, HashAlgorithmName.SHA256, protectedHeaders, unprotectedHeaders);
        var bytes = CoseSign1Message.SignEmbedded(new byte[] { 1, 2, 3 }, signer);
        var message = CoseSign1Message.DecodeSign1(bytes);

        var resolver = new AzureKeyVaultCoseKeySigningKeyResolver();
        var result = resolver.Resolve(message);

        Assert.That(result.IsSuccess, Is.True);
        Assert.That(result.SigningKey, Is.Not.Null);
    }

    [Test]
    public void Resolve_WithEc2CoseKeyHeader_ES512_P521_Succeeds()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP521);
        var ecParams = ecdsa.ExportParameters(false);

        var coseKeyEncoded = EncodeEc2CoseKeyWithCurve(ecParams, coseAlgorithm: -36, coseCurve: CoseKeyHeaderContributor.CoseEllipticCurves.P521);

        CoseHeaderMap protectedHeaders = new();
        CoseHeaderMap unprotectedHeaders = new();
        unprotectedHeaders.Add(CoseKeyHeaderContributor.CoseKeyHeaderLabel, CoseHeaderValue.FromEncodedValue(coseKeyEncoded));

        var signer = new CoseSigner(ecdsa, HashAlgorithmName.SHA512, protectedHeaders, unprotectedHeaders);
        var bytes = CoseSign1Message.SignEmbedded(new byte[] { 1, 2, 3 }, signer);
        var message = CoseSign1Message.DecodeSign1(bytes);

        var resolver = new AzureKeyVaultCoseKeySigningKeyResolver();
        var result = resolver.Resolve(message);

        Assert.That(result.IsSuccess, Is.True);
        Assert.That(result.SigningKey, Is.Not.Null);
    }

    [Test]
    public void Resolve_WithUnsupportedCurveInEc2CoseKeyHeader_ReturnsFailure()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var ecParams = ecdsa.ExportParameters(false);

        var coseKeyEncoded = EncodeEc2CoseKeyWithCurve(ecParams, coseAlgorithm: -35, coseCurve: 999);

        CoseHeaderMap protectedHeaders = new();
        CoseHeaderMap unprotectedHeaders = new();
        unprotectedHeaders.Add(CoseKeyHeaderContributor.CoseKeyHeaderLabel, CoseHeaderValue.FromEncodedValue(coseKeyEncoded));

        var signer = new CoseSigner(ecdsa, HashAlgorithmName.SHA384, protectedHeaders, unprotectedHeaders);
        var bytes = CoseSign1Message.SignEmbedded(new byte[] { 1, 2, 3 }, signer);
        var message = CoseSign1Message.DecodeSign1(bytes);

        var resolver = new AzureKeyVaultCoseKeySigningKeyResolver();
        var result = resolver.Resolve(message);

        Assert.That(result.IsSuccess, Is.False);
        Assert.That(result.ErrorCode, Is.EqualTo("COSE_KEY_UNSUPPORTED"));
    }

    [Test]
    public void ResolveAsync_WhenCancelled_ThrowsOperationCanceledException()
    {
        var resolver = new AzureKeyVaultCoseKeySigningKeyResolver();

        using var rsa = RSA.Create(2048);
        var signer = new CoseSigner(rsa, RSASignaturePadding.Pss, HashAlgorithmName.SHA256);
        var bytes = CoseSign1Message.SignEmbedded(new byte[] { 1, 2, 3 }, signer);
        var message = CoseSign1Message.DecodeSign1(bytes);

        using var cts = new CancellationTokenSource();
        cts.Cancel();

        Assert.That(async () => await resolver.ResolveAsync(message, cts.Token), Throws.InstanceOf<OperationCanceledException>());
    }

    [Test]
    public void Resolve_WithProtectedCoseKeyHeader_Succeeds()
    {
        using var rsa = RSA.Create(2048);
        var rsaParams = rsa.ExportParameters(false);

        var valid = EncodeRsaCoseKey(rsaParams, coseAlgorithm: -37, keyId: null);

        CoseHeaderMap protectedHeaders = new();
        CoseHeaderMap unprotectedHeaders = new();
        protectedHeaders.Add(CoseKeyHeaderContributor.CoseKeyHeaderLabel, CoseHeaderValue.FromEncodedValue(valid));

        var signer = new CoseSigner(rsa, RSASignaturePadding.Pss, HashAlgorithmName.SHA256, protectedHeaders, unprotectedHeaders);
        var bytes = CoseSign1Message.SignEmbedded(new byte[] { 1, 2, 3 }, signer);
        var message = CoseSign1Message.DecodeSign1(bytes);

        var resolver = new AzureKeyVaultCoseKeySigningKeyResolver();
        var result = resolver.Resolve(message);

        Assert.That(result.IsSuccess, Is.True);
    }

    [Test]
    public void Resolve_ReturnedSigningKey_IsIdempotentlyDisposable_AndThrowsWhenUsedAfterDispose()
    {
        using var rsa = RSA.Create(2048);

        var coseKeyEncoded = EncodeRsaCoseKey(rsa.ExportParameters(false), coseAlgorithm: -37, keyId: "kid");

        CoseHeaderMap protectedHeaders = new();
        CoseHeaderMap unprotectedHeaders = new();
        unprotectedHeaders.Add(CoseKeyHeaderContributor.CoseKeyHeaderLabel, CoseHeaderValue.FromEncodedValue(coseKeyEncoded));

        var signer = new CoseSigner(rsa, RSASignaturePadding.Pss, HashAlgorithmName.SHA256, protectedHeaders, unprotectedHeaders);
        var bytes = CoseSign1Message.SignEmbedded(new byte[] { 1, 2, 3 }, signer);
        var message = CoseSign1Message.DecodeSign1(bytes);

        var resolver = new AzureKeyVaultCoseKeySigningKeyResolver();
        var result = resolver.Resolve(message);

        Assert.That(result.IsSuccess, Is.True);
        Assert.That(result.SigningKey, Is.Not.Null);

        var signingKey = result.SigningKey!;
        signingKey.Dispose();
        Assert.That(() => signingKey.Dispose(), Throws.Nothing);
        Assert.That(() => signingKey.GetCoseKey(), Throws.InstanceOf<ObjectDisposedException>());
    }

    [Test]
    public void Resolve_WithRsaKidAsUnexpectedType_SkipsKidAndStillResolves()
    {
        using var rsa = RSA.Create(2048);
        var rsaParams = rsa.ExportParameters(false);

        var coseKeyEncoded = EncodeRsaCoseKeyWithKidAsInt(rsaParams, coseAlgorithm: -37, kidInt: 123);

        CoseHeaderMap protectedHeaders = new();
        CoseHeaderMap unprotectedHeaders = new();
        unprotectedHeaders.Add(CoseKeyHeaderContributor.CoseKeyHeaderLabel, CoseHeaderValue.FromEncodedValue(coseKeyEncoded));

        var signer = new CoseSigner(rsa, RSASignaturePadding.Pss, HashAlgorithmName.SHA256, protectedHeaders, unprotectedHeaders);
        var bytes = CoseSign1Message.SignEmbedded(new byte[] { 1, 2, 3 }, signer);
        var message = CoseSign1Message.DecodeSign1(bytes);

        var resolver = new AzureKeyVaultCoseKeySigningKeyResolver();
        var result = resolver.Resolve(message);

        Assert.That(result.IsSuccess, Is.True);
        Assert.That(result.KeyId, Is.Null);
    }

    [Test]
    public void Resolve_WithUnknownLabel_IgnoresItAndStillResolves()
    {
        using var rsa = RSA.Create(2048);
        var rsaParams = rsa.ExportParameters(false);

        var coseKeyEncoded = EncodeRsaCoseKeyWithUnknownLabel(rsaParams, coseAlgorithm: -37);

        CoseHeaderMap protectedHeaders = new();
        CoseHeaderMap unprotectedHeaders = new();
        unprotectedHeaders.Add(CoseKeyHeaderContributor.CoseKeyHeaderLabel, CoseHeaderValue.FromEncodedValue(coseKeyEncoded));

        var signer = new CoseSigner(rsa, RSASignaturePadding.Pss, HashAlgorithmName.SHA256, protectedHeaders, unprotectedHeaders);
        var bytes = CoseSign1Message.SignEmbedded(new byte[] { 1, 2, 3 }, signer);
        var message = CoseSign1Message.DecodeSign1(bytes);

        var resolver = new AzureKeyVaultCoseKeySigningKeyResolver();
        var result = resolver.Resolve(message);

        Assert.That(result.IsSuccess, Is.True);
    }

    [Test]
    public void Resolve_WithRsaModulusWrongCborType_ReturnsInvalid()
    {
        using var rsa = RSA.Create(2048);
        var rsaParams = rsa.ExportParameters(false);

        var coseKeyEncoded = EncodeRsaCoseKeyWithWrongTypes(rsaParams, coseAlgorithm: -37);

        CoseHeaderMap protectedHeaders = new();
        CoseHeaderMap unprotectedHeaders = new();
        unprotectedHeaders.Add(CoseKeyHeaderContributor.CoseKeyHeaderLabel, CoseHeaderValue.FromEncodedValue(coseKeyEncoded));

        var signer = new CoseSigner(rsa, RSASignaturePadding.Pss, HashAlgorithmName.SHA256, protectedHeaders, unprotectedHeaders);
        var bytes = CoseSign1Message.SignEmbedded(new byte[] { 1, 2, 3 }, signer);
        var message = CoseSign1Message.DecodeSign1(bytes);

        var resolver = new AzureKeyVaultCoseKeySigningKeyResolver();
        var result = resolver.Resolve(message);

        Assert.That(result.IsSuccess, Is.False);
        Assert.That(result.ErrorCode, Is.EqualTo("COSE_KEY_INVALID"));
    }

    [Test]
    public void Resolve_WithMissingKeyTypeOrAlgorithm_ReturnsInvalid()
    {
        using var rsa = RSA.Create(2048);
        var rsaParams = rsa.ExportParameters(false);

        var missingAlg = EncodeRsaCoseKeyMissingAlgorithm(rsaParams);

        CoseHeaderMap protectedHeaders = new();
        CoseHeaderMap unprotectedHeaders = new();
        unprotectedHeaders.Add(CoseKeyHeaderContributor.CoseKeyHeaderLabel, CoseHeaderValue.FromEncodedValue(missingAlg));

        var signer = new CoseSigner(rsa, RSASignaturePadding.Pss, HashAlgorithmName.SHA256, protectedHeaders, unprotectedHeaders);
        var bytes = CoseSign1Message.SignEmbedded(new byte[] { 1, 2, 3 }, signer);
        var message = CoseSign1Message.DecodeSign1(bytes);

        var resolver = new AzureKeyVaultCoseKeySigningKeyResolver();
        var result = resolver.Resolve(message);

        Assert.That(result.IsSuccess, Is.False);
        Assert.That(result.ErrorCode, Is.EqualTo("COSE_KEY_INVALID"));
    }

    [Test]
    public void Resolve_WithRsaMissingExponent_ReturnsInvalid()
    {
        using var rsa = RSA.Create(2048);
        var rsaParams = rsa.ExportParameters(false);

        var coseKeyEncoded = EncodeRsaCoseKeyMissingExponent(rsaParams, coseAlgorithm: -37);

        CoseHeaderMap protectedHeaders = new();
        CoseHeaderMap unprotectedHeaders = new();
        unprotectedHeaders.Add(CoseKeyHeaderContributor.CoseKeyHeaderLabel, CoseHeaderValue.FromEncodedValue(coseKeyEncoded));

        var signer = new CoseSigner(rsa, RSASignaturePadding.Pss, HashAlgorithmName.SHA256, protectedHeaders, unprotectedHeaders);
        var bytes = CoseSign1Message.SignEmbedded(new byte[] { 1, 2, 3 }, signer);
        var message = CoseSign1Message.DecodeSign1(bytes);

        var resolver = new AzureKeyVaultCoseKeySigningKeyResolver();
        var result = resolver.Resolve(message);

        Assert.That(result.IsSuccess, Is.False);
        Assert.That(result.ErrorCode, Is.EqualTo("COSE_KEY_INVALID"));
    }

    private static byte[] EncodeRsaCoseKey(RSAParameters rsaParams, int coseAlgorithm, string? keyId)
    {
        var writer = new CborWriter();

        int mapSize = keyId != null ? 5 : 4;
        writer.WriteStartMap(mapSize);

        writer.WriteInt32(CoseKeyHeaderContributor.CoseKeyLabels.KeyType);
        writer.WriteInt32(CoseKeyHeaderContributor.CoseKeyTypes.RSA);

        if (keyId != null)
        {
            writer.WriteInt32(CoseKeyHeaderContributor.CoseKeyLabels.KeyId);
            writer.WriteTextString(keyId);
        }

        writer.WriteInt32(CoseKeyHeaderContributor.CoseKeyLabels.Algorithm);
        writer.WriteInt32(coseAlgorithm);

        writer.WriteInt32(CoseKeyHeaderContributor.RSALabels.N);
        writer.WriteByteString(rsaParams.Modulus!);

        writer.WriteInt32(CoseKeyHeaderContributor.RSALabels.E);
        writer.WriteByteString(rsaParams.Exponent!);

        writer.WriteEndMap();
        return writer.Encode();
    }

    private static byte[] EncodeEc2CoseKey(ECParameters ecParams, int coseAlgorithm, byte[]? keyIdBytes)
    {
        var writer = new CborWriter();

        int mapSize = keyIdBytes != null ? 6 : 5;
        writer.WriteStartMap(mapSize);

        writer.WriteInt32(CoseKeyHeaderContributor.CoseKeyLabels.KeyType);
        writer.WriteInt32(CoseKeyHeaderContributor.CoseKeyTypes.EC2);

        if (keyIdBytes != null)
        {
            writer.WriteInt32(CoseKeyHeaderContributor.CoseKeyLabels.KeyId);
            writer.WriteByteString(keyIdBytes);
        }

        writer.WriteInt32(CoseKeyHeaderContributor.CoseKeyLabels.Algorithm);
        writer.WriteInt32(coseAlgorithm);

        writer.WriteInt32(CoseKeyHeaderContributor.EC2Labels.Curve);
        writer.WriteInt32(CoseKeyHeaderContributor.CoseEllipticCurves.P384);

        writer.WriteInt32(CoseKeyHeaderContributor.EC2Labels.X);
        writer.WriteByteString(ecParams.Q.X!);

        writer.WriteInt32(CoseKeyHeaderContributor.EC2Labels.Y);
        writer.WriteByteString(ecParams.Q.Y!);

        writer.WriteEndMap();
        return writer.Encode();
    }

    private static byte[] EncodeEc2CoseKeyWithCurve(ECParameters ecParams, int coseAlgorithm, int coseCurve)
    {
        var writer = new CborWriter();

        writer.WriteStartMap(5);

        writer.WriteInt32(CoseKeyHeaderContributor.CoseKeyLabels.KeyType);
        writer.WriteInt32(CoseKeyHeaderContributor.CoseKeyTypes.EC2);

        writer.WriteInt32(CoseKeyHeaderContributor.CoseKeyLabels.Algorithm);
        writer.WriteInt32(coseAlgorithm);

        writer.WriteInt32(CoseKeyHeaderContributor.EC2Labels.Curve);
        writer.WriteInt32(coseCurve);

        writer.WriteInt32(CoseKeyHeaderContributor.EC2Labels.X);
        writer.WriteByteString(ecParams.Q.X!);

        writer.WriteInt32(CoseKeyHeaderContributor.EC2Labels.Y);
        writer.WriteByteString(ecParams.Q.Y!);

        writer.WriteEndMap();
        return writer.Encode();
    }

    private static byte[] EncodeUnsupportedCoseKey(int keyType, int coseAlgorithm)
    {
        var writer = new CborWriter();
        writer.WriteStartMap(2);
        writer.WriteInt32(CoseKeyHeaderContributor.CoseKeyLabels.KeyType);
        writer.WriteInt32(keyType);
        writer.WriteInt32(CoseKeyHeaderContributor.CoseKeyLabels.Algorithm);
        writer.WriteInt32(coseAlgorithm);
        writer.WriteEndMap();
        return writer.Encode();
    }

    private static byte[] EncodeRsaCoseKeyWithKidAsInt(RSAParameters rsaParams, int coseAlgorithm, int kidInt)
    {
        var writer = new CborWriter();

        writer.WriteStartMap(5);

        writer.WriteInt32(CoseKeyHeaderContributor.CoseKeyLabels.KeyType);
        writer.WriteInt32(CoseKeyHeaderContributor.CoseKeyTypes.RSA);

        writer.WriteInt32(CoseKeyHeaderContributor.CoseKeyLabels.KeyId);
        writer.WriteInt32(kidInt);

        writer.WriteInt32(CoseKeyHeaderContributor.CoseKeyLabels.Algorithm);
        writer.WriteInt32(coseAlgorithm);

        writer.WriteInt32(CoseKeyHeaderContributor.RSALabels.N);
        writer.WriteByteString(rsaParams.Modulus!);

        writer.WriteInt32(CoseKeyHeaderContributor.RSALabels.E);
        writer.WriteByteString(rsaParams.Exponent!);

        writer.WriteEndMap();
        return writer.Encode();
    }

    private static byte[] EncodeRsaCoseKeyWithUnknownLabel(RSAParameters rsaParams, int coseAlgorithm)
    {
        var writer = new CborWriter();

        writer.WriteStartMap(5);

        writer.WriteInt32(CoseKeyHeaderContributor.CoseKeyLabels.KeyType);
        writer.WriteInt32(CoseKeyHeaderContributor.CoseKeyTypes.RSA);

        // Unknown label should be ignored.
        writer.WriteInt32(999);
        writer.WriteTextString("ignored");

        writer.WriteInt32(CoseKeyHeaderContributor.CoseKeyLabels.Algorithm);
        writer.WriteInt32(coseAlgorithm);

        writer.WriteInt32(CoseKeyHeaderContributor.RSALabels.N);
        writer.WriteByteString(rsaParams.Modulus!);

        writer.WriteInt32(CoseKeyHeaderContributor.RSALabels.E);
        writer.WriteByteString(rsaParams.Exponent!);

        writer.WriteEndMap();
        return writer.Encode();
    }

    private static byte[] EncodeRsaCoseKeyWithWrongTypes(RSAParameters rsaParams, int coseAlgorithm)
    {
        var writer = new CborWriter();

        // Intentionally use wrong CBOR types for -1 (n) and -2 (e) to exercise SkipValue branches.
        writer.WriteStartMap(4);

        writer.WriteInt32(CoseKeyHeaderContributor.CoseKeyLabels.KeyType);
        writer.WriteInt32(CoseKeyHeaderContributor.CoseKeyTypes.RSA);

        writer.WriteInt32(CoseKeyHeaderContributor.CoseKeyLabels.Algorithm);
        writer.WriteInt32(coseAlgorithm);

        writer.WriteInt32(CoseKeyHeaderContributor.RSALabels.N);
        writer.WriteTextString("not-bytes");

        writer.WriteInt32(CoseKeyHeaderContributor.RSALabels.E);
        writer.WriteInt32(65537);

        writer.WriteEndMap();
        return writer.Encode();
    }

    private static byte[] EncodeRsaCoseKeyMissingAlgorithm(RSAParameters rsaParams)
    {
        var writer = new CborWriter();
        writer.WriteStartMap(3);

        writer.WriteInt32(CoseKeyHeaderContributor.CoseKeyLabels.KeyType);
        writer.WriteInt32(CoseKeyHeaderContributor.CoseKeyTypes.RSA);

        writer.WriteInt32(CoseKeyHeaderContributor.RSALabels.N);
        writer.WriteByteString(rsaParams.Modulus!);

        writer.WriteInt32(CoseKeyHeaderContributor.RSALabels.E);
        writer.WriteByteString(rsaParams.Exponent!);

        writer.WriteEndMap();
        return writer.Encode();
    }

    private static byte[] EncodeRsaCoseKeyMissingExponent(RSAParameters rsaParams, int coseAlgorithm)
    {
        var writer = new CborWriter();

        writer.WriteStartMap(3);

        writer.WriteInt32(CoseKeyHeaderContributor.CoseKeyLabels.KeyType);
        writer.WriteInt32(CoseKeyHeaderContributor.CoseKeyTypes.RSA);

        writer.WriteInt32(CoseKeyHeaderContributor.CoseKeyLabels.Algorithm);
        writer.WriteInt32(coseAlgorithm);

        writer.WriteInt32(CoseKeyHeaderContributor.RSALabels.N);
        writer.WriteByteString(rsaParams.Modulus!);

        writer.WriteEndMap();
        return writer.Encode();
    }
}
