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
    public void IsApplicableTo_WithCoseKeyHeader_ReturnsTrue()
    {
        using var rsa = RSA.Create(2048);

        var coseKeyEncoded = EncodeRsaCoseKey(rsa.ExportParameters(false), coseAlgorithm: -37, keyId: null);

        CoseHeaderMap protectedHeaders = new();
        CoseHeaderMap unprotectedHeaders = new();
        unprotectedHeaders.Add(CoseKeyHeaderContributor.CoseKeyHeaderLabel, CoseHeaderValue.FromEncodedValue(coseKeyEncoded));

        var signer = new CoseSigner(rsa, RSASignaturePadding.Pss, HashAlgorithmName.SHA256, protectedHeaders, unprotectedHeaders);
        var bytes = CoseSign1Message.SignEmbedded(new byte[] { 1, 2, 3 }, signer);
        var message = CoseSign1Message.DecodeSign1(bytes);

        var resolver = new AzureKeyVaultCoseKeySigningKeyResolver();
        Assert.That(resolver.IsApplicableTo(message), Is.True);
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
}
