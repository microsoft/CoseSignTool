// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.MST.Plugin.Tests;

using System.CommandLine;
using System.CommandLine.Parsing;
using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using System.Text;
using System.Text.Json;
using CoseSign1.Transparent.MST.Extensions;
using CoseSign1.Transparent.MST.Trust;
using CoseSign1.Validation.Trust;
using CoseSign1.Validation.Trust.Engine;
using CoseSign1.Validation.Trust.Plan;
using CoseSign1.Validation.Trust.Subjects;
using CoseSignTool.Abstractions;
using Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Tests for <see cref="MstVerificationProvider" />.
/// </summary>
[TestFixture]
public class MstVerificationProviderTests
{
    [Test]
    public void CreateTrustPlanPolicy_WithNullParseResult_ThrowsArgumentNullException()
    {
        var provider = new MstVerificationProvider();
        var context = new VerificationContext(detachedPayload: null);

        Assert.Throws<ArgumentNullException>(() => provider.CreateTrustPlanPolicy(null!, context));
    }

    [Test]
    public void CreateTrustPlanPolicy_WhenMstRootSelectedWithLedgerAllowList_ReturnsNonNull()
    {
        var provider = new MstVerificationProvider();
        var parseResult = CreateParseResult(provider, [
            "verify",
            "mst",
            "--mst-trust-ledger-instance",
            "esrp-cts-cp.confidential-ledger.azure.com"
        ]);

        var context = new VerificationContext(detachedPayload: null);
        var policy = provider.CreateTrustPlanPolicy(parseResult, context);

        Assert.That(policy, Is.Not.Null);
    }

    [Test]
    public void CreateTrustPlanPolicy_WhenMstRootSelectedButNoAllowListOrOfflineKeys_ThrowsArgumentException()
    {
        var provider = new MstVerificationProvider();
        var parseResult = CreateParseResult(provider, [
            "verify",
            "mst"
        ]);

        var context = new VerificationContext(detachedPayload: null);
        Assert.Throws<ArgumentException>(() => provider.CreateTrustPlanPolicy(parseResult, context));
    }

    [Test]
    public void CreateTrustPlanPolicy_WhenMstTrustNotEnabled_ReturnsNull()
    {
        var provider = new MstVerificationProvider();
        var parseResult = CreateParseResult(provider, [
            "verify"
        ]);

        var context = new VerificationContext(detachedPayload: null);
        var policy = provider.CreateTrustPlanPolicy(parseResult, context);

        Assert.That(policy, Is.Null);
    }

    [Test]
    public void ConfigureValidation_WhenOfflineKeysFileDoesNotExist_ThrowsArgumentException()
    {
        var provider = new MstVerificationProvider();

        var trustFilePath = Path.Combine(Path.GetTempPath(), $"mst-offline-{Guid.NewGuid():N}.jwks.json");
        var parseResult = CreateParseResult(provider, [
            "verify",
            "mst",
            "--mst-offline-keys",
            trustFilePath
        ]);

        var context = new VerificationContext(detachedPayload: null);

        var services = new ServiceCollection();
        var builder = services.ConfigureCoseValidation();

        Assert.Throws<ArgumentException>(() => provider.ConfigureValidation(builder, parseResult, context));
    }

    [Test]
    public void ConfigureValidation_WhenMstRootNotSelected_DoesNotThrowWithoutConfiguration()
    {
        var provider = new MstVerificationProvider();
        var parseResult = CreateParseResult(provider, [
            "verify"
        ]);

        var context = new VerificationContext(detachedPayload: null);

        var services = new ServiceCollection();
        var builder = services.ConfigureCoseValidation();

        Assert.DoesNotThrow(() => provider.ConfigureValidation(builder, parseResult, context));
    }

    [Test]
    public async Task ConfigureValidation_WhenOfflineKeysProvided_TrustedFactIsNotMissingOfflineKeys()
    {
        var provider = new MstVerificationProvider();

        var tempDir = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), $"mst-{Guid.NewGuid():N}"));
        try
        {
            var jwksPath = Path.Combine(tempDir.FullName, "keys.jwks.json");

            var rsaJwk = CreateRsaPublicJwkJsonElement();
            File.WriteAllText(jwksPath, JsonSerializer.Serialize(new { keys = new[] { rsaJwk } }), Encoding.UTF8);

            var parseResult = CreateParseResult(provider, [
                "verify",
                "mst",
                "--mst-offline-keys",
                jwksPath,
            ]);

            var context = new VerificationContext(detachedPayload: null);

            var services = new ServiceCollection();
            var builder = services.ConfigureCoseValidation();
            provider.ConfigureValidation(builder, parseResult, context);

            using var sp = services.BuildServiceProvider();
            var pack = sp.GetServices<ITrustPack>().Single(p => p is MstTrustPack);

            var message = CreateMessageWithEmptyReceiptHeader();
            var messageSubject = TrustSubject.Message(message);
            var receiptBytes = message.GetMstReceiptBytes().Single();
            var subject = TrustSubject.CounterSignature(messageSubject.Id, receiptBytes);
            var factContext = new TrustFactContext(subject.Id, subject, new TrustEvaluationOptions(), memoryCache: null, message);

            var facts = await pack.ProduceAsync(factContext, typeof(MstReceiptTrustedFact), CancellationToken.None);
            Assert.That(facts.IsMissing, Is.False);
        }
        finally
        {
            if (tempDir.Exists)
            {
                tempDir.Delete(recursive: true);
            }
        }
    }

    [Test]
    public void GetVerificationMetadata_WhenMstTrustEnabled_IncludesExpectedKeys()
    {
        var provider = new MstVerificationProvider();
        var parseResult = CreateParseResult(provider, [
            "verify",
            "mst",
            "--mst-trust-ledger-instance",
            "esrp-cts-cp.confidential-ledger.azure.com"
        ]);

        var metadata = provider.GetVerificationMetadata(parseResult, message: null!, validationResult: null!);

        Assert.That(metadata, Does.ContainKey("MST Trust"));
    }

    [Test]
    public void GetVerificationMetadata_WhenMstRootNotSelected_ReportsDisabled()
    {
        var provider = new MstVerificationProvider();
        var parseResult = CreateParseResult(provider, [
            "verify"
        ]);

        var metadata = provider.GetVerificationMetadata(parseResult, message: null!, validationResult: null!);

        Assert.That(metadata, Does.ContainKey("MST Trust"));
        Assert.That(metadata["MST Trust"], Is.EqualTo("No"));
        Assert.That(metadata.Keys, Has.Count.EqualTo(1));
    }

    [Test]
    public void GetVerificationMetadata_WhenOfflineKeysAliasProvided_IncludesOfflineKeyPath()
    {
        var provider = new MstVerificationProvider();

        var tempDir = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), $"mst-{Guid.NewGuid():N}"));
        try
        {
            var jwksPath = Path.Combine(tempDir.FullName, "keys.jwks.json");
            File.WriteAllText(jwksPath, "{\"keys\":[]}", Encoding.UTF8);

            var parseResult = CreateParseResult(provider, [
                "verify",
                "mst",
                "--offline_keys",
                jwksPath,
                "--mst-trust-ledger-instance",
                "https://example.contoso/ledger",
                "--mst-trust-ledger-instance",
                "example.contoso",
                "--mst-trust-ledger-instance",
                "  ",
                "--mst-trust-ledger-instance",
                "other.contoso",
            ]);

            var metadata = provider.GetVerificationMetadata(parseResult, message: null!, validationResult: null!);

            Assert.That(metadata["MST Trust"], Is.EqualTo("Yes"));
            Assert.That(metadata["MST Offline Keys"], Is.EqualTo(jwksPath));
            Assert.That(metadata["MST Trusted Ledgers"], Is.EqualTo("example.contoso, other.contoso"));
        }
        finally
        {
            if (tempDir.Exists)
            {
                tempDir.Delete(recursive: true);
            }
        }
    }

    private static ParseResult CreateParseResult(MstVerificationProvider provider, string[] args)
    {
        var root = new RootCommand("root");
        var verify = new Command("verify");
        var mst = new Command("mst");
        provider.AddVerificationOptions(mst);
        verify.AddCommand(mst);
        root.AddCommand(verify);

        return root.Parse(args);
    }

    private static JsonElement CreateRsaPublicJwkJsonElement()
    {
        using var rsa = RSA.Create(2048);
        var parameters = rsa.ExportParameters(includePrivateParameters: false);

        var jwk = new
        {
            kty = "RSA",
            n = Base64UrlEncode(parameters.Modulus!),
            e = Base64UrlEncode(parameters.Exponent!),
        };

        using var doc = JsonDocument.Parse(JsonSerializer.Serialize(jwk));
        return doc.RootElement.Clone();
    }

    private static string Base64UrlEncode(byte[] bytes)
    {
        return Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    private static string WriteTempFile(string dir, string fileName, string contents)
    {
        var path = Path.Combine(dir, fileName);
        File.WriteAllText(path, contents, Encoding.UTF8);
        return path;
    }

    private static CoseSign1Message CreateMessageWithEmptyReceiptHeader()
    {
        using var key = ECDsa.Create();
        var payload = "payload"u8.ToArray();

        var protectedHeaders = new CoseHeaderMap();
        var unprotectedHeaders = new CoseHeaderMap();
        unprotectedHeaders[new CoseHeaderLabel(394)] = CborValue(writer =>
        {
            // MST receipt header is an array of COSE_Sign1 byte strings.
            // Include a single empty receipt entry so counter-signature scoped facts can be exercised.
            writer.WriteStartArray(1);
            writer.WriteByteString(Array.Empty<byte>());
            writer.WriteEndArray();
        });

        var signer = new CoseSigner(key, HashAlgorithmName.SHA256, protectedHeaders, unprotectedHeaders);
        var encoded = CoseSign1Message.SignEmbedded(payload, signer);
        return CoseSign1Message.DecodeSign1(encoded);
    }

    private static CoseHeaderValue CborValue(Action<CborWriter> write)
    {
        var writer = new CborWriter();
        write(writer);
        return CoseHeaderValue.FromEncodedValue(writer.Encode());
    }
}
