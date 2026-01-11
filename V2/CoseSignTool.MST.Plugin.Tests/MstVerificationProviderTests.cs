// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.MST.Plugin.Tests;

using System.CommandLine;
using System.CommandLine.Parsing;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using CoseSign1.Transparent.MST.Validation;
using CoseSignTool.Abstractions;

/// <summary>
/// Tests for <see cref="MstVerificationProvider" />.
/// </summary>
[TestFixture]
public class MstVerificationProviderTests
{
    [Test]
    public void CreateTrustPolicy_WithNullParseResult_ThrowsArgumentNullException()
    {
        var provider = new MstVerificationProvider();
        var context = new VerificationContext(detachedPayload: null);

        Assert.Throws<ArgumentNullException>(() => provider.CreateTrustPolicy(null!, context));
    }

    [Test]
    public void CreateTrustPolicy_WhenRequireReceiptAndVerifyReceipt_ReturnsRequireReceiptPresentAndTrusted()
    {
        var provider = new MstVerificationProvider();
        var parseResult = CreateParseResult(provider, [
            "verify",
            "--require-receipt",
            "--verify-receipt",
            "true"
        ]);

        var context = new VerificationContext(detachedPayload: null);
        var policy = provider.CreateTrustPolicy(parseResult, context);

        Assert.That(policy, Is.Not.Null);
    }

    [Test]
    public void CreateTrustPolicy_WhenRequireReceiptButNotVerifyReceipt_ReturnsRequireReceiptPresent()
    {
        var provider = new MstVerificationProvider();
        var parseResult = CreateParseResult(provider, [
            "verify",
            "--require-receipt",
            "--verify-receipt",
            "false"
        ]);

        var context = new VerificationContext(detachedPayload: null);
        var policy = provider.CreateTrustPolicy(parseResult, context);

        Assert.That(policy, Is.Not.Null);
    }

    [Test]
    public void CreateTrustPolicy_WhenNotRequiringReceipt_ReturnsNull()
    {
        var provider = new MstVerificationProvider();
        var parseResult = CreateParseResult(provider, [
            "verify",
            "--verify-receipt",
            "true"
        ]);

        var context = new VerificationContext(detachedPayload: null);
        var policy = provider.CreateTrustPolicy(parseResult, context);

        Assert.That(policy, Is.Null);
    }

    [Test]
    public void CreateValidators_OfflineTrustFileDoesNotExist_ReturnsPresenceOnly()
    {
        var provider = new MstVerificationProvider();

        var trustFilePath = Path.Combine(Path.GetTempPath(), $"mst-trust-{Guid.NewGuid():N}.json");
        var parseResult = CreateParseResult(provider, [
            "verify",
            "--mst-endpoint",
            "https://mst.example.com",
            "--mst-trust-mode",
            "offline",
            "--mst-trust-file",
            trustFilePath,
            "--verify-receipt",
            "true"
        ]);

        var validators = provider.CreateValidators(parseResult).ToList();

        Assert.That(validators.OfType<MstReceiptPresenceAssertionProvider>().Count(), Is.EqualTo(1));
        Assert.That(validators.OfType<MstReceiptAssertionProvider>().Any(), Is.False);
    }

    [Test]
    public void CreateValidators_OfflineTrustKeysWithMixedEntries_ReturnsPresenceAndOfflineReceiptValidator()
    {
        var provider = new MstVerificationProvider();

        var tempDir = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), $"mst-{Guid.NewGuid():N}"));
        try
        {
            var jwkPath = Path.Combine(tempDir.FullName, "key.jwk.json");
            var jwksPath = Path.Combine(tempDir.FullName, "keys.jwks.json");

            var rsaJwk = CreateRsaPublicJwkJsonElement();

            File.WriteAllText(jwkPath, rsaJwk.GetRawText(), Encoding.UTF8);
            File.WriteAllText(jwksPath, JsonSerializer.Serialize(new { keys = new[] { rsaJwk } }), Encoding.UTF8);

            var parseResult = CreateParseResult(provider, [
                "verify",
                "--mst-endpoint",
                "https://mst.example.com",
                "--mst-trust-mode",
                "offline",
                "--verify-receipt",
                "true",

                // Invalid entries (should be skipped)
                "--mst-trusted-key",
                "noequal",
                "--mst-trusted-key",
                "=C:\\nonexistent\\file.json",
                "--mst-trusted-key",
                "mst.example.com=",

                // Valid entries
                "--mst-trusted-key",
                $"https://mst.example.com={jwksPath}",
                "--mst-trusted-key",
                $"   mst.example.com   ={jwkPath}",

                // Valid issuer but missing file (skipped)
                "--mst-trusted-key",
                $"mst.example.com={Path.Combine(tempDir.FullName, "missing.json")}",

                // Non-object JSON (skipped)
                "--mst-trusted-key",
                $"mst.example.com={WriteTempFile(tempDir.FullName, "array.json", "[]")}",

                // Object with keys not array (skipped)
                "--mst-trusted-key",
                $"mst.example.com={WriteTempFile(tempDir.FullName, "bad-keys.json", "{\"keys\":123}")}",
            ]);

            var validators = provider.CreateValidators(parseResult).ToList();

            Assert.That(validators.OfType<MstReceiptPresenceAssertionProvider>().Count(), Is.EqualTo(1));
            Assert.That(validators.OfType<MstReceiptAssertionProvider>().Count(), Is.EqualTo(1));
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
    public void GetVerificationMetadata_WhenEndpointProvided_IncludesExpectedKeys()
    {
        var provider = new MstVerificationProvider();
        var parseResult = CreateParseResult(provider, [
            "verify",
            "--require-receipt",
            "--mst-endpoint",
            "https://mst.example.com",
            "--verify-receipt",
            "false"
        ]);

        var metadata = provider.GetVerificationMetadata(parseResult, message: null!, validationResult: null!);

        Assert.That(metadata, Does.ContainKey("Receipt Required"));
        Assert.That(metadata, Does.ContainKey("MST Endpoint"));
        Assert.That(metadata, Does.ContainKey("Verify Receipt"));
    }

    private static ParseResult CreateParseResult(MstVerificationProvider provider, string[] args)
    {
        var root = new RootCommand("root");
        var verify = new Command("verify");
        provider.AddVerificationOptions(verify);
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
}
