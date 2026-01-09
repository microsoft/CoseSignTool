// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.MST.Plugin.Tests;

using System.CommandLine;
using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using CoseSign1.Tests.Common;
using CoseSign1.Transparent.MST.Validation;
using CoseSign1.Validation;
using CoseSign1.Validation.Results;
using CoseSignTool.Abstractions;

[TestFixture]
public class MstVerificationProviderTests
{
    private static X509Certificate2 CreateTestCertificate()
        => TestCertificateUtils.CreateCertificate(nameof(MstVerificationProviderTests), useEcc: true);

    [Test]
    public void IsActivated_WithNoMstArgs_ReturnsFalse()
    {
        var provider = new MstVerificationProvider();
        var parse = Parse(provider, Array.Empty<string>());

        Assert.That(provider.IsActivated(parse), Is.False);
    }

    [Test]
    public void IsActivated_WithRequireReceipt_ReturnsTrue()
    {
        var provider = new MstVerificationProvider();
        var parse = Parse(provider, new[] { "--require-receipt" });

        Assert.That(provider.IsActivated(parse), Is.True);
    }

    [Test]
    public void CreateValidators_WhenRequireReceiptButNoEndpoint_ReturnsPresenceValidatorOnly()
    {
        var provider = new MstVerificationProvider();
        var parse = Parse(provider, new[] { "--require-receipt" });

        var validators = provider.CreateValidators(parse).ToList();

        Assert.That(validators, Has.Count.EqualTo(1));
        Assert.That(validators[0], Is.InstanceOf<MstReceiptPresenceTrustValidator>());
    }

    [Test]
    public void CreateTrustPolicy_WhenRequireReceiptAndVerifyReceiptDefault_ReturnsRequirePresentAndTrusted()
    {
        var provider = new MstVerificationProvider();
        var parse = Parse(provider, new[] { "--require-receipt" });

        var policy = provider.CreateTrustPolicy(parse, new VerificationContext(detachedPayload: null));
        Assert.That(policy, Is.Not.Null);

        Assert.That(policy!.IsSatisfied(new Dictionary<string, bool>()), Is.False);
    }

    [Test]
    public void CreateTrustPolicy_WhenRequireReceiptButVerifyReceiptFalse_ReturnsRequirePresentOnly()
    {
        var provider = new MstVerificationProvider();
        var parse = Parse(provider, new[] { "--require-receipt", "--verify-receipt", "false" });

        var policy = provider.CreateTrustPolicy(parse, new VerificationContext(detachedPayload: null));
        Assert.That(policy, Is.Not.Null);

        Assert.That(policy!.IsSatisfied(new Dictionary<string, bool>
        {
            [MstTrustClaims.ReceiptPresent] = true,
            [MstTrustClaims.ReceiptTrusted] = false
        }), Is.True);
    }

    [Test]
    public void CreateValidators_WhenEndpointProvided_DefaultsToOnlineAndAddsOnlineValidator()
    {
        var provider = new MstVerificationProvider();
        var parse = Parse(provider, new[] { "--mst-endpoint", "https://example.test" });

        var validators = provider.CreateValidators(parse).ToList();

        Assert.That(validators.Any(v => v is MstReceiptPresenceTrustValidator), Is.True);
        Assert.That(validators.Any(v => v is MstReceiptOnlineValidator), Is.True);
    }

    [Test]
    public void CreateValidators_WhenOfflineModeWithoutOfflineKeys_ReturnsPresenceValidatorOnly()
    {
        var provider = new MstVerificationProvider();
        var parse = Parse(provider, new[] { "--mst-endpoint", "https://example.test", "--mst-trust-mode", "offline" });

        var validators = provider.CreateValidators(parse).ToList();

        Assert.That(validators, Has.Count.EqualTo(1));
        Assert.That(validators[0], Is.InstanceOf<MstReceiptPresenceTrustValidator>());
    }

    [Test]
    public void CreateValidators_WhenOfflineModeWithBadTrustedKeyEntries_StillReturnsPresenceValidatorOnly()
    {
        var provider = new MstVerificationProvider();
        var args = new[]
        {
            "--mst-endpoint", "https://example.test",
            "--mst-trust-mode", "offline",
            "--mst-trusted-key", "",
            "--mst-trusted-key", "not-an-entry",
            "--mst-trusted-key", "issuer=",
            "--mst-trusted-key", "=path",
            "--mst-trusted-key", "issuer=C:\\does-not-exist.json"
        };

        var parse = Parse(provider, args);
        var validators = provider.CreateValidators(parse).ToList();

        Assert.That(validators, Has.Count.EqualTo(1));
        Assert.That(validators[0], Is.InstanceOf<MstReceiptPresenceTrustValidator>());
    }

    [Test]
    public void GetVerificationMetadata_IncludesReceiptRequiredAndEndpointWhenPresent()
    {
        var provider = new MstVerificationProvider();
        var parse = Parse(provider, new[] { "--mst-endpoint", "https://example.test", "--verify-receipt", "false" });

        using var testCert = CreateTestCertificate();
        var message = CreateSignedMessage(testCert);
        var validationResult = ValidationResult.Success("test", ValidationStage.KeyMaterialTrust);

        var metadata = provider.GetVerificationMetadata(parse, message, validationResult);

        Assert.That(metadata, Does.ContainKey("Receipt Required"));
        Assert.That(metadata, Does.ContainKey("MST Endpoint"));
        Assert.That(metadata, Does.ContainKey("Verify Receipt"));
    }

    [Test]
    public void IsActivated_WithOfflineTrustedKeyEntries_ReturnsTrue()
    {
        var provider = new MstVerificationProvider();

        var parse = Parse(provider, new[]
        {
            "--mst-trust-mode", "offline",
            "--mst-trusted-key", "example.test=C:\\does-not-exist.json"
        });

        Assert.That(provider.IsActivated(parse), Is.True);
    }

    [Test]
    public void CreateValidators_WhenOfflineModeWithMissingTrustFile_ReturnsPresenceValidatorOnly()
    {
        var provider = new MstVerificationProvider();
        var missingTrustFile = new FileInfo(Path.Combine(Path.GetTempPath(), $"mst_trust_{Guid.NewGuid():N}.json"));

        var parse = Parse(provider, new[]
        {
            "--mst-endpoint", "https://example.test",
            "--mst-trust-mode", "offline",
            "--mst-trust-file", missingTrustFile.FullName
        });

        var validators = provider.CreateValidators(parse).ToList();

        Assert.That(validators, Has.Count.EqualTo(1));
        Assert.That(validators[0], Is.InstanceOf<MstReceiptPresenceTrustValidator>());
    }

    [Test]
    public void CreateValidators_WhenOfflineModeWithTrustedJwk_AddsReceiptValidator()
    {
        var provider = new MstVerificationProvider();

        using var rsa = RSA.Create(2048);
        var p = rsa.ExportParameters(includePrivateParameters: false);

        var jwkJson = JsonSerializer.Serialize(new
        {
            kty = "RSA",
            n = Base64UrlEncode(p.Modulus!),
            e = Base64UrlEncode(p.Exponent!)
        });

        var jwkPath = Path.Combine(Path.GetTempPath(), $"mst_jwk_{Guid.NewGuid():N}.json");
        File.WriteAllText(jwkPath, jwkJson);

        try
        {
            var parse = Parse(provider, new[]
            {
                "--mst-endpoint", "https://example.test",
                "--mst-trust-mode", "offline",
                "--mst-trusted-key", $"https://example.test={jwkPath}"
            });

            var validators = provider.CreateValidators(parse).ToList();

            Assert.That(validators.Any(v => v is MstReceiptPresenceTrustValidator), Is.True);
            Assert.That(validators.Any(v => v is MstReceiptValidator), Is.True);
        }
        finally
        {
            if (File.Exists(jwkPath))
            {
                File.Delete(jwkPath);
            }
        }
    }

    [Test]
    public void CreateValidators_WhenOfflineModeWithTrustedJwks_AddsReceiptValidator()
    {
        var provider = new MstVerificationProvider();

        using var rsa = RSA.Create(2048);
        var p = rsa.ExportParameters(includePrivateParameters: false);

        var jwk = new
        {
            kty = "RSA",
            n = Base64UrlEncode(p.Modulus!),
            e = Base64UrlEncode(p.Exponent!)
        };

        var jwksJson = JsonSerializer.Serialize(new { keys = new[] { jwk } });
        var jwksPath = Path.Combine(Path.GetTempPath(), $"mst_jwks_{Guid.NewGuid():N}.json");
        File.WriteAllText(jwksPath, jwksJson);

        try
        {
            var parse = Parse(provider, new[]
            {
                "--mst-endpoint", "https://example.test",
                "--mst-trust-mode", "offline",
                "--mst-trusted-key", $"example.test={jwksPath}"
            });

            var validators = provider.CreateValidators(parse).ToList();

            Assert.That(validators.Any(v => v is MstReceiptPresenceTrustValidator), Is.True);
            Assert.That(validators.Any(v => v is MstReceiptValidator), Is.True);
        }
        finally
        {
            if (File.Exists(jwksPath))
            {
                File.Delete(jwksPath);
            }
        }
    }

    private static System.CommandLine.Parsing.ParseResult Parse(MstVerificationProvider provider, string[] args)
    {
        var verify = new Command("verify");
        provider.AddVerificationOptions(verify);

        var root = new RootCommand();
        root.AddCommand(verify);

        var allArgs = new List<string> { "verify" };
        allArgs.AddRange(args);

        return root.Parse(allArgs.ToArray());
    }

    private static CoseSign1Message CreateSignedMessage(X509Certificate2 cert)
    {
        using var key = cert.GetECDsaPrivateKey()!;
        var signer = new CoseSigner(key, HashAlgorithmName.SHA256);
        var payloadBytes = System.Text.Encoding.UTF8.GetBytes("payload");
        var signedBytes = CoseSign1Message.SignEmbedded(payloadBytes, signer);
        return CoseMessage.DecodeSign1(signedBytes);
    }

    private static string Base64UrlEncode(byte[] bytes)
    {
        return Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }
}
