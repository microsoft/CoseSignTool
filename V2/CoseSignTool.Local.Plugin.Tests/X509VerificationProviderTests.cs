// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Local.Plugin.Tests;

using System.CommandLine;
using System.CommandLine.Parsing;
using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using CoseSignTool.Abstractions.Security;
using CoseSign1.Validation.Results;
using CoseSign1.Tests.Common;
using CoseSignTool.Local.Plugin;
using Microsoft.Extensions.Logging.Abstractions;

[TestFixture]
public class X509VerificationProviderTests
{
    private static CoseSign1Message CreateMessage()
    {
        using RSA rsa = RSA.Create(2048);
        CoseSigner coseSigner = new(
            rsa,
            RSASignaturePadding.Pkcs1,
            HashAlgorithmName.SHA256,
            protectedHeaders: new CoseHeaderMap(),
            unprotectedHeaders: new CoseHeaderMap());

        byte[] coseBytes = CoseSign1Message.SignEmbedded(Encoding.UTF8.GetBytes("payload"), coseSigner);
        return CoseMessage.DecodeSign1(coseBytes);
    }

    private static (X509VerificationProvider provider, ParseResult parseResult) CreateParseResult(params string[] args)
    {
        var provider = new X509VerificationProvider();

        var root = new RootCommand("root");
        var verify = new Command("verify");
        provider.AddVerificationOptions(verify);
        root.AddCommand(verify);

        var parseResult = root.Parse(new[] { "verify" }.Concat(args).ToArray());

        return (provider, parseResult);
    }

    [Test]
    public void GetVerificationMetadata_DefaultsToSystemTrust()
    {
        var (provider, parseResult) = CreateParseResult();

        var metadata = provider.GetVerificationMetadata(parseResult, CreateMessage(), ValidationResult.Success("ok"));

        Assert.That(metadata["Trust Mode"], Is.EqualTo("System Trust"));
        Assert.That(metadata["Revocation Check"], Is.EqualTo("Online"));
    }

    [Test]
    public void GetVerificationMetadata_AllowUntrusted_OverridesTrustMode()
    {
        var (provider, parseResult) = CreateParseResult("--allow-untrusted");

        var metadata = provider.GetVerificationMetadata(parseResult, CreateMessage(), ValidationResult.Success("ok"));

        Assert.That(metadata["Trust Mode"], Is.EqualTo("Allow Untrusted"));
    }

    [Test]
    public void GetVerificationMetadata_CustomTrustRoots_OverridesTrustMode()
    {
        using var cert = TestCertificateUtils.CreateCertificate();
        var certPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".cer");
        File.WriteAllBytes(certPath, cert.Export(X509ContentType.Cert));

        try
        {
            var (provider, parseResult) = CreateParseResult("--trust-roots", certPath);

            var metadata = provider.GetVerificationMetadata(parseResult, CreateMessage(), ValidationResult.Success("ok"));

            Assert.That(metadata["Trust Mode"], Is.EqualTo("Custom Roots"));
        }
        finally
        {
            File.Delete(certPath);
        }
    }

    [Test]
    public void ParseRevocationMode_MapsToX509RevocationMode()
    {
        var (provider, online) = CreateParseResult("--revocation-mode", "online");
        Assert.That(provider.ParseRevocationMode(online), Is.EqualTo(X509RevocationMode.Online));

        var (provider2, offline) = CreateParseResult("--revocation-mode", "offline");
        Assert.That(provider2.ParseRevocationMode(offline), Is.EqualTo(X509RevocationMode.Offline));

        var (provider3, none) = CreateParseResult("--revocation-mode", "none");
        Assert.That(provider3.ParseRevocationMode(none), Is.EqualTo(X509RevocationMode.NoCheck));
    }

    [Test]
    public void LoadCustomRoots_LoadsCerFilesFromTrustRootsOption()
    {
        using var cert = TestCertificateUtils.CreateCertificate();
        var certPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".cer");
        File.WriteAllBytes(certPath, cert.Export(X509ContentType.Cert));

        try
        {
            var (provider, parseResult) = CreateParseResult("--trust-roots", certPath);

            var roots = provider.LoadCustomRoots(parseResult, NullLogger.Instance);

            Assert.That(roots.Count, Is.EqualTo(1));
            Assert.That(roots[0].Thumbprint, Is.EqualTo(cert.Thumbprint));
        }
        finally
        {
            File.Delete(certPath);
        }
    }

    [Test]
    public void GetTrustPfxPassword_ReadsFromEnvVar()
    {
        var envName = "COSESIGNTOOL_TRUST_PFX_PASSWORD";
        var original = Environment.GetEnvironmentVariable(envName);

        var tempPfxPath = Path.GetTempFileName();

        try
        {
            Environment.SetEnvironmentVariable(envName, "secret");
            var (provider, parseResult) = CreateParseResult("--trust-pfx", tempPfxPath);

            var secure = provider.GetTrustPfxPassword(parseResult, NullLogger.Instance);

            Assert.That(secure, Is.Not.Null);
        }
        finally
        {
            Environment.SetEnvironmentVariable(envName, original);

            if (File.Exists(tempPfxPath))
            {
                File.Delete(tempPfxPath);
            }
        }
    }

    [Test]
    public void GetTrustPfxPassword_ReadsFromPasswordFile()
    {
        var password = "p@ssw0rd";
        var passwordFile = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".txt");
        var tempPfxPath = Path.GetTempFileName();

        try
        {
            File.WriteAllText(passwordFile, password);
            var (provider, parseResult) = CreateParseResult(
                "--trust-pfx", tempPfxPath,
                "--trust-pfx-password-file", passwordFile);

            var secure = provider.GetTrustPfxPassword(parseResult, NullLogger.Instance);

            Assert.That(secure, Is.Not.Null);
            Assert.That(SecurePasswordProvider.ConvertToPlainString(secure!), Is.EqualTo(password));
        }
        finally
        {
            if (File.Exists(passwordFile))
            {
                File.Delete(passwordFile);
            }

            if (File.Exists(tempPfxPath))
            {
                File.Delete(tempPfxPath);
            }
        }
    }

    [Test]
    public void GetTrustPfxPassword_UsesCustomEnvVarName_WhenProvided()
    {
        var envName = "COSESIGNTOOL_TRUST_PFX_PASSWORD_TEST";
        var original = Environment.GetEnvironmentVariable(envName);

        var tempPfxPath = Path.GetTempFileName();

        try
        {
            Environment.SetEnvironmentVariable(envName, "secret");
            var (provider, parseResult) = CreateParseResult(
                "--trust-pfx", tempPfxPath,
                "--trust-pfx-password-env", envName);

            var secure = provider.GetTrustPfxPassword(parseResult, NullLogger.Instance);

            Assert.That(secure, Is.Not.Null);
        }
        finally
        {
            Environment.SetEnvironmentVariable(envName, original);

            if (File.Exists(tempPfxPath))
            {
                File.Delete(tempPfxPath);
            }
        }
    }

    [Test]
    public void GetTrustPfxPassword_WhenNoSourcesConfigured_ReturnsNull()
    {
        var (provider, parseResult) = CreateParseResult();

        var secure = provider.GetTrustPfxPassword(parseResult, NullLogger.Instance);

        Assert.That(secure, Is.Null);
    }

    [Test]
    public void LoadCustomRoots_LoadsPfxFile_WhenProvided()
    {
        using var cert = TestCertificateUtils.CreateCertificate();
        var pfxPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".pfx");
        var passwordFile = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".txt");

        try
        {
            var password = "pfx-password";
            File.WriteAllBytes(pfxPath, cert.Export(X509ContentType.Pkcs12, password));
            File.WriteAllText(passwordFile, password);

            var (provider, parseResult) = CreateParseResult(
                "--trust-pfx", pfxPath,
                "--trust-pfx-password-file", passwordFile);

            var roots = provider.LoadCustomRoots(parseResult, NullLogger.Instance);

            Assert.That(roots.Count, Is.GreaterThanOrEqualTo(1));
        }
        finally
        {
            if (File.Exists(pfxPath))
            {
                File.Delete(pfxPath);
            }

            if (File.Exists(passwordFile))
            {
                File.Delete(passwordFile);
            }
        }
    }

    [Test]
    public void ExtractCommonName_ParsesCnFromDistinguishedName()
    {
        Assert.That(X509VerificationProvider.ExtractCommonName("CN=Example, O=Org"), Is.EqualTo("Example"));
        Assert.That(X509VerificationProvider.ExtractCommonName(""), Is.Null);
        Assert.That(X509VerificationProvider.ExtractCommonName(" , "), Is.Null);
    }
}
