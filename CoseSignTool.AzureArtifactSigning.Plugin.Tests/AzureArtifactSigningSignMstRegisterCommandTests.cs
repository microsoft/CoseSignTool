// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.AzureArtifactSigning.Plugin.Tests;

using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using System.Text.Json;
using Azure;
using Azure.ArtifactSigning.MST;
using CoseSign1;
using CoseSign1.Abstractions.Interfaces;
using CoseSign1.Interfaces;
using CoseSignTool.Abstractions;
using CoseSignTool.AzureArtifactSigning.Plugin;
using Microsoft.Extensions.Configuration;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;

/// <summary>
/// Tests for <see cref="AzureArtifactSigningSignMstRegisterCommand"/>.
/// </summary>
[TestClass]
public class AzureArtifactSigningSignMstRegisterCommandTests
{
    private const string AasEndpoint = "https://contoso.codesigning.azure.net/";
    private const string ProxyEndpoint = "https://api-canary.northcentralus.codesigning.azure.net/";

    /// <summary>
    /// Verifies that the Artifact Signing command plugin owns the combined sign-and-register command.
    /// </summary>
    [TestMethod]
    public void Plugin_ExposesArtifactSigningSignMstRegisterCommand()
    {
        AzureArtifactSigningCommandPlugin plugin = new();

        IPluginCommand command = plugin.Commands.Single();

        Assert.AreEqual("aas_sign_mst_register", command.Name);
        Assert.IsInstanceOfType<AzureArtifactSigningSignMstRegisterCommand>(command);
    }

    /// <summary>
    /// Verifies the command exposes provider, signing, header, and registration options using plugin conventions.
    /// </summary>
    [TestMethod]
    public void Options_IncludeSigningAndProxyArguments()
    {
        AzureArtifactSigningSignMstRegisterCommand command = new();

        Assert.IsTrue(command.Options.ContainsKey("endpoint"));
        Assert.IsTrue(command.Options.ContainsKey("proxy-endpoint"));
        Assert.IsTrue(command.Options.ContainsKey("aas-endpoint"));
        Assert.IsTrue(command.Options.ContainsKey("aas-account-name"));
        Assert.IsTrue(command.Options.ContainsKey("aas-cert-profile-name"));
        Assert.IsTrue(command.Options.ContainsKey("payload"));
        Assert.IsTrue(command.Options.ContainsKey("signature"));
        Assert.IsTrue(command.Options.ContainsKey("correlation-id"));
        Assert.IsTrue(command.Options.ContainsKey("aas-exclude-credentials"));
        Assert.IsTrue(command.Options.ContainsKey("hash-algorithm"));
        Assert.IsTrue(command.Options.ContainsKey("rsa-signature-padding"));
        Assert.IsTrue(command.Options.ContainsKey("cbor-protected-headers"));
        Assert.IsTrue(command.Options.ContainsKey("cbor-unprotected-headers"));
    }

    /// <summary>
    /// Verifies that signing happens first and the exact generated statement is written and registered.
    /// </summary>
    [TestMethod]
    public async Task ExecuteAsync_WithValidArguments_SignsWritesAndRegistersSameStatement()
    {
        byte[] statementBytes = new byte[] { 0xD2, 0x84, 0x40, 0xA0, 0x40, 0x40 };
        byte[] receiptBytes = new byte[] { 0xD8, 0x63, 0x81, 0x01 };
        string payloadPath = Path.GetTempFileName();
        string signaturePath = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid():N}.cose");
        string outputPath = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid():N}.json");
        RecordingTransparencyClient client = new(receiptBytes);
        byte[]? signedPayload = null;
        CoseSign1MessageSigningOptions? capturedSigningOptions = null;
        ICoseHeaderExtender? capturedHeaderExtender = null;
        AzureArtifactSigningSignMstRegisterCommand command = new(
            (_, _, _) => client,
            async (payload, _, _, signingOptions, headerExtender, cancellationToken) =>
            {
                using MemoryStream payloadBuffer = new();
                await payload.CopyToAsync(payloadBuffer, cancellationToken);
                signedPayload = payloadBuffer.ToArray();
                capturedSigningOptions = signingOptions;
                capturedHeaderExtender = headerExtender;
                return statementBytes;
            });
        IConfigurationRoot configuration = CreateConfiguration(
            payloadPath,
            signaturePath,
            outputPath,
            correlationId: "test-correlation-id",
            hashAlgorithm: "SHA384",
            rsaSignaturePadding: "PKCS1",
            cborProtectedHeaders: "external-signatures=RAECAwQ=");

        try
        {
            byte[] payloadBytes = "payload"u8.ToArray();
            await File.WriteAllBytesAsync(payloadPath, payloadBytes);

            PluginExitCode result = await command.ExecuteAsync(configuration);

            Assert.AreEqual(PluginExitCode.Success, result);
            CollectionAssert.AreEqual(payloadBytes, signedPayload);
            CollectionAssert.AreEqual(statementBytes, await File.ReadAllBytesAsync(signaturePath));
            CollectionAssert.AreEqual(statementBytes, client.SubmittedData);
            Assert.AreEqual("test-account", client.AccountName);
            Assert.AreEqual("test-profile", client.CertificateProfileName);
            Assert.AreEqual("debugruisuprivatetrust", client.MstInstanceName);
            Assert.AreEqual("test-correlation-id", client.CorrelationId);
            Assert.AreEqual(HashAlgorithmName.SHA384, capturedSigningOptions?.HashAlgorithm);
            Assert.AreSame(RSASignaturePadding.Pkcs1, capturedSigningOptions?.RsaSignaturePadding);

            CoseHeaderMap protectedHeaders = capturedHeaderExtender!.ExtendProtectedHeaders(new CoseHeaderMap());
            CollectionAssert.AreEqual(
                new byte[] { 0x44, 0x01, 0x02, 0x03, 0x04 },
                protectedHeaders[new CoseHeaderLabel("external-signatures")].EncodedValue.ToArray());

            using JsonDocument output = JsonDocument.Parse(await File.ReadAllTextAsync(outputPath));
            Assert.AreEqual(
                Convert.ToBase64String(receiptBytes),
                output.RootElement.GetProperty("TransparencyReceipt").GetString());
        }
        finally
        {
            File.Delete(payloadPath);
            File.Delete(signaturePath);
            File.Delete(outputPath);
        }
    }

    /// <summary>
    /// Verifies that registration is not attempted and no statement is written when signing fails.
    /// </summary>
    [TestMethod]
    public async Task ExecuteAsync_WhenSigningFails_DoesNotRegisterOrWriteStatement()
    {
        string payloadPath = Path.GetTempFileName();
        string signaturePath = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid():N}.cose");
        bool clientCreated = false;
        AzureArtifactSigningSignMstRegisterCommand command = new(
            (_, _, _) =>
            {
                clientCreated = true;
                return new RecordingTransparencyClient(Array.Empty<byte>());
            },
            (_, _, _, _, _, _) => throw new InvalidOperationException("Signing failed."));
        IConfigurationRoot configuration = CreateConfiguration(payloadPath, signaturePath);

        try
        {
            await File.WriteAllTextAsync(payloadPath, "payload");

            PluginExitCode result = await command.ExecuteAsync(configuration);

            Assert.AreEqual(PluginExitCode.UnknownError, result);
            Assert.IsFalse(clientCreated);
            Assert.IsFalse(File.Exists(signaturePath));
        }
        finally
        {
            File.Delete(payloadPath);
            File.Delete(signaturePath);
        }
    }

    /// <summary>
    /// Verifies that an account is required before signing starts.
    /// </summary>
    [TestMethod]
    public async Task ExecuteAsync_WithoutAccount_ReturnsMissingRequiredOption()
    {
        bool signingStarted = false;
        AzureArtifactSigningSignMstRegisterCommand command = new(
            (_, _, _) => throw new AssertFailedException("Client should not be created."),
            (_, _, _, _, _, _) =>
            {
                signingStarted = true;
                return Task.FromResult<ReadOnlyMemory<byte>>(Array.Empty<byte>());
            });
        IConfigurationRoot configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["endpoint"] = "https://debugruisuprivatetrust.confidential-ledger.azure.com",
                ["proxy-endpoint"] = ProxyEndpoint,
                ["aas-endpoint"] = AasEndpoint,
                ["aas-cert-profile-name"] = "test-profile",
                ["payload"] = "payload.bin",
                ["signature"] = "statement.cose",
            })
            .Build();

        PluginExitCode result = await command.ExecuteAsync(configuration);

        Assert.AreEqual(PluginExitCode.MissingRequiredOption, result);
        Assert.IsFalse(signingStarted);
    }

    /// <summary>
    /// Verifies that insecure signing endpoints are rejected.
    /// </summary>
    [TestMethod]
    public async Task ExecuteAsync_WithHttpAasEndpoint_ReturnsInvalidArgumentValue()
    {
        AzureArtifactSigningSignMstRegisterCommand command = CreateCommandThatMustNotRun();
        IConfigurationRoot configuration = CreateConfiguration(
            "payload.bin",
            "statement.cose",
            aasEndpoint: "http://contoso.codesigning.azure.net/");

        PluginExitCode result = await command.ExecuteAsync(configuration);

        Assert.AreEqual(PluginExitCode.InvalidArgumentValue, result);
    }

    /// <summary>
    /// Verifies that insecure proxy endpoints are rejected.
    /// </summary>
    [TestMethod]
    public async Task ExecuteAsync_WithHttpProxyEndpoint_ReturnsInvalidArgumentValue()
    {
        AzureArtifactSigningSignMstRegisterCommand command = CreateCommandThatMustNotRun();
        IConfigurationRoot configuration = CreateConfiguration(
            "payload.bin",
            "statement.cose",
            proxyEndpoint: "http://api-canary.northcentralus.codesigning.azure.net/");

        PluginExitCode result = await command.ExecuteAsync(configuration);

        Assert.AreEqual(PluginExitCode.InvalidArgumentValue, result);
    }

    /// <summary>
    /// Verifies that invalid timeout values are rejected before file access.
    /// </summary>
    [TestMethod]
    public async Task ExecuteAsync_WithInvalidTimeout_ReturnsInvalidArgumentValue()
    {
        AzureArtifactSigningSignMstRegisterCommand command = CreateCommandThatMustNotRun();
        IConfigurationRoot configuration = CreateConfiguration(
            "payload.bin",
            "statement.cose",
            timeout: "0");

        PluginExitCode result = await command.ExecuteAsync(configuration);

        Assert.AreEqual(PluginExitCode.InvalidArgumentValue, result);
    }

    /// <summary>
    /// Verifies that the command uses the Artifact Signing credential exclusion validation.
    /// </summary>
    [TestMethod]
    public async Task ExecuteAsync_WithUnknownCredentialExclusion_ReturnsInvalidArgumentValue()
    {
        string payloadPath = Path.GetTempFileName();
        string signaturePath = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid():N}.cose");
        AzureArtifactSigningSignMstRegisterCommand command = CreateCommandThatMustNotRun();
        IConfigurationRoot configuration = CreateConfiguration(
            payloadPath,
            signaturePath,
            excludedCredentials: "UnknownCredential");

        try
        {
            await File.WriteAllTextAsync(payloadPath, "payload");

            PluginExitCode result = await command.ExecuteAsync(configuration);

            Assert.AreEqual(PluginExitCode.InvalidArgumentValue, result);
            Assert.IsFalse(File.Exists(signaturePath));
        }
        finally
        {
            File.Delete(payloadPath);
            File.Delete(signaturePath);
        }
    }

    /// <summary>
    /// Verifies invalid signing algorithms are rejected before signing or registration starts.
    /// </summary>
    [TestMethod]
    public async Task ExecuteAsync_WithInvalidHashAlgorithm_ReturnsInvalidArgumentValue()
    {
        string payloadPath = Path.GetTempFileName();
        string signaturePath = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid():N}.cose");
        AzureArtifactSigningSignMstRegisterCommand command = CreateCommandThatMustNotRun();
        IConfigurationRoot configuration = CreateConfiguration(payloadPath, signaturePath, hashAlgorithm: "MD5");

        try
        {
            await File.WriteAllTextAsync(payloadPath, "payload");

            PluginExitCode result = await command.ExecuteAsync(configuration);

            Assert.AreEqual(PluginExitCode.InvalidArgumentValue, result);
            Assert.IsFalse(File.Exists(signaturePath));
        }
        finally
        {
            File.Delete(payloadPath);
            File.Delete(signaturePath);
        }
    }

    private static AzureArtifactSigningSignMstRegisterCommand CreateCommandThatMustNotRun()
    {
        return new AzureArtifactSigningSignMstRegisterCommand(
            (_, _, _) => throw new AssertFailedException("Client should not be created."),
            (_, _, _, _, _, _) => throw new AssertFailedException("Signing should not start."));
    }

    private static IConfigurationRoot CreateConfiguration(
        string payloadPath,
        string signaturePath,
        string? outputPath = null,
        string? proxyEndpoint = ProxyEndpoint,
        string? aasEndpoint = AasEndpoint,
        string? correlationId = null,
        string? timeout = null,
        string? excludedCredentials = null,
        string? hashAlgorithm = null,
        string? rsaSignaturePadding = null,
        string? cborProtectedHeaders = null)
    {
        return new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["endpoint"] = "https://debugruisuprivatetrust.confidential-ledger.azure.com",
                ["proxy-endpoint"] = proxyEndpoint,
                ["aas-endpoint"] = aasEndpoint,
                ["aas-account-name"] = "test-account",
                ["aas-cert-profile-name"] = "test-profile",
                ["payload"] = payloadPath,
                ["signature"] = signaturePath,
                ["output"] = outputPath,
                ["correlation-id"] = correlationId,
                ["timeout"] = timeout,
                ["aas-exclude-credentials"] = excludedCredentials,
                ["hash-algorithm"] = hashAlgorithm,
                ["rsa-signature-padding"] = rsaSignaturePadding,
                ["cbor-protected-headers"] = cborProtectedHeaders,
            })
            .Build();
    }

    private sealed class RecordingTransparencyClient : TransparencyClient
    {
        private readonly byte[] receipt;

        public RecordingTransparencyClient(byte[] receipt)
        {
            this.receipt = receipt;
        }

        public string? AccountName { get; private set; }

        public string? CertificateProfileName { get; private set; }

        public string? MstInstanceName { get; private set; }

        public string? CorrelationId { get; private set; }

        public byte[]? SubmittedData { get; private set; }

        public override async Task<Response<Stream>> RegisterTransparencyAsync(
            string codeSigningAccountName,
            string certificateProfileName,
            string mstInstanceName,
            Stream data,
            string xCorrelationId = null,
            CancellationToken cancellationToken = default)
        {
            using MemoryStream submittedData = new();
            await data.CopyToAsync(submittedData, cancellationToken);
            this.AccountName = codeSigningAccountName;
            this.CertificateProfileName = certificateProfileName;
            this.MstInstanceName = mstInstanceName;
            this.CorrelationId = xCorrelationId;
            this.SubmittedData = submittedData.ToArray();

            return Response.FromValue<Stream>(
                new MemoryStream(this.receipt, writable: false),
                Mock.Of<Response>());
        }
    }
}
