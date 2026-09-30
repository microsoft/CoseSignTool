// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.AzureArtifactSigning.Plugin.Tests;

using Azure;
using Azure.ArtifactSigning.MST;
using CoseSignTool.Abstractions;
using CoseSignTool.AzureArtifactSigning.Plugin;
using Microsoft.Extensions.Configuration;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using System.Text.Json;

/// <summary>
/// Tests for <see cref="AzureArtifactSigningMstRegisterCommand"/>.
/// </summary>
[TestClass]
public class AzureArtifactSigningMstRegisterCommandTests
{
    private const string ProxyEndpoint = "https://api-canary.northcentralus.codesigning.azure.net/";

    /// <summary>
    /// Verifies that the Artifact Signing command plugin owns the MST proxy command.
    /// </summary>
    [TestMethod]
    public void Plugin_ExposesArtifactSigningMstRegisterCommand()
    {
        AzureArtifactSigningCommandPlugin plugin = new();

        IPluginCommand command = plugin.Commands.Single();

        Assert.AreEqual("aas_mst_register", command.Name);
        Assert.IsInstanceOfType<AzureArtifactSigningMstRegisterCommand>(command);
    }

    /// <summary>
    /// Verifies that all Artifact Signing proxy options are registered with the CLI.
    /// </summary>
    [TestMethod]
    public void Options_IncludeArtifactSigningProxyArguments()
    {
        AzureArtifactSigningMstRegisterCommand command = new();

        Assert.IsTrue(command.Options.ContainsKey("endpoint"));
        Assert.IsTrue(command.Options.ContainsKey("proxy-endpoint"));
        Assert.IsTrue(command.Options.ContainsKey("account-name"));
        Assert.IsTrue(command.Options.ContainsKey("cert-profile-name"));
        Assert.IsTrue(command.Options.ContainsKey("correlation-id"));
        Assert.IsTrue(command.Options.ContainsKey("aas-exclude-credentials"));
    }

    /// <summary>
    /// Verifies request mapping and receipt output for a successful proxy registration.
    /// </summary>
    [TestMethod]
    public async Task ExecuteAsync_WithValidArguments_CallsProxyAndWritesResult()
    {
        byte[] coseBytes = new byte[] { 0xD2, 0x84, 0x40, 0xA0, 0x40, 0x40 };
        byte[] receiptBytes = new byte[] { 0xD8, 0x63, 0x81, 0x01 };
        string payloadPath = Path.GetTempFileName();
        string signaturePath = Path.GetTempFileName();
        string outputPath = Path.GetTempFileName();
        RecordingTransparencyClient client = new(receiptBytes);
        AzureArtifactSigningMstRegisterCommand command = new((_, _, _) => client);
        IConfigurationRoot configuration = CreateConfiguration(
            payloadPath,
            signaturePath,
            outputPath,
            correlationId: "test-correlation-id");

        try
        {
            await File.WriteAllTextAsync(payloadPath, "payload");
            await File.WriteAllBytesAsync(signaturePath, coseBytes);

            PluginExitCode result = await command.ExecuteAsync(configuration);

            Assert.AreEqual(PluginExitCode.Success, result);
            Assert.AreEqual("test-account", client.AccountName);
            Assert.AreEqual("test-profile", client.CertificateProfileName);
            Assert.AreEqual("debugruisuprivatetrust", client.MstInstanceName);
            Assert.AreEqual("test-correlation-id", client.CorrelationId);
            CollectionAssert.AreEqual(coseBytes, client.SubmittedData);

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
    /// Verifies that an account is required before the proxy client is created.
    /// </summary>
    [TestMethod]
    public async Task ExecuteAsync_WithoutAccount_ReturnsMissingRequiredOption()
    {
        AzureArtifactSigningMstRegisterCommand command = new(
            (_, _, _) => throw new AssertFailedException("Client should not be created."));
        IConfigurationRoot configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["endpoint"] = "https://debugruisuprivatetrust.confidential-ledger.azure.com",
                ["proxy-endpoint"] = ProxyEndpoint,
                ["cert-profile-name"] = "test-profile",
                ["payload"] = "payload.bin",
                ["signature"] = "statement.cose"
            })
            .Build();

        PluginExitCode result = await command.ExecuteAsync(configuration);

        Assert.AreEqual(PluginExitCode.MissingRequiredOption, result);
    }

    /// <summary>
    /// Verifies that insecure proxy endpoints are rejected.
    /// </summary>
    [TestMethod]
    public async Task ExecuteAsync_WithHttpProxyEndpoint_ReturnsInvalidArgumentValue()
    {
        AzureArtifactSigningMstRegisterCommand command = new(
            (_, _, _) => throw new AssertFailedException("Client should not be created."));
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
        AzureArtifactSigningMstRegisterCommand command = new(
            (_, _, _) => throw new AssertFailedException("Client should not be created."));
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
        byte[] coseBytes = new byte[] { 0xD2, 0x84, 0x40, 0xA0, 0x40, 0x40 };
        string payloadPath = Path.GetTempFileName();
        string signaturePath = Path.GetTempFileName();
        AzureArtifactSigningMstRegisterCommand command = new();
        IConfigurationRoot configuration = CreateConfiguration(
            payloadPath,
            signaturePath,
            excludedCredentials: "UnknownCredential");

        try
        {
            await File.WriteAllTextAsync(payloadPath, "payload");
            await File.WriteAllBytesAsync(signaturePath, coseBytes);

            PluginExitCode result = await command.ExecuteAsync(configuration);

            Assert.AreEqual(PluginExitCode.InvalidArgumentValue, result);
        }
        finally
        {
            File.Delete(payloadPath);
            File.Delete(signaturePath);
        }
    }

    private static IConfigurationRoot CreateConfiguration(
        string payloadPath,
        string signaturePath,
        string? outputPath = null,
        string? proxyEndpoint = ProxyEndpoint,
        string? correlationId = null,
        string? timeout = null,
        string? excludedCredentials = null)
    {
        return new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["endpoint"] = "https://debugruisuprivatetrust.confidential-ledger.azure.com",
                ["proxy-endpoint"] = proxyEndpoint,
                ["account-name"] = "test-account",
                ["cert-profile-name"] = "test-profile",
                ["payload"] = payloadPath,
                ["signature"] = signaturePath,
                ["output"] = outputPath,
                ["correlation-id"] = correlationId,
                ["timeout"] = timeout,
                ["aas-exclude-credentials"] = excludedCredentials
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
