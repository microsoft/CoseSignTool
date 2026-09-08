// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

extern alias IdentityAlias;

namespace CoseSignTool.MST.Plugin.Tests;

using System.Text.Json;
using Azure;
using Azure.ArtifactSigning.MST;
using DefaultAzureCredentialOptions = IdentityAlias::Azure.Identity.DefaultAzureCredentialOptions;

/// <summary>
/// Tests the Azure Artifact Signing proxy path of <see cref="RegisterCommand"/>.
/// </summary>
[TestClass]
public class RegisterCommandProxyTests
{
    private const string ProxyEndpoint = "https://api-canary.northcentralus.codesigning.azure.net/";

    [TestMethod]
    public void Options_IncludeProxyArguments()
    {
        RegisterCommand command = new();

        Assert.IsTrue(command.Options.ContainsKey("proxy-endpoint"));
        Assert.IsTrue(command.Options.ContainsKey("account-name"));
        Assert.IsTrue(command.Options.ContainsKey("cert-profile-name"));
        Assert.IsTrue(command.Options.ContainsKey("correlation-id"));
        Assert.IsTrue(command.Options.ContainsKey("aas-exclude-credentials"));
    }

    [TestMethod]
    public void CreateCredentialOptions_WithExclusions_DisablesRequestedCredentials()
    {
        IConfigurationRoot configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                { "aas-exclude-credentials", "ManagedIdentityCredential,VisualStudioCredential" }
            })
            .Build();

        DefaultAzureCredentialOptions options = RegisterCommand.CreateCredentialOptions(configuration);

        Assert.IsTrue(options.ExcludeManagedIdentityCredential);
        Assert.IsTrue(options.ExcludeVisualStudioCredential);
        Assert.IsTrue(options.ExcludeInteractiveBrowserCredential);
        Assert.IsFalse(options.ExcludeAzureCliCredential);
    }

    [TestMethod]
    public void CreateCredentialOptions_WithUnknownCredential_Throws()
    {
        IConfigurationRoot configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                { "aas-exclude-credentials", "UnknownCredential" }
            })
            .Build();

        Assert.ThrowsException<ArgumentException>(() => RegisterCommand.CreateCredentialOptions(configuration));
    }

    [TestMethod]
    public async Task ExecuteAsync_WithProxyEndpoint_CallsRegisterTransparencyAndWritesResult()
    {
        byte[] coseBytes = new byte[] { 0xD2, 0x84, 0x40, 0xA0, 0x40, 0x40 };
        byte[] receiptBytes = new byte[] { 0xD8, 0x63, 0x81, 0x01 };
        string payloadPath = Path.GetTempFileName();
        string signaturePath = Path.GetTempFileName();
        string outputPath = Path.GetTempFileName();
        RecordingTransparencyClient client = new(receiptBytes);
        RegisterCommand command = new((_, _) => client);
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

    [TestMethod]
    public async Task ExecuteAsync_WithProxyEndpointAndMissingAccount_ReturnsMissingRequiredOption()
    {
        RegisterCommand command = new((_, _) => throw new AssertFailedException("Client should not be created."));
        IConfigurationRoot configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                { "endpoint", "https://debugruisuprivatetrust.confidential-ledger.azure.com" },
                { "proxy-endpoint", ProxyEndpoint },
                { "cert-profile-name", "test-profile" },
                { "payload", "payload.bin" },
                { "signature", "statement.cose" }
            })
            .Build();

        PluginExitCode result = await command.ExecuteAsync(configuration);

        Assert.AreEqual(PluginExitCode.MissingRequiredOption, result);
    }

    [TestMethod]
    public async Task ExecuteAsync_WithInvalidProxyEndpoint_ReturnsInvalidArgumentValue()
    {
        RegisterCommand command = new((_, _) => throw new AssertFailedException("Client should not be created."));
        IConfigurationRoot configuration = CreateConfiguration(
            "payload.bin",
            "statement.cose",
            proxyEndpoint: "http://api-canary.northcentralus.codesigning.azure.net/");

        PluginExitCode result = await command.ExecuteAsync(configuration);

        Assert.AreEqual(PluginExitCode.InvalidArgumentValue, result);
    }

    [TestMethod]
    public async Task ExecuteAsync_WithoutProxyEndpoint_UsesExistingDirectPath()
    {
        RegisterCommand command = new((_, _) => throw new AssertFailedException("Proxy client should not be created."));
        IConfigurationRoot configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>())
            .Build();

        PluginExitCode result = await command.ExecuteAsync(configuration);

        Assert.AreEqual(PluginExitCode.MissingRequiredOption, result);
    }

    private static IConfigurationRoot CreateConfiguration(
        string payloadPath,
        string signaturePath,
        string? outputPath = null,
        string? proxyEndpoint = ProxyEndpoint,
        string? correlationId = null)
    {
        return new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                { "endpoint", "https://debugruisuprivatetrust.confidential-ledger.azure.com" },
                { "proxy-endpoint", proxyEndpoint },
                { "account-name", "test-account" },
                { "cert-profile-name", "test-profile" },
                { "payload", payloadPath },
                { "signature", signaturePath },
                { "output", outputPath },
                { "correlation-id", correlationId }
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
