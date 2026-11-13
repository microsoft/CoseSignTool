// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.AzureArtifactSigning.Plugin.Tests;

using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using System.Text.Json;
using Azure;
using Azure.ArtifactSigning.MST;
using Azure.Core;
using CoseSign1.Abstractions.Interfaces;
using CoseSign1.Transparent.Extensions;
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
    /// Verifies command discovery and option inspection do not construct an MST client.
    /// </summary>
    [TestMethod]
    public void ConstructorAndOptions_DoNotCreateTransparencyClient()
    {
        int clientCreationCount = 0;
        AzureArtifactSigningSignMstRegisterCommand command = new(
            (_, _) =>
            {
                clientCreationCount++;
                return new RecordingTransparencyClient(Array.Empty<byte>());
            });

        _ = command.Options;

        Assert.AreEqual(0, clientCreationCount);
    }

    /// <summary>
    /// Verifies the command exposes provider, signing, header, and registration options using plugin conventions.
    /// </summary>
    [TestMethod]
    public void Options_IncludeSigningAndProxyArguments()
    {
        AzureArtifactSigningSignMstRegisterCommand command = new();

        Assert.IsTrue(command.Options.ContainsKey("mst-instance-name"));
        Assert.IsTrue(command.Options.ContainsKey("proxy-endpoint"));
        Assert.IsTrue(command.Options.ContainsKey("aas-endpoint"));
        Assert.IsTrue(command.Options.ContainsKey("aas-account-name"));
        Assert.IsTrue(command.Options.ContainsKey("aas-cert-profile-name"));
        Assert.IsTrue(command.Options.ContainsKey("payload"));
        Assert.IsTrue(command.Options.ContainsKey("signature"));
        Assert.IsTrue(command.Options.ContainsKey("correlation-id"));
        Assert.IsTrue(command.Options.ContainsKey("aas-exclude-credentials"));
        Assert.IsTrue(command.Options.ContainsKey("ContentType"));
        Assert.IsTrue(command.Options.ContainsKey("cty"));
        Assert.IsTrue(command.Options.ContainsKey("hash-algorithm"));
        Assert.IsTrue(command.Options.ContainsKey("rsa-signature-padding"));
        Assert.IsTrue(command.Options.ContainsKey("cbor-protected-headers"));
        Assert.IsTrue(command.Options.ContainsKey("cbor-unprotected-headers"));
    }

    /// <summary>
    /// Verifies that the original statement is registered and the persisted statement contains the returned receipt.
    /// </summary>
    [DataTestMethod]
    [DataRow(true, false)]
    [DataRow(false, false)]
    [DataRow(true, true)]
    [DataRow(false, true)]
    public async Task ExecuteAsync_WithValidArguments_RegistersOriginalAndWritesTransparentStatement(
        bool seekableReceipt,
        bool useSuppliedCredential)
    {
        using RSA rsa = RSA.Create(2048);
        CoseSigner signer = new(rsa, RSASignaturePadding.Pss, HashAlgorithmName.SHA256);
        byte[] statementBytes = CoseSign1Message.SignEmbedded("payload"u8.ToArray(), signer);
        byte[] receiptBytes = new byte[] { 0xD8, 0x63, 0x81, 0x01 };
        string payloadPath = Path.GetTempFileName();
        string signaturePath = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid():N}.cose");
        string outputPath = Path.GetTempFileName();
        RecordingTransparencyClient client = new(receiptBytes, seekableReceipt);
        byte[] statementBuffer = new byte[statementBytes.Length + 2];
        statementBytes.CopyTo(statementBuffer, 1);
        byte[]? signedPayload = null;
        string? capturedContentType = null;
        HashAlgorithmName capturedHashAlgorithm = default;
        RSASignaturePadding? capturedRsaSignaturePadding = null;
        ICoseHeaderExtender? capturedHeaderExtender = null;
        TokenCredential? suppliedCredential = useSuppliedCredential ? new Mock<TokenCredential>(MockBehavior.Strict).Object : null;
        TokenCredential? signingCredential = null;
        TokenCredential? registrationCredential = null;
        AzureArtifactSigningSignMstRegisterCommand command = new(
            (_, credential) =>
            {
                registrationCredential = credential;
                return client;
            },
            async (payload, _, _, credential, contentType, hashAlgorithm, rsaSignaturePadding, headerExtender, cancellationToken) =>
            {
                using MemoryStream payloadBuffer = new();
                await payload.CopyToAsync(payloadBuffer, cancellationToken);
                signedPayload = payloadBuffer.ToArray();
                capturedContentType = contentType;
                capturedHashAlgorithm = hashAlgorithm;
                capturedRsaSignaturePadding = rsaSignaturePadding;
                capturedHeaderExtender = headerExtender;
                signingCredential = credential;
                return statementBuffer.AsMemory(1, statementBytes.Length);
            });
        IConfigurationRoot configuration = CreateConfiguration(
            payloadPath,
            signaturePath,
            correlationId: "test-correlation-id",
            contentType: "application/spdx+json",
            hashAlgorithm: "SHA384",
            rsaSignaturePadding: "PKCS1",
            outputPath: outputPath,
            excludedCredentials: useSuppliedCredential ? "NotARealCredential" : "ManagedIdentityCredential",
            cborProtectedHeaders: "external-signatures=RAECAwQ=");

        try
        {
            byte[] payloadBytes = "payload"u8.ToArray();
            await File.WriteAllBytesAsync(payloadPath, payloadBytes);
            await File.WriteAllTextAsync(outputPath, new string(' ', 4096));

            PluginExitCode result = useSuppliedCredential
                ? await command.ExecuteAsync(configuration, suppliedCredential)
                : await command.ExecuteAsync(configuration);

            Assert.AreEqual(PluginExitCode.Success, result);
            Assert.IsNotNull(signingCredential);
            Assert.AreSame(signingCredential, registrationCredential);
            if (useSuppliedCredential)
            {
                Assert.AreSame(suppliedCredential, signingCredential);
            }

            CollectionAssert.AreEqual(payloadBytes, signedPayload);
            CollectionAssert.AreEqual(statementBytes, client.SubmittedData);
            Assert.AreEqual("test-account", client.AccountName);
            Assert.AreEqual("test-profile", client.CertificateProfileName);
            Assert.AreEqual("debugruisuprivatetrust", client.MstInstanceName);
            Assert.AreEqual("test-correlation-id", client.CorrelationId);
            Assert.AreEqual("application/spdx+json", capturedContentType);
            Assert.AreEqual(HashAlgorithmName.SHA384, capturedHashAlgorithm);
            Assert.AreSame(RSASignaturePadding.Pkcs1, capturedRsaSignaturePadding);

            CoseHeaderMap protectedHeaders = capturedHeaderExtender!.ExtendProtectedHeaders(new CoseHeaderMap());
            CollectionAssert.AreEqual(
                new byte[] { 0x44, 0x01, 0x02, 0x03, 0x04 },
                protectedHeaders[new CoseHeaderLabel("external-signatures")].EncodedValue.ToArray());

            byte[] transparentStatementBytes = await File.ReadAllBytesAsync(signaturePath);
            CoseSign1Message transparentStatement = CoseMessage.DecodeSign1(transparentStatementBytes);
            Assert.IsTrue(transparentStatement.TryGetReceipts(out List<byte[]>? receipts));
            Assert.AreEqual(1, receipts!.Count);
            CollectionAssert.AreEqual(receiptBytes, receipts[0]);

            using JsonDocument output = JsonDocument.Parse(await File.ReadAllTextAsync(outputPath));
            Assert.AreEqual(signaturePath, output.RootElement.GetProperty("SignaturePath").GetString());
            CollectionAssert.AreEqual(receiptBytes, output.RootElement.GetProperty("TransparencyReceipt").GetBytesFromBase64());
        }
        finally
        {
            File.Delete(payloadPath);
            File.Delete(signaturePath);
            File.Delete(outputPath);
        }
    }

    /// <summary>
    /// Verifies that registration failure does not leave a non-transparent statement at the output path.
    /// </summary>
    [TestMethod]
    public async Task ExecuteAsync_WhenRegistrationFails_DoesNotWriteStatement()
    {
        using RSA rsa = RSA.Create(2048);
        CoseSigner signer = new(rsa, RSASignaturePadding.Pss, HashAlgorithmName.SHA256);
        byte[] statementBytes = CoseSign1Message.SignEmbedded("payload"u8.ToArray(), signer);
        string payloadPath = Path.GetTempFileName();
        string signaturePath = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid():N}.cose");
        RecordingTransparencyClient client = new(
            new RequestFailedException(500, "Registration failed.", "InternalServerError", null));
        AzureArtifactSigningSignMstRegisterCommand command = new(
            (_, _) => client,
            (_, _, _, _, _, _, _, _, _) => Task.FromResult<ReadOnlyMemory<byte>>(statementBytes));
        IConfigurationRoot configuration = CreateConfiguration(payloadPath, signaturePath);

        try
        {
            await File.WriteAllTextAsync(payloadPath, "payload");

            PluginExitCode result = await command.ExecuteAsync(configuration);

            Assert.AreEqual(PluginExitCode.UnknownError, result);
            CollectionAssert.AreEqual(statementBytes, client.SubmittedData);
            Assert.IsFalse(File.Exists(signaturePath));
        }
        finally
        {
            File.Delete(payloadPath);
            File.Delete(signaturePath);
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
        RecordingTransparencyClient client = new(Array.Empty<byte>());
        AzureArtifactSigningSignMstRegisterCommand command = new(
            (_, _) => client,
            (_, _, _, _, _, _, _, _, _) => throw new InvalidOperationException("Signing failed."));
        IConfigurationRoot configuration = CreateConfiguration(payloadPath, signaturePath);

        try
        {
            await File.WriteAllTextAsync(payloadPath, "payload");

            PluginExitCode result = await command.ExecuteAsync(configuration);

            Assert.AreEqual(PluginExitCode.UnknownError, result);
            Assert.IsNull(client.SubmittedData);
            Assert.IsFalse(File.Exists(signaturePath));
        }
        finally
        {
            File.Delete(payloadPath);
            File.Delete(signaturePath);
        }
    }

    /// <summary>
    /// Verifies client construction fails before any signing operation.
    /// </summary>
    [TestMethod]
    public async Task ExecuteAsync_WhenClientConstructionFails_DoesNotSignOrWriteStatement()
    {
        string payloadPath = Path.GetTempFileName();
        string signaturePath = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid():N}.cose");
        AzureArtifactSigningSignMstRegisterCommand command = new(
            (_, _) => throw new InvalidOperationException("Client construction failed."),
            (_, _, _, _, _, _, _, _, _) => throw new AssertFailedException("Signing should not start."));

        try
        {
            PluginExitCode result = await command.ExecuteAsync(CreateConfiguration(payloadPath, signaturePath));

            Assert.AreEqual(PluginExitCode.UnknownError, result);
            Assert.IsFalse(File.Exists(signaturePath));
        }
        finally
        {
            File.Delete(payloadPath);
            File.Delete(signaturePath);
        }
    }

    /// <summary>
    /// Verifies that an omitted payload path or dash reads binary standard input without a payload file.
    /// </summary>
    [DataTestMethod]
    [DataRow(null)]
    [DataRow("-")]
    public async Task ExecuteAsync_WithStandardInput_SignsAndRegistersPayload(string? payloadPath)
    {
        byte[] payloadBytes = new byte[] { 0x00, 0xFF, 0x80, 0x0A };
        byte[] receiptBytes = new byte[] { 0xD8, 0x63, 0x81, 0x01 };
        using RSA rsa = RSA.Create(2048);
        CoseSigner signer = new(rsa, RSASignaturePadding.Pss, HashAlgorithmName.SHA256);
        byte[] statementBytes = CoseSign1Message.SignEmbedded(payloadBytes, signer);
        string signaturePath = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid():N}.cose");
        RecordingTransparencyClient client = new(receiptBytes);
        AzureArtifactSigningSignMstRegisterCommand command = new(
            (_, _) => client,
            async (payload, _, _, _, _, _, _, _, cancellationToken) =>
            {
                using MemoryStream buffer = new();
                await payload.CopyToAsync(buffer, cancellationToken);
                CollectionAssert.AreEqual(payloadBytes, buffer.ToArray());
                return statementBytes;
            },
            () => new MemoryStream(payloadBytes, writable: false));

        try
        {
            PluginExitCode result = await command.ExecuteAsync(CreateConfiguration(payloadPath, signaturePath));

            Assert.AreEqual(PluginExitCode.Success, result);
            CollectionAssert.AreEqual(statementBytes, client.SubmittedData);
            CoseSign1Message statement = CoseMessage.DecodeSign1(await File.ReadAllBytesAsync(signaturePath));
            Assert.IsTrue(statement.TryGetReceipts(out List<byte[]>? receipts));
            CollectionAssert.AreEqual(receiptBytes, receipts!.Single());
        }
        finally
        {
            File.Delete(signaturePath);
        }
    }

    /// <summary>
    /// Verifies empty receipts never produce an output statement, regardless of stream capabilities.
    /// </summary>
    [DataTestMethod]
    [DataRow(true)]
    [DataRow(false)]
    public async Task ExecuteAsync_WithEmptyReceipt_DoesNotWriteStatement(bool seekableReceipt)
    {
        string payloadPath = Path.GetTempFileName();
        string signaturePath = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid():N}.cose");
        RecordingTransparencyClient client = new(Array.Empty<byte>(), seekableReceipt);
        AzureArtifactSigningSignMstRegisterCommand command = new(
            (_, _) => client,
            (_, _, _, _, _, _, _, _, _) => Task.FromResult<ReadOnlyMemory<byte>>(Array.Empty<byte>()));

        try
        {
            PluginExitCode result = await command.ExecuteAsync(CreateConfiguration(payloadPath, signaturePath));

            Assert.AreEqual(PluginExitCode.UnknownError, result);
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
            (_, _) => throw new AssertFailedException("Client should not be created."),
            (_, _, _, _, _, _, _, _, _) =>
            {
                signingStarted = true;
                return Task.FromResult<ReadOnlyMemory<byte>>(Array.Empty<byte>());
            });
        IConfigurationRoot configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["mst-instance-name"] = "debugruisuprivatetrust",
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
            (_, _) => throw new AssertFailedException("Client should not be created."),
            (_, _, _, _, _, _, _, _, _) => throw new AssertFailedException("Signing should not start."));
    }

    private static IConfigurationRoot CreateConfiguration(
        string? payloadPath,
        string signaturePath,
        string? outputPath = null,
        string? proxyEndpoint = ProxyEndpoint,
        string? aasEndpoint = AasEndpoint,
        string? correlationId = null,
        string? timeout = null,
        string? excludedCredentials = null,
        string? contentType = null,
        string? hashAlgorithm = null,
        string? rsaSignaturePadding = null,
        string? cborProtectedHeaders = null)
    {
        return new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["mst-instance-name"] = "debugruisuprivatetrust",
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
                ["ContentType"] = contentType,
                ["hash-algorithm"] = hashAlgorithm,
                ["rsa-signature-padding"] = rsaSignaturePadding,
                ["cbor-protected-headers"] = cborProtectedHeaders,
            })
            .Build();
    }

    private sealed class RecordingTransparencyClient : TransparencyClient
    {
        private readonly byte[]? receipt;
        private readonly RequestFailedException? exception;
        private readonly bool seekableReceipt;

        public RecordingTransparencyClient(byte[] receipt, bool seekableReceipt = true)
        {
            this.receipt = receipt;
            this.seekableReceipt = seekableReceipt;
        }

        public RecordingTransparencyClient(RequestFailedException exception)
        {
            this.exception = exception;
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

            if (this.exception is not null)
            {
                throw this.exception;
            }

            MemoryStream receiptStream = new(this.receipt!, writable: false);
            if (this.seekableReceipt)
            {
                return Response.FromValue<Stream>(receiptStream, Mock.Of<Response>());
            }

            Mock<Stream> nonSeekableStream = new() { CallBase = true };
            nonSeekableStream.SetupGet(stream => stream.CanRead).Returns(true);
            nonSeekableStream.SetupGet(stream => stream.CanSeek).Returns(false);
            nonSeekableStream
                .Setup(stream => stream.ReadAsync(It.IsAny<Memory<byte>>(), It.IsAny<CancellationToken>()))
                .Returns((Memory<byte> buffer, CancellationToken token) => receiptStream.ReadAsync(buffer, token));
            nonSeekableStream.Setup(stream => stream.Close()).Callback(receiptStream.Dispose);
            return Response.FromValue(nonSeekableStream.Object, Mock.Of<Response>());
        }
    }
}
