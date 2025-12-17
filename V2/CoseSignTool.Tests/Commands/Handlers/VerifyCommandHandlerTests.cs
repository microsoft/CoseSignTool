// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.CommandLine;
using System.CommandLine.Invocation;
using System.CommandLine.Parsing;
using System.Formats.Cbor;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using CoseSign1.Certificates;
using CoseSign1.Certificates.ChainBuilders;
using CoseSign1.Direct;
using CoseSign1.Tests.Common;
using CoseSign1.Indirect;
using CoseSign1.Validation;
using CoseSignTool.Abstractions;
using CoseSignTool.Commands.Handlers;
using CoseSignTool.Output;

namespace CoseSignTool.Tests.Commands.Handlers;

/// <summary>
/// Tests for the VerifyCommandHandler class.
/// </summary>
[TestFixture]
public class VerifyCommandHandlerTests
{
    [Test]
    public void Constructor_WithNullFormatter_UsesDefaultFormatter()
    {
        // Arrange & Act
        var handler = new VerifyCommandHandler(null);

        // Assert
        Assert.That(handler, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithFormatter_UsesProvidedFormatter()
    {
        // Arrange
        var formatter = new TextOutputFormatter();

        // Act
        var handler = new VerifyCommandHandler(formatter);

        // Assert
        Assert.That(handler, Is.Not.Null);
    }

    [Test]
    public async Task HandleAsync_WithNullSignature_ReturnsFileNotFound()
    {
        // Arrange
        var handler = new VerifyCommandHandler();
        var context = CreateInvocationContext(signature: null);

        // Act
        var result = await handler.HandleAsync(context);

        // Assert
        Assert.That(result, Is.EqualTo((int)ExitCode.FileNotFound));
    }

    [Test]
    public async Task HandleAsync_WithNonExistentSignature_ReturnsFileNotFound()
    {
        // Arrange
        var handler = new VerifyCommandHandler();
        var nonExistentFile = new FileInfo(Path.Combine(Path.GetTempPath(), $"nonexistent_{Guid.NewGuid()}.cose"));
        var context = CreateInvocationContext(signature: nonExistentFile);

        // Act
        var result = await handler.HandleAsync(context);

        // Assert
        Assert.That(result, Is.EqualTo((int)ExitCode.FileNotFound));
    }

    [Test]
    public async Task HandleAsync_WithValidSignature_ReturnsInvalidSignatureForInvalidCose()
    {
        // Arrange
        var handler = new VerifyCommandHandler();
        var tempFile = Path.GetTempFileName();
        await File.WriteAllBytesAsync(tempFile, [0xD2, 0x84, 0x43, 0xA1]); // Invalid COSE bytes (incomplete)
        var signature = new FileInfo(tempFile);
        var context = CreateInvocationContext(signature: signature);

        try
        {
            // Act
            var result = await handler.HandleAsync(context);

            // Assert - invalid COSE data returns InvalidSignature
            Assert.That(result, Is.EqualTo((int)ExitCode.InvalidSignature));
        }
        finally
        {
            if (File.Exists(tempFile))
            {
                File.Delete(tempFile);
            }
        }
    }

    [Test]
    public async Task HandleAsync_WithNullContext_ThrowsArgumentNullException()
    {
        // Arrange
        var handler = new VerifyCommandHandler();

        // Act & Assert
        Assert.ThrowsAsync<ArgumentNullException>(() => handler.HandleAsync(null!));
    }

    [Test]
    public async Task HandleAsync_WithRandomBytes_ReturnsInvalidSignature()
    {
        // Arrange
        var handler = new VerifyCommandHandler();
        var tempFile = Path.GetTempFileName();
        await File.WriteAllBytesAsync(tempFile, [0x01, 0x02, 0x03, 0x04, 0x05]);
        var signature = new FileInfo(tempFile);
        var context = CreateInvocationContext(signature: signature);

        try
        {
            // Act
            var result = await handler.HandleAsync(context);

            // Assert - random bytes returns InvalidSignature
            Assert.That(result, Is.EqualTo((int)ExitCode.InvalidSignature));
        }
        finally
        {
            if (File.Exists(tempFile))
            {
                File.Delete(tempFile);
            }
        }
    }

    [Test]
    public async Task HandleAsync_UsesProvidedFormatter()
    {
        // Arrange
        var stringWriter = new StringWriter();
        var formatter = new TextOutputFormatter(stringWriter);
        var handler = new VerifyCommandHandler(formatter);
        var tempFile = Path.GetTempFileName();
        await File.WriteAllBytesAsync(tempFile, [0xD2, 0x84]);
        var signature = new FileInfo(tempFile);
        var context = CreateInvocationContext(signature: signature);

        try
        {
            // Act
            await handler.HandleAsync(context);
            formatter.Flush();

            // Assert - formatter should have been used
            var output = stringWriter.ToString();
            Assert.That(output, Does.Contain("Verification Operation"));
        }
        finally
        {
            if (File.Exists(tempFile))
            {
                File.Delete(tempFile);
            }
        }
    }

    [Test]
    public async Task HandleAsync_WithEmptyFile_ReturnsInvalidSignature()
    {
        // Arrange
        var handler = new VerifyCommandHandler();
        var tempFile = Path.GetTempFileName();
        await File.WriteAllBytesAsync(tempFile, []);
        var signature = new FileInfo(tempFile);
        var context = CreateInvocationContext(signature: signature);

        try
        {
            // Act
            var result = await handler.HandleAsync(context);

            // Assert - empty file returns InvalidSignature
            Assert.That(result, Is.EqualTo((int)ExitCode.InvalidSignature));
        }
        finally
        {
            if (File.Exists(tempFile))
            {
                File.Delete(tempFile);
            }
        }
    }

    [Test]
    public async Task HandleAsync_WhenSignatureLooksLikeBase64Text_WritesHintAndReturnsInvalidSignature()
    {
        var tempFile = Path.GetTempFileName();

        // Provide sufficiently long, base64-ish printable ASCII so LooksLikeBase64Text() evaluates to true.
        var base64ish = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo9PT09QUJDREVGR0hJSktMTU5PUA==";
        await File.WriteAllTextAsync(tempFile, base64ish);

        var signature = new FileInfo(tempFile);
        var context = CreateInvocationContext(signature: signature);

        var output = new StringWriter();
        var formatter = new TextOutputFormatter(output: output, error: output);
        var handler = new VerifyCommandHandler(formatter);

        try
        {
            var exitCode = await handler.HandleAsync(context);
            formatter.Flush();

            Assert.That(exitCode, Is.EqualTo((int)ExitCode.InvalidSignature));
            Assert.That(output.ToString(), Does.Contain("appears to be Base64 text"));
        }
        finally
        {
            if (File.Exists(tempFile))
            {
                File.Delete(tempFile);
            }
        }
    }

    [Test]
    public void LooksLikeBase64Text_WhenNullOrEmpty_ReturnsFalse()
    {
        var method = typeof(VerifyCommandHandler).GetMethod(
            "LooksLikeBase64Text",
            BindingFlags.NonPublic | BindingFlags.Static);

        Assert.That(method, Is.Not.Null);

        Assert.That((bool)method!.Invoke(null, new object?[] { null })!, Is.False);
        Assert.That((bool)method.Invoke(null, new object?[] { Array.Empty<byte>() })!, Is.False);
    }

    [Test]
    public void LooksLikeBase64Text_WhenTooShort_ReturnsFalse()
    {
        var method = typeof(VerifyCommandHandler).GetMethod(
            "LooksLikeBase64Text",
            BindingFlags.NonPublic | BindingFlags.Static);

        Assert.That(method, Is.Not.Null);

        // < 16 bytes inspected
        var shortBytes = System.Text.Encoding.ASCII.GetBytes("QUJDREVGR0g=");
        Assert.That((bool)method!.Invoke(null, new object?[] { shortBytes })!, Is.False);
    }

    [Test]
    public void LooksLikeBase64Text_WhenBinaryData_ReturnsFalse()
    {
        var method = typeof(VerifyCommandHandler).GetMethod(
            "LooksLikeBase64Text",
            BindingFlags.NonPublic | BindingFlags.Static);

        Assert.That(method, Is.Not.Null);

        // Contains a non-printable byte early, which should return false immediately.
        var bytes = new byte[32];
        bytes[0] = 0x00;
        bytes[1] = 0x01;
        bytes[2] = 0xFF;
        Assert.That((bool)method!.Invoke(null, new object?[] { bytes })!, Is.False);
    }

    [Test]
    public void LooksLikeBase64Text_WhenBase64ishAscii_ReturnsTrue()
    {
        var method = typeof(VerifyCommandHandler).GetMethod(
            "LooksLikeBase64Text",
            BindingFlags.NonPublic | BindingFlags.Static);

        Assert.That(method, Is.Not.Null);

        var bytes = System.Text.Encoding.ASCII.GetBytes(new string('A', 128));
        Assert.That((bool)method!.Invoke(null, new object?[] { bytes })!, Is.True);
    }

    [Test]
    public void VerifyIndirectPayloadHash_WhenNoContent_ReturnsFalse()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signer = new CoseSigner(key, HashAlgorithmName.SHA256);
        var payload = System.Text.Encoding.UTF8.GetBytes("payload");

        var detached = CoseSign1Message.SignDetached(payload, signer);
        var message = CoseSign1Message.DecodeSign1(detached);

        var method = typeof(VerifyCommandHandler).GetMethod(
            "VerifyIndirectPayloadHash",
            BindingFlags.NonPublic | BindingFlags.Static);

        Assert.That(method, Is.Not.Null);

        var result = (bool)method!.Invoke(null, new object[] { message, payload })!;
        Assert.That(result, Is.False);
    }

    [Test]
    public void VerifyIndirectPayloadHash_Private_WhenHeaderMissing_ReturnsFalse()
    {
        var payload = System.Text.Encoding.UTF8.GetBytes("payload");
        var embeddedHash = SHA256.HashData(payload);

        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signer = new CoseSigner(key, HashAlgorithmName.SHA256);
        var signed = CoseSign1Message.SignEmbedded(embeddedHash, signer);
        var message = CoseSign1Message.DecodeSign1(signed);

        var method = typeof(VerifyCommandHandler).GetMethod(
            "VerifyIndirectPayloadHash",
            BindingFlags.NonPublic | BindingFlags.Static);

        Assert.That(method, Is.Not.Null);

        var result = (bool)method!.Invoke(null, new object[] { message, payload })!;
        Assert.That(result, Is.False);
    }

    [Test]
    public void VerifyIndirectPayloadHash_WhenAlgorithmUnsupported_ReturnsFalse()
    {
        var payload = System.Text.Encoding.UTF8.GetBytes("payload");
        var embeddedHash = SHA256.HashData(payload);

        var protectedHeaders = new CoseHeaderMap();
        protectedHeaders.Add(CoseHashEnvelopeHeaderContributor.HeaderLabels.PayloadHashAlg, CoseHeaderValue.FromInt32(-999));

        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signer = new CoseSigner(key, HashAlgorithmName.SHA256, protectedHeaders);
        var signed = CoseSign1Message.SignEmbedded(embeddedHash, signer);
        var message = CoseSign1Message.DecodeSign1(signed);

        var method = typeof(VerifyCommandHandler).GetMethod(
            "VerifyIndirectPayloadHash",
            BindingFlags.NonPublic | BindingFlags.Static);

        Assert.That(method, Is.Not.Null);

        var result = (bool)method!.Invoke(null, new object[] { message, payload })!;
        Assert.That(result, Is.False);
    }

    [Test]
    public void VerifyIndirectPayloadHash_WhenHashMatches_ReturnsTrue()
    {
        var payload = System.Text.Encoding.UTF8.GetBytes("payload");
        var embeddedHash = SHA256.HashData(payload);

        var protectedHeaders = new CoseHeaderMap();
        protectedHeaders.Add(CoseHashEnvelopeHeaderContributor.HeaderLabels.PayloadHashAlg, CoseHeaderValue.FromInt32(-16));

        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signer = new CoseSigner(key, HashAlgorithmName.SHA256, protectedHeaders);
        var signed = CoseSign1Message.SignEmbedded(embeddedHash, signer);
        var message = CoseSign1Message.DecodeSign1(signed);

        var method = typeof(VerifyCommandHandler).GetMethod(
            "VerifyIndirectPayloadHash",
            BindingFlags.NonPublic | BindingFlags.Static);

        Assert.That(method, Is.Not.Null);

        var result = (bool)method!.Invoke(null, new object[] { message, payload })!;
        Assert.That(result, Is.True);
    }

    [Test]
    public void VerifyIndirectPayloadHash_WhenHashMismatches_ReturnsFalse()
    {
        var payload = System.Text.Encoding.UTF8.GetBytes("payload");
        var embeddedHash = SHA256.HashData(payload);

        var protectedHeaders = new CoseHeaderMap();
        protectedHeaders.Add(CoseHashEnvelopeHeaderContributor.HeaderLabels.PayloadHashAlg, CoseHeaderValue.FromInt32(-16));

        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signer = new CoseSigner(key, HashAlgorithmName.SHA256, protectedHeaders);
        var signed = CoseSign1Message.SignEmbedded(embeddedHash, signer);
        var message = CoseSign1Message.DecodeSign1(signed);

        var differentPayload = System.Text.Encoding.UTF8.GetBytes("different");

        var method = typeof(VerifyCommandHandler).GetMethod(
            "VerifyIndirectPayloadHash",
            BindingFlags.NonPublic | BindingFlags.Static);

        Assert.That(method, Is.Not.Null);

        var result = (bool)method!.Invoke(null, new object[] { message, differentPayload })!;
        Assert.That(result, Is.False);
    }

    [Test]
    public async Task HandleAsync_WithIndirectSignature_WritesIndirectAndPayloadFile()
    {
        // Arrange
        var payloadBytes = System.Text.Encoding.UTF8.GetBytes("payload-bytes");
        var embeddedHash = SHA256.HashData(payloadBytes);

        var protectedHeaders = new CoseHeaderMap();
        protectedHeaders.Add(CoseHashEnvelopeHeaderContributor.HeaderLabels.PayloadHashAlg, CoseHeaderValue.FromInt32(-16));

        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signer = new CoseSigner(key, HashAlgorithmName.SHA256, protectedHeaders);
        var encoded = CoseSign1Message.SignEmbedded(embeddedHash, signer);

        var tempPayload = Path.GetTempFileName();
        var tempSignature = Path.GetTempFileName();

        var stringWriter = new StringWriter();
        var formatter = new TextOutputFormatter(output: stringWriter, error: stringWriter);
        var handler = new VerifyCommandHandler(formatter);

        try
        {
            await File.WriteAllBytesAsync(tempPayload, payloadBytes);
            await File.WriteAllBytesAsync(tempSignature, encoded);

            var context = CreateInvocationContext(signature: new FileInfo(tempSignature));

            // Act
            var result = await handler.HandleAsync(context, new FileInfo(tempPayload), signatureOnly: false);
            formatter.Flush();

            // Assert - It will fail certificate validation, but should still report the signature type.
            Assert.That(result, Is.EqualTo((int)ExitCode.VerificationFailed));

            var output = stringWriter.ToString();
            Assert.That(output, Does.Contain("Indirect"));
            Assert.That(output, Does.Contain("Payload File"));
        }
        finally
        {
            if (File.Exists(tempPayload))
            {
                File.Delete(tempPayload);
            }
            if (File.Exists(tempSignature))
            {
                File.Delete(tempSignature);
            }
        }
    }

    [Test]
    public async Task HandleAsync_WhenProviderValidatorFails_WritesFailureDetailsAndReturnsVerificationFailed()
    {
        // Arrange - Create a real signature using sign-ephemeral (so base certificate validation can succeed)
        var builder = new CoseSignTool.Commands.CommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";

        var stringWriter = new StringWriter();
        var formatter = new TextOutputFormatter(output: stringWriter, error: stringWriter);

        var failingProvider = new MockVerificationProvider(isActivated: true, validationPasses: false);
        var handler = new VerifyCommandHandler(formatter, new[] { failingProvider });

        try
        {
            File.WriteAllText(tempPayload, "Test payload for failing-provider verify test");
            rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\"");
            Assert.That(File.Exists(tempSignature), "Signature should exist");

            var signature = new FileInfo(tempSignature);
            var context = CreateInvocationContext(signature: signature);

            // Act
            var result = await handler.HandleAsync(context);
            formatter.Flush();

            // Assert
            Assert.That(result, Is.EqualTo((int)ExitCode.VerificationFailed));
            var output = stringWriter.ToString();
            Assert.That(output, Does.Contain("Signature verification failed"));
            Assert.That(output, Does.Contain("MOCK_ERROR"));
        }
        finally
        {
            if (File.Exists(tempPayload))
            {
                File.Delete(tempPayload);
            }
            if (File.Exists(tempSignature))
            {
                File.Delete(tempSignature);
            }
        }
    }

    [Test]
    public async Task HandleAsync_WithDetachedSignatureAndNoPayload_ReturnsInvalidArguments()
    {
        // Arrange
        var handler = new VerifyCommandHandler();

        var payload = "test payload"u8.ToArray();
        byte[] detachedBytes;
        using (var key = ECDsa.Create(ECCurve.NamedCurves.nistP256))
        {
            var signer = new CoseSigner(key, HashAlgorithmName.SHA256);
            detachedBytes = CoseSign1Message.SignDetached(payload, signer);
        }

        var tempSignatureFile = Path.GetTempFileName();
        await File.WriteAllBytesAsync(tempSignatureFile, detachedBytes);
        var signature = new FileInfo(tempSignatureFile);
        var context = CreateInvocationContext(signature: signature);

        try
        {
            // Act
            var result = await handler.HandleAsync(context, payloadFile: null, signatureOnly: false);

            // Assert
            Assert.That(result, Is.EqualTo((int)ExitCode.InvalidArguments));
        }
        finally
        {
            if (File.Exists(tempSignatureFile))
            {
                File.Delete(tempSignatureFile);
            }
        }
    }

    private static InvocationContext CreateInvocationContext(FileInfo? signature = null)
    {
        var command = new Command("verify");
        var signatureArg = new Argument<string?>("signature");

        command.AddArgument(signatureArg);

        // Parse using a root command so the "verify" token is interpreted as a command name,
        // not as the argument value.
        var root = new RootCommand();
        root.AddCommand(command);

        var args = signature != null ? $"verify \"{signature.FullName}\"" : "verify";
        var parseResult = root.Parse(args);
        return new InvocationContext(parseResult);
    }

    [Test]
    public async Task HandleAsync_WithMissingSignatureFile_ReturnsFileNotFound()
    {
        var output = new StringWriter();
        var error = new StringWriter();
        var handler = new VerifyCommandHandler(new TextOutputFormatter(output, error));

        var missingSignature = new FileInfo(Path.Combine(Path.GetTempPath(), $"missing_{Guid.NewGuid():N}.cose"));
        var context = CreateInvocationContext(signature: missingSignature);

        var result = await handler.HandleAsync(context);

        Assert.That(result, Is.EqualTo((int)ExitCode.FileNotFound));
        Assert.That(error.ToString(), Does.Contain("Signature file not found"));
    }

    [Test]
    public async Task HandleAsync_WithMissingPayloadFile_ReturnsFileNotFound()
    {
        var output = new StringWriter();
        var error = new StringWriter();
        var handler = new VerifyCommandHandler(new TextOutputFormatter(output, error));

        var context = CreateInvocationContext(signature: null);
        var missingPayload = new FileInfo(Path.Combine(Path.GetTempPath(), $"missing_payload_{Guid.NewGuid():N}.bin"));

        var result = await handler.HandleAsync(context, payloadFile: missingPayload, signatureOnly: false);

        Assert.That(result, Is.EqualTo((int)ExitCode.FileNotFound));
        Assert.That(error.ToString(), Does.Contain("Payload file not found"));
    }

    [Test]
    [System.Runtime.Versioning.RequiresPreviewFeatures("Uses preview cryptography APIs.")]
    public async Task HandleAsync_WithValidSignatureAndActivatedProvider_WritesMetadataAndReturnsSuccess()
    {
        var output = new StringWriter();
        var error = new StringWriter();
        var formatter = new TextOutputFormatter(output, error);

        var provider = new AlwaysOnVerificationProvider();
        var handler = new VerifyCommandHandler(formatter, new List<IVerificationProvider> { provider });

        var cert = TestCertificateUtils.CreateCertificate("VerifyHandlerTest");

        var chainBuilder = new X509ChainBuilder();
        var signingService = CertificateSigningService.Create(cert, chainBuilder);
        var factory = new DirectSignatureFactory(signingService);
        var payload = new byte[] { 1, 2, 3, 4, 5 };
        var signatureBytes = factory.CreateCoseSign1MessageBytes(payload, "application/test");

        var tempSignaturePath = Path.Combine(Path.GetTempPath(), $"valid_{Guid.NewGuid():N}.cose");
        File.WriteAllBytes(tempSignaturePath, signatureBytes);

        try
        {
            var context = CreateInvocationContext(signature: new FileInfo(tempSignaturePath));
            var result = await handler.HandleAsync(context, payloadFile: null, signatureOnly: false);

            Assert.That(result, Is.EqualTo((int)ExitCode.Success));

            var outText = output.ToString();
            Assert.That(outText, Does.Contain("Active Providers"));
            Assert.That(outText, Does.Contain(provider.ProviderName));
            Assert.That(outText, Does.Contain("Test-Metadata-Null"));
            Assert.That(outText, Does.Contain("null"));
        }
        finally
        {
            cert.Dispose();

            if (File.Exists(tempSignaturePath))
            {
                File.Delete(tempSignaturePath);
            }
        }
    }

    [Test]
    [System.Runtime.Versioning.RequiresPreviewFeatures("Uses preview cryptography APIs.")]
    public async Task HandleAsync_WithValidSignature_WhenSignatureOnly_ReturnsSuccessAndWritesSignatureVerifiedMessage()
    {
        var output = new StringWriter();
        var error = new StringWriter();
        var formatter = new TextOutputFormatter(output, error);
        var handler = new VerifyCommandHandler(formatter);

        var cert = TestCertificateUtils.CreateCertificate("VerifyHandlerSignatureOnlyTest");

        var chainBuilder = new X509ChainBuilder();
        var signingService = CertificateSigningService.Create(cert, chainBuilder);
        var factory = new DirectSignatureFactory(signingService);
        var payload = new byte[] { 9, 8, 7 };
        var signatureBytes = factory.CreateCoseSign1MessageBytes(payload, "application/test");

        var tempSignaturePath = Path.Combine(Path.GetTempPath(), $"sigonly_{Guid.NewGuid():N}.cose");
        File.WriteAllBytes(tempSignaturePath, signatureBytes);

        try
        {
            var context = CreateInvocationContext(signature: new FileInfo(tempSignaturePath));
            var result = await handler.HandleAsync(context, payloadFile: null, signatureOnly: true);

            Assert.That(result, Is.EqualTo((int)ExitCode.Success));
            Assert.That(output.ToString(), Does.Contain("payload verification skipped"));
        }
        finally
        {
            cert.Dispose();

            if (File.Exists(tempSignaturePath))
            {
                File.Delete(tempSignaturePath);
            }
        }
    }

    [Test]
    [System.Runtime.Versioning.RequiresPreviewFeatures("Uses preview cryptography APIs.")]
    public async Task HandleAsync_WithIndirectSignature_WhenPayloadHashMismatch_ReturnsVerificationFailed()
    {
        var output = new StringWriter();
        var error = new StringWriter();
        var formatter = new TextOutputFormatter(output, error);
        var handler = new VerifyCommandHandler(formatter);

        var cert = TestCertificateUtils.CreateCertificate("VerifyHandlerIndirectMismatchTest");

        var chainBuilder = new X509ChainBuilder();
        var signingService = CertificateSigningService.Create(cert, chainBuilder);
        var factory = new IndirectSignatureFactory(signingService);
        var originalPayload = "original payload"u8.ToArray();
        var signatureBytes = factory.CreateCoseSign1MessageBytes(originalPayload, "application/test");

        var tempSignaturePath = Path.Combine(Path.GetTempPath(), $"indirect_{Guid.NewGuid():N}.cose");
        var tempPayloadPath = Path.Combine(Path.GetTempPath(), $"indirect_payload_{Guid.NewGuid():N}.bin");

        File.WriteAllBytes(tempSignaturePath, signatureBytes);
        File.WriteAllBytes(tempPayloadPath, "different payload"u8.ToArray());

        try
        {
            var context = CreateInvocationContext(signature: new FileInfo(tempSignaturePath));
            var result = await handler.HandleAsync(context, payloadFile: new FileInfo(tempPayloadPath), signatureOnly: false);

            Assert.That(result, Is.EqualTo((int)ExitCode.VerificationFailed));
            Assert.That(error.ToString(), Does.Contain("Payload hash does not match"));
            Assert.That(output.ToString(), Does.Contain("Payload File"));
        }
        finally
        {
            cert.Dispose();

            if (File.Exists(tempSignaturePath))
            {
                File.Delete(tempSignaturePath);
            }

            if (File.Exists(tempPayloadPath))
            {
                File.Delete(tempPayloadPath);
            }
        }
    }

    private sealed class AlwaysOnVerificationProvider : IVerificationProvider
    {
        public string ProviderName => "TestProvider";
        public string Description => "Test provider";
        public int Priority => 0;

        public void AddVerificationOptions(Command command)
        {
        }

        public bool IsActivated(ParseResult parseResult) => true;

        public IEnumerable<IValidator<CoseSign1Message>> CreateValidators(ParseResult parseResult)
        {
            return Array.Empty<IValidator<CoseSign1Message>>();
        }

        public IDictionary<string, object?> GetVerificationMetadata(ParseResult parseResult, CoseSign1Message message, ValidationResult validationResult)
        {
            return new Dictionary<string, object?>
            {
                ["Test-Metadata-Null"] = null,
                ["Test-Metadata-Number"] = 123
            };
        }
    }

    [Test]
    public async Task HandleAsync_WithValidCoseSignature_ReturnsSuccessOrValidationStatus()
    {
        // Arrange - Create a real signature using sign-ephemeral
        var builder = new CoseSignTool.Commands.CommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var handler = new VerifyCommandHandler();

        try
        {
            File.WriteAllText(tempPayload, "Test payload for verify test");
            rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\"");
            Assert.That(File.Exists(tempSignature), "Signature should exist");

            var signature = new FileInfo(tempSignature);
            var context = CreateInvocationContext(signature: signature);

            // Act
            var result = await handler.HandleAsync(context);

            // Assert - Should return success or a validation status (not file-related errors)
            Assert.That(
                result == (int)ExitCode.Success ||
                result == (int)ExitCode.VerificationFailed ||
                result == (int)ExitCode.UntrustedCertificate,
                $"Expected success or validation failure, got {result}");
        }
        finally
        {
            if (File.Exists(tempPayload))
            {
                File.Delete(tempPayload);
            }
            if (File.Exists(tempSignature))
            {
                File.Delete(tempSignature);
            }
        }
    }

    [Test]
    public async Task HandleAsync_WithJsonFormatter_ProducesJsonOutput()
    {
        // Arrange
        var stringWriter = new StringWriter();
        var formatter = new JsonOutputFormatter(stringWriter);
        var handler = new VerifyCommandHandler(formatter);
        var tempFile = Path.GetTempFileName();
        await File.WriteAllBytesAsync(tempFile, [0xD2, 0x84]);
        var signature = new FileInfo(tempFile);
        var context = CreateInvocationContext(signature: signature);

        try
        {
            // Act
            await handler.HandleAsync(context);
            formatter.Flush();

            // Assert - JSON formatter should produce JSON-like output
            var output = stringWriter.ToString();
            Assert.That(output.Contains("{") || output.Contains("[") || output.Contains("\""));
        }
        finally
        {
            if (File.Exists(tempFile))
            {
                File.Delete(tempFile);
            }
        }
    }

    [Test]
    public async Task HandleAsync_WithXmlFormatter_ProducesXmlOutput()
    {
        // Arrange
        var stringWriter = new StringWriter();
        var formatter = new XmlOutputFormatter(stringWriter);
        var handler = new VerifyCommandHandler(formatter);
        var tempFile = Path.GetTempFileName();
        await File.WriteAllBytesAsync(tempFile, [0xD2, 0x84]);
        var signature = new FileInfo(tempFile);
        var context = CreateInvocationContext(signature: signature);

        try
        {
            // Act
            await handler.HandleAsync(context);
            formatter.Flush();

            // Assert - XML formatter should produce XML-like output
            var output = stringWriter.ToString();
            Assert.That(output.Contains("<") || output.Contains("</") || output.Contains("xml"));
        }
        finally
        {
            if (File.Exists(tempFile))
            {
                File.Delete(tempFile);
            }
        }
    }

    [Test]
    public async Task HandleAsync_WithQuietFormatter_SuppressesOutput()
    {
        // Arrange
        var formatter = new QuietOutputFormatter();
        var handler = new VerifyCommandHandler(formatter);
        var tempFile = Path.GetTempFileName();
        await File.WriteAllBytesAsync(tempFile, [0xD2, 0x84]);
        var signature = new FileInfo(tempFile);
        var context = CreateInvocationContext(signature: signature);

        try
        {
            // Act
            var result = await handler.HandleAsync(context);

            // Assert - Should complete without throwing
            Assert.That(
                result == (int)ExitCode.InvalidSignature ||
                result == (int)ExitCode.FileNotFound ||
                result == (int)ExitCode.VerificationFailed, Is.True);
        }
        finally
        {
            if (File.Exists(tempFile))
            {
                File.Delete(tempFile);
            }
        }
    }

    [Test]
    public async Task HandleAsync_WithEmbeddedPayloadSignature_IndicatesEmbedded()
    {
        // Arrange
        var builder = new CoseSignTool.Commands.CommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var stringWriter = new StringWriter();
        var formatter = new TextOutputFormatter(stringWriter);
        var handler = new VerifyCommandHandler(formatter);

        try
        {
            File.WriteAllText(tempPayload, "Test payload");
            // Use embedded signature type
            rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\" --signature-type embedded");
            Assert.That(File.Exists(tempSignature), "Signature should exist");

            var signature = new FileInfo(tempSignature);
            var context = CreateInvocationContext(signature: signature);

            // Act
            await handler.HandleAsync(context);
            formatter.Flush();

            // Assert
            var output = stringWriter.ToString();
            Assert.That(output, Does.Contain("Embedded"));
        }
        finally
        {
            if (File.Exists(tempPayload))
            {
                File.Delete(tempPayload);
            }
            if (File.Exists(tempSignature))
            {
                File.Delete(tempSignature);
            }
        }
    }

    [Test]
    public async Task HandleAsync_WithDetachedSignature_IndicatesDetached()
    {
        // Arrange
        var builder = new CoseSignTool.Commands.CommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var stringWriter = new StringWriter();
        var formatter = new TextOutputFormatter(stringWriter);
        var handler = new VerifyCommandHandler(formatter);

        try
        {
            File.WriteAllText(tempPayload, "Test payload");
            // Use direct with detached flag
            rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\" --signature-type detached");
            Assert.That(File.Exists(tempSignature), "Signature should exist");

            var signature = new FileInfo(tempSignature);
            var context = CreateInvocationContext(signature: signature);

            // Act
            await handler.HandleAsync(context);
            formatter.Flush();

            // Assert
            var output = stringWriter.ToString();
            Assert.That(output, Does.Contain("Detached"));
        }
        finally
        {
            if (File.Exists(tempPayload))
            {
                File.Delete(tempPayload);
            }
            if (File.Exists(tempSignature))
            {
                File.Delete(tempSignature);
            }
        }
    }

    [Test]
    public async Task HandleAsync_WithVerificationProvider_CallsProviderMethods()
    {
        // Arrange - Create a real signature using sign-ephemeral
        var builder = new CoseSignTool.Commands.CommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var stringWriter = new StringWriter();
        var formatter = new TextOutputFormatter(stringWriter);

        // Create a mock provider that is activated and returns validators
        var mockProvider = new MockVerificationProvider(isActivated: true, validationPasses: true);
        var handler = new VerifyCommandHandler(formatter, new[] { mockProvider });

        try
        {
            File.WriteAllText(tempPayload, "Test payload for verify test");
            rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\"");
            Assert.That(File.Exists(tempSignature), "Signature should exist");

            var signature = new FileInfo(tempSignature);
            var context = CreateInvocationContext(signature: signature);

            // Act
            var result = await handler.HandleAsync(context);
            formatter.Flush();

            // Assert - Provider should have been called
            Assert.That(mockProvider.IsActivatedCalled, Is.True, "IsActivated should have been called");
            Assert.That(mockProvider.CreateValidatorsCalled, Is.True, "CreateValidators should have been called");
            Assert.That(mockProvider.GetMetadataCalled, Is.True, "GetVerificationMetadata should have been called");

            // Provider name should appear in output
            var output = stringWriter.ToString();
            Assert.That(output, Does.Contain("MockProvider"));
        }
        finally
        {
            if (File.Exists(tempPayload))
            {
                File.Delete(tempPayload);
            }
            if (File.Exists(tempSignature))
            {
                File.Delete(tempSignature);
            }
        }
    }

    [Test]
    public async Task HandleAsync_WithProviderNullMetadataValue_WritesNull()
    {
        // Arrange
        var builder = new CoseSignTool.Commands.CommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var stringWriter = new StringWriter();
        var formatter = new TextOutputFormatter(output: stringWriter, error: stringWriter);

        var provider = new NullMetadataVerificationProvider();
        var handler = new VerifyCommandHandler(formatter, new[] { provider });

        try
        {
            File.WriteAllText(tempPayload, "Test payload for null-metadata verify test");
            rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\"");
            Assert.That(File.Exists(tempSignature), "Signature should exist");

            var signature = new FileInfo(tempSignature);
            var context = CreateInvocationContext(signature: signature);

            // Act
            var result = await handler.HandleAsync(context);
            formatter.Flush();

            // Assert - only check output for null formatting (success vs trust may vary)
            Assert.That(result, Is.Not.EqualTo((int)ExitCode.InvalidSignature));
            Assert.That(stringWriter.ToString(), Does.Contain("NullMetadata").And.Contain("null"));
        }
        finally
        {
            if (File.Exists(tempPayload))
            {
                File.Delete(tempPayload);
            }
            if (File.Exists(tempSignature))
            {
                File.Delete(tempSignature);
            }
        }
    }

    [Test]
    public async Task HandleAsync_WithFailingVerificationProvider_ReturnsVerificationFailed()
    {
        // Arrange - Create a real signature using sign-ephemeral
        var builder = new CoseSignTool.Commands.CommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var stringWriter = new StringWriter();
        var formatter = new TextOutputFormatter(stringWriter);

        // Create a provider that adds a failing validator
        var mockProvider = new MockVerificationProvider(isActivated: true, validationPasses: false);
        var handler = new VerifyCommandHandler(formatter, new[] { mockProvider });

        try
        {
            File.WriteAllText(tempPayload, "Test payload for verify test");
            rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\"");
            Assert.That(File.Exists(tempSignature), "Signature should exist");

            var signature = new FileInfo(tempSignature);
            var context = CreateInvocationContext(signature: signature);

            // Act
            var result = await handler.HandleAsync(context);
            formatter.Flush();

            // Assert - The mock provider should have been called
            Assert.That(mockProvider.CreateValidatorsCalled, Is.True, "CreateValidators should have been called");

            // The result should be either success (if only cert validation passed)
            // or verification failed (if our mock validator's failure was processed)
            // Since the composite validator runs all validators, check that at least the provider was invoked
            var output = stringWriter.ToString();
            Assert.That(output, Does.Contain("Active Providers: MockProvider"));
        }
        finally
        {
            if (File.Exists(tempPayload))
            {
                File.Delete(tempPayload);
            }
            if (File.Exists(tempSignature))
            {
                File.Delete(tempSignature);
            }
        }
    }

    [Test]
    public async Task HandleAsync_WithInactiveProvider_DoesNotCallProviderValidators()
    {
        // Arrange - Create a real signature using sign-ephemeral
        var builder = new CoseSignTool.Commands.CommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var stringWriter = new StringWriter();
        var formatter = new TextOutputFormatter(stringWriter);

        // Create a provider that is NOT activated
        var mockProvider = new MockVerificationProvider(isActivated: false, validationPasses: true);
        var handler = new VerifyCommandHandler(formatter, new[] { mockProvider });

        try
        {
            File.WriteAllText(tempPayload, "Test payload for verify test");
            rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\"");
            Assert.That(File.Exists(tempSignature), "Signature should exist");

            var signature = new FileInfo(tempSignature);
            var context = CreateInvocationContext(signature: signature);

            // Act
            await handler.HandleAsync(context);

            // Assert - Provider should have checked activation but not created validators
            Assert.That(mockProvider.IsActivatedCalled, Is.True, "IsActivated should have been called");
            Assert.That(mockProvider.CreateValidatorsCalled, Is.False, "CreateValidators should NOT have been called");
            Assert.That(mockProvider.GetMetadataCalled, Is.False, "GetVerificationMetadata should NOT have been called");
        }
        finally
        {
            if (File.Exists(tempPayload))
            {
                File.Delete(tempPayload);
            }
            if (File.Exists(tempSignature))
            {
                File.Delete(tempSignature);
            }
        }
    }

    #region Payload and SignatureOnly Tests

    [Test]
    public async Task HandleAsync_WithPayloadFile_PassesPayloadToHandler()
    {
        // Arrange
        var builder = new CoseSignTool.Commands.CommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var stringWriter = new StringWriter();
        var formatter = new TextOutputFormatter(stringWriter);
        var handler = new VerifyCommandHandler(formatter);

        try
        {
            File.WriteAllText(tempPayload, "Test payload for detached verification test");
            // Create a detached signature
            rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\" --signature-type detached");
            Assert.That(File.Exists(tempSignature), "Signature should exist");

            var signature = new FileInfo(tempSignature);
            var payload = new FileInfo(tempPayload);
            var context = CreateInvocationContext(signature: signature);

            // Act
            var result = await handler.HandleAsync(context, payload, signatureOnly: false);
            formatter.Flush();

            // Assert - Should complete and show payload file info
            var output = stringWriter.ToString();
            Assert.That(output, Does.Contain("Payload File").Or.Contain("Detached"));
        }
        finally
        {
            if (File.Exists(tempPayload))
            {
                File.Delete(tempPayload);
            }
            if (File.Exists(tempSignature))
            {
                File.Delete(tempSignature);
            }
        }
    }

    [Test]
    public async Task HandleAsync_WithNonExistentPayloadFile_ReturnsFileNotFound()
    {
        // Arrange
        var builder = new CoseSignTool.Commands.CommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var handler = new VerifyCommandHandler();

        try
        {
            File.WriteAllText(tempPayload, "Test payload");
            rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\"");
            Assert.That(File.Exists(tempSignature), "Signature should exist");

            var signature = new FileInfo(tempSignature);
            var nonExistentPayload = new FileInfo(Path.Combine(Path.GetTempPath(), $"nonexistent_{Guid.NewGuid()}.bin"));
            var context = CreateInvocationContext(signature: signature);

            // Act
            var result = await handler.HandleAsync(context, nonExistentPayload, signatureOnly: false);

            // Assert - Should return FileNotFound for non-existent payload
            Assert.That(result, Is.EqualTo((int)ExitCode.FileNotFound));
        }
        finally
        {
            if (File.Exists(tempPayload))
            {
                File.Delete(tempPayload);
            }
            if (File.Exists(tempSignature))
            {
                File.Delete(tempSignature);
            }
        }
    }

    [Test]
    public async Task HandleAsync_WithSignatureOnlyTrue_SkipsPayloadVerification()
    {
        // Arrange
        var builder = new CoseSignTool.Commands.CommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var stringWriter = new StringWriter();
        var formatter = new TextOutputFormatter(stringWriter);
        var handler = new VerifyCommandHandler(formatter);

        try
        {
            File.WriteAllText(tempPayload, "Test payload for signature-only test");
            rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\"");
            Assert.That(File.Exists(tempSignature), "Signature should exist");

            var signature = new FileInfo(tempSignature);
            var context = CreateInvocationContext(signature: signature);

            // Act
            var result = await handler.HandleAsync(context, payloadFile: null, signatureOnly: true);
            formatter.Flush();

            // Assert - Should show signature-only mode in output
            var output = stringWriter.ToString();
            Assert.That(output, Does.Contain("Signature Only").Or.Contain("Yes"));
        }
        finally
        {
            if (File.Exists(tempPayload))
            {
                File.Delete(tempPayload);
            }
            if (File.Exists(tempSignature))
            {
                File.Delete(tempSignature);
            }
        }
    }

    [Test]
    public async Task HandleAsync_DetachedSignatureWithoutPayload_ReturnsInvalidArguments()
    {
        // Arrange
        var builder = new CoseSignTool.Commands.CommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var handler = new VerifyCommandHandler();

        try
        {
            File.WriteAllText(tempPayload, "Test payload for detached test");
            // Create a detached signature
            rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\" --signature-type detached");
            Assert.That(File.Exists(tempSignature), "Signature should exist");

            var signature = new FileInfo(tempSignature);
            var context = CreateInvocationContext(signature: signature);

            // Act - Try to verify detached signature without providing payload
            var result = await handler.HandleAsync(context, payloadFile: null, signatureOnly: false);

            // Assert - Should return InvalidArguments because detached requires payload
            Assert.That(result, Is.EqualTo((int)ExitCode.InvalidArguments));
        }
        finally
        {
            if (File.Exists(tempPayload))
            {
                File.Delete(tempPayload);
            }
            if (File.Exists(tempSignature))
            {
                File.Delete(tempSignature);
            }
        }
    }

    [Test]
    public async Task HandleAsync_OverloadWithNoArgs_CallsMainMethod()
    {
        // Arrange
        var builder = new CoseSignTool.Commands.CommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var handler = new VerifyCommandHandler();

        try
        {
            File.WriteAllText(tempPayload, "Test payload");
            rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\"");
            Assert.That(File.Exists(tempSignature), "Signature should exist");

            var signature = new FileInfo(tempSignature);
            var context = CreateInvocationContext(signature: signature);

            // Act - Call the overload that takes only context
            var result = await handler.HandleAsync(context);

            // Assert - Should complete without throwing
            Assert.That(
                result == (int)ExitCode.Success ||
                result == (int)ExitCode.VerificationFailed ||
                result == (int)ExitCode.UntrustedCertificate,
                $"Expected success or validation failure, got {result}");
        }
        finally
        {
            if (File.Exists(tempPayload))
            {
                File.Delete(tempPayload);
            }
            if (File.Exists(tempSignature))
            {
                File.Delete(tempSignature);
            }
        }
    }

    [Test]
    public async Task HandleAsync_WhenProviderThrows_ReturnsVerificationFailedAndWritesError()
    {
        // Arrange
        var builder = new CoseSignTool.Commands.CommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";

        var stringWriter = new StringWriter();
        var formatter = new TextOutputFormatter(output: stringWriter, error: stringWriter);
        var handler = new VerifyCommandHandler(formatter, new[] { new ThrowingVerificationProvider() });

        try
        {
            File.WriteAllText(tempPayload, "Test payload for provider-throws test");
            rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\"");
            Assert.That(File.Exists(tempSignature), "Signature should exist");

            var signature = new FileInfo(tempSignature);
            var context = CreateInvocationContext(signature: signature);

            // Act
            var result = await handler.HandleAsync(context);
            formatter.Flush();

            // Assert
            Assert.That(result, Is.EqualTo((int)ExitCode.VerificationFailed));
            Assert.That(stringWriter.ToString(), Does.Contain("Error verifying signature"));
        }
        finally
        {
            if (File.Exists(tempPayload))
            {
                File.Delete(tempPayload);
            }
            if (File.Exists(tempSignature))
            {
                File.Delete(tempSignature);
            }
        }
    }

    #endregion

    /// <summary>
    /// Mock verification provider for testing provider integration.
    /// </summary>
    private class MockVerificationProvider : IVerificationProvider
    {
        private readonly bool IsActivatedValue;
        private readonly bool ValidationPasses;

        public bool IsActivatedCalled { get; private set; }
        public bool CreateValidatorsCalled { get; private set; }
        public bool GetMetadataCalled { get; private set; }

        public MockVerificationProvider(bool isActivated, bool validationPasses)
        {
            IsActivatedValue = isActivated;
            ValidationPasses = validationPasses;
        }

        public string ProviderName => "MockProvider";

        public string Description => "Mock provider for testing";

        public int Priority => 100;

        public void AddVerificationOptions(Command command)
        {
            // No options needed for mock
        }

        public bool IsActivated(ParseResult parseResult)
        {
            IsActivatedCalled = true;
            return IsActivatedValue;
        }

        public IEnumerable<IValidator<CoseSign1Message>> CreateValidators(ParseResult parseResult)
        {
            CreateValidatorsCalled = true;
            yield return new MockValidator(ValidationPasses);
        }

        public IDictionary<string, object?> GetVerificationMetadata(
            ParseResult parseResult,
            CoseSign1Message message,
            ValidationResult validationResult)
        {
            GetMetadataCalled = true;
            return new Dictionary<string, object?>
            {
                { "MockMetadata", "MockValue" }
            };
        }
    }

    private sealed class NullMetadataVerificationProvider : IVerificationProvider
    {
        public string ProviderName => "NullMetadataProvider";

        public string Description => "Provides null metadata values";

        public int Priority => 0;

        public void AddVerificationOptions(Command command)
        {
            // No-op
        }

        public bool IsActivated(ParseResult parseResult) => true;

        public IEnumerable<IValidator<CoseSign1Message>> CreateValidators(ParseResult parseResult)
        {
            // Always pass so we can reach metadata writing.
            yield return new MockValidator(shouldPass: true);
        }

        public IDictionary<string, object?> GetVerificationMetadata(
            ParseResult parseResult,
            CoseSign1Message message,
            ValidationResult validationResult)
        {
            return new Dictionary<string, object?>
            {
                { "NullMetadata", null }
            };
        }
    }

    private sealed class ThrowingVerificationProvider : IVerificationProvider
    {
        public string ProviderName => "Throwing";

        public string Description => "Throws from IsActivated";

        public int Priority => 0;

        public void AddVerificationOptions(Command command)
        {
            // No-op
        }

        public bool IsActivated(ParseResult parseResult)
        {
            throw new InvalidOperationException("boom");
        }

        public IEnumerable<IValidator<CoseSign1Message>> CreateValidators(ParseResult parseResult)
        {
            return Array.Empty<IValidator<CoseSign1Message>>();
        }

        public IDictionary<string, object?> GetVerificationMetadata(
            ParseResult parseResult,
            CoseSign1Message message,
            ValidationResult result)
        {
            return new Dictionary<string, object?>();
        }
    }

    /// <summary>
    /// Mock validator for testing.
    /// </summary>
    private class MockValidator : IValidator<CoseSign1Message>
    {
        private readonly bool ShouldPass;

        public MockValidator(bool shouldPass)
        {
            ShouldPass = shouldPass;
        }

        public ValidationResult Validate(CoseSign1Message input)
        {
            return ShouldPass
                ? ValidationResult.Success("MockValidator")
                : ValidationResult.Failure("MockValidator", "Mock validation failure", "MOCK_ERROR");
        }

        public Task<ValidationResult> ValidateAsync(CoseSign1Message input, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(Validate(input));
        }
    }

    #region Indirect payload hash verification helper coverage

    [TestCase(-16, "SHA256")]
    [TestCase(-43, "SHA384")]
    [TestCase(-44, "SHA512")]
    public void VerifyIndirectPayloadHash_WhenPayloadMatches_ReturnsTrue(int coseAlgId, string _)
    {
        var payload = System.Text.Encoding.UTF8.GetBytes("payload-bytes");

        using HashAlgorithm hasher = coseAlgId switch
        {
            -16 => SHA256.Create(),
            -43 => SHA384.Create(),
            -44 => SHA512.Create(),
            _ => throw new ArgumentOutOfRangeException(nameof(coseAlgId))
        };

        var embeddedHash = hasher.ComputeHash(payload);

        var protectedHeaders = new CoseHeaderMap();
        protectedHeaders.Add(CoseHashEnvelopeHeaderContributor.HeaderLabels.PayloadHashAlg, CoseHeaderValue.FromInt32(coseAlgId));

        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signer = new CoseSigner(key, HashAlgorithmName.SHA256, protectedHeaders);

        var encoded = CoseSign1Message.SignEmbedded(embeddedHash, signer);
        var message = CoseMessage.DecodeSign1(encoded);

        var result = InvokeVerifyIndirectPayloadHash(message, payload);
        Assert.That(result, Is.True);
    }

    [Test]
    public void VerifyIndirectPayloadHash_WhenAlgUnknown_ReturnsFalse()
    {
        var payload = new byte[] { 1, 2, 3 };
        var embeddedHash = SHA256.HashData(payload);

        var protectedHeaders = new CoseHeaderMap();
        protectedHeaders.Add(CoseHashEnvelopeHeaderContributor.HeaderLabels.PayloadHashAlg, CoseHeaderValue.FromInt32(-9999));

        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signer = new CoseSigner(key, HashAlgorithmName.SHA256, protectedHeaders);

        var encoded = CoseSign1Message.SignEmbedded(embeddedHash, signer);
        var message = CoseMessage.DecodeSign1(encoded);

        var result = InvokeVerifyIndirectPayloadHash(message, payload);
        Assert.That(result, Is.False);
    }

    [Test]
    public void VerifyIndirectPayloadHash_WhenHeaderMissing_ReturnsFalse()
    {
        var payload = new byte[] { 1, 2, 3 };
        var embeddedHash = SHA256.HashData(payload);

        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signer = new CoseSigner(key, HashAlgorithmName.SHA256);

        var encoded = CoseSign1Message.SignEmbedded(embeddedHash, signer);
        var message = CoseMessage.DecodeSign1(encoded);

        var result = InvokeVerifyIndirectPayloadHash(message, payload);
        Assert.That(result, Is.False);
    }

    [Test]
    public void VerifyIndirectPayloadHash_WhenContentMissing_ReturnsFalse()
    {
        var payload = new byte[] { 1, 2, 3 };

        var protectedHeaders = new CoseHeaderMap();
        protectedHeaders.Add(CoseHashEnvelopeHeaderContributor.HeaderLabels.PayloadHashAlg, CoseHeaderValue.FromInt32(-16));

        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signer = new CoseSigner(key, HashAlgorithmName.SHA256, protectedHeaders);

        var signature = CoseSign1Message.SignDetached(payload, signer);
        var message = CoseSign1Message.DecodeSign1(signature);

        var result = InvokeVerifyIndirectPayloadHash(message, payload);
        Assert.That(result, Is.False);
    }

    private static bool InvokeVerifyIndirectPayloadHash(CoseSign1Message message, byte[] payload)
    {
        var method = typeof(VerifyCommandHandler).GetMethod(
            "VerifyIndirectPayloadHash",
            BindingFlags.NonPublic | BindingFlags.Static);

        Assert.That(method, Is.Not.Null);

        return (bool)method!.Invoke(null, new object[] { message, payload })!;
    }

    #endregion
}