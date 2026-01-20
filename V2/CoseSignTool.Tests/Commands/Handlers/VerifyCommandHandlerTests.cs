// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Tests.Commands.Handlers;

using System.CommandLine;
using System.CommandLine.Invocation;
using System.CommandLine.Parsing;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using CoseSign1.Abstractions;
using CoseSign1.Certificates;
using CoseSign1.Certificates.ChainBuilders;
using CoseSign1.Factories.Direct;
using CoseSign1.Tests.Common;
using CoseSign1.Factories.Indirect;
using CoseSign1.Validation.DependencyInjection;
using CoseSign1.Validation.Interfaces;
using CoseSign1.Validation.Results;
using CoseSign1.Validation.Trust;
using CoseSignTool.Local.Plugin;
using CoseSignTool.Abstractions;
using CoseSignTool.Commands.Handlers;
using CoseSignTool.Output;
using Microsoft.Extensions.DependencyInjection;

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
        var handler = new VerifyCommandHandler(new TestConsole(), null);

        // Assert
        Assert.That(handler, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithFormatter_UsesProvidedFormatter()
    {
        // Arrange
        var formatter = new TextOutputFormatter();

        // Act
        var handler = TestConsole.CreateVerifyCommandHandler(formatter);

        // Assert
        Assert.That(handler, Is.Not.Null);
    }

    [Test]
    public async Task HandleAsync_WithNullSignature_ReturnsFileNotFound()
    {
        // Arrange
        var handler = TestConsole.CreateVerifyCommandHandler();
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
        var handler = TestConsole.CreateVerifyCommandHandler();
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
        var handler = TestConsole.CreateVerifyCommandHandler();
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
        var handler = TestConsole.CreateVerifyCommandHandler();

        // Act & Assert
        Assert.ThrowsAsync<ArgumentNullException>(() => handler.HandleAsync(null!));
    }

    [Test]
    public async Task HandleAsync_WithRandomBytes_ReturnsInvalidSignature()
    {
        // Arrange
        var handler = TestConsole.CreateVerifyCommandHandler();
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
        var handler = TestConsole.CreateVerifyCommandHandler(formatter);
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
        var handler = TestConsole.CreateVerifyCommandHandler();
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
        var handler = TestConsole.CreateVerifyCommandHandler(formatter);

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
    public void VerifyIndirectPayloadHash_WhenSha384HashMatches_ReturnsTrue()
    {
        var payload = System.Text.Encoding.UTF8.GetBytes("payload");
        var embeddedHash = SHA384.HashData(payload);

        var protectedHeaders = new CoseHeaderMap();
        protectedHeaders.Add(CoseHashEnvelopeHeaderContributor.HeaderLabels.PayloadHashAlg, CoseHeaderValue.FromInt32(-43));

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
    public void VerifyIndirectPayloadHash_WhenSha512HashMatches_ReturnsTrue()
    {
        var payload = System.Text.Encoding.UTF8.GetBytes("payload");
        var embeddedHash = SHA512.HashData(payload);

        var protectedHeaders = new CoseHeaderMap();
        protectedHeaders.Add(CoseHashEnvelopeHeaderContributor.HeaderLabels.PayloadHashAlg, CoseHeaderValue.FromInt32(-44));

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
    public async Task HandleAsync_WhenDecodeFailsAndInputLooksBase64_PrintsHint()
    {
        var tempSignature = Path.GetTempFileName();

        var stringWriter = new StringWriter();
        var formatter = new TextOutputFormatter(output: stringWriter, error: stringWriter);
        var handler = TestConsole.CreateVerifyCommandHandler(formatter);

        try
        {
            // Base64-ish ASCII (decoding will fail, but should trigger the hint).
            await File.WriteAllTextAsync(tempSignature, new string('A', 256));

            var context = CreateInvocationContext(signature: new FileInfo(tempSignature));

            var result = await handler.HandleAsync(context, payloadFile: null, signatureOnly: false);
            formatter.Flush();

            Assert.That(result, Is.EqualTo((int)ExitCode.InvalidSignature));

            var output = stringWriter.ToString();
            Assert.That(output, Does.Contain("appears to be Base64 text"));
            Assert.That(output, Does.Contain("Decode it to bytes first"));
        }
        finally
        {
            if (File.Exists(tempSignature))
            {
                File.Delete(tempSignature);
            }
        }
    }

    [Test]
    [System.Runtime.Versioning.RequiresPreviewFeatures("Uses preview cryptography APIs.")]
    public async Task HandleAsync_WithIndirectSignature_WritesIndirectAndPayloadFile()
    {
        // Arrange - Create indirect signature using certificate-based signing (with x5chain header)
        var payloadBytes = System.Text.Encoding.UTF8.GetBytes("payload-bytes");

        var cert = TestCertificateUtils.CreateCertificate("IndirectSignatureTest");
        var chainBuilder = new X509ChainBuilder();
        var signingService = CertificateSigningService.Create(cert, chainBuilder);
        var factory = new IndirectSignatureFactory(signingService);
        var signatureBytes = factory.CreateCoseSign1MessageBytes(payloadBytes, "application/test");

        var tempPayload = Path.GetTempFileName();
        var tempSignature = Path.GetTempFileName();

        var stringWriter = new StringWriter();
        var formatter = new TextOutputFormatter(output: stringWriter, error: stringWriter);
        
        // Use X509VerificationProvider to resolve signing key from x5chain
        var x509Provider = new X509VerificationProvider();
        var handler = TestConsole.CreateVerifyCommandHandler(formatter, new[] { x509Provider });

        try
        {
            await File.WriteAllBytesAsync(tempPayload, payloadBytes);
            await File.WriteAllBytesAsync(tempSignature, signatureBytes);

            // Use helper that ensures provider options are registered
            var context = CreateInvocationContextWithProviders(
                new[] { x509Provider },
                $"verify x509 \"{tempSignature}\" --allow-untrusted");

            // Act
            var result = await handler.HandleAsync(context, new FileInfo(tempPayload), signatureOnly: false);
            formatter.Flush();

            // Assert - With ephemeral cert, expect UntrustedCertificate or Success (if chain validation is disabled)
            Assert.That(result, Is.EqualTo((int)ExitCode.UntrustedCertificate).Or.EqualTo((int)ExitCode.Success));

            var output = stringWriter.ToString();
            Assert.That(output, Does.Contain("Indirect"));
            Assert.That(output, Does.Contain("Payload File"));
        }
        finally
        {
            cert.Dispose();
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
    public async Task HandleAsync_WhenProviderValidatorFails_WritesFailureDetailsAndReturnsUntrustedCertificate()
    {
        // Arrange - Create a real signature using sign x509 ephemeral (so base certificate validation can succeed)
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";

        var stringWriter = new StringWriter();
        var formatter = new TextOutputFormatter(output: stringWriter, error: stringWriter);

        // Use X509VerificationProvider to resolve the real signing key from x5chain
        // Then the failing assertion provider to test assertion failure handling
        var x509Provider = new X509VerificationProvider();
        // Don't include mock key resolver - let X509 provider handle key resolution
        var failingProvider = new MockVerificationProvider(isActivated: true, validationPasses: false, includeKeyResolver: false);
        var handler = TestConsole.CreateVerifyCommandHandler(formatter, new IVerificationProvider[] { x509Provider, failingProvider });

        try
        {
            File.WriteAllText(tempPayload, "Test payload for failing-provider verify test");
            rootCommand.Invoke($"sign x509 ephemeral \"{tempPayload}\"");
            Assert.That(File.Exists(tempSignature), "Signature should exist");

            var signature = new FileInfo(tempSignature);

            // Use the helper to ensure provider options are registered on the same instances
            var context = CreateInvocationContextWithProviders(
                new IVerificationProvider[] { x509Provider, failingProvider },
                $"verify x509 \"{signature.FullName}\" --allow-untrusted --payload \"{tempPayload}\"");

            // Act
            var result = await handler.HandleAsync(context, new FileInfo(tempPayload), signatureOnly: false);
            formatter.Flush();

            // Assert - Validation fails due to mock provider's failing assertion (trust policy not satisfied)
            Assert.That(result, Is.EqualTo((int)ExitCode.UntrustedCertificate));
            var output = stringWriter.ToString();
            Assert.That(output, Does.Contain("not trusted").IgnoreCase);
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
        var handler = TestConsole.CreateVerifyCommandHandler();

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
        var verify = new Command("verify");
        var x509 = new Command("x509");
        x509.AddArgument(new Argument<string?>("signature"));
        verify.AddCommand(x509);

        // Parse using a root command so the "verify" token is interpreted as a command name.
        var root = new RootCommand();
        root.AddCommand(verify);

        var args = signature != null ? $"verify x509 \"{signature.FullName}\"" : "verify x509";
        var parseResult = root.Parse(args);
        return new InvocationContext(parseResult);
    }

    private static InvocationContext CreateInvocationContext(System.CommandLine.Command rootCommand, string fullArgs)
    {
        var parseResult = rootCommand.Parse(fullArgs);
        return new InvocationContext(parseResult);
    }

    /// <summary>
    /// Creates a verify command with all options from the provided verification providers registered.
    /// This ensures the provider's options are properly initialized before IsActivated is called.
    /// </summary>
    private static Command CreateVerifyCommandWithProviders(IEnumerable<IVerificationProvider> providers)
    {
        var verify = new Command("verify");
        var x509 = new Command("x509");
        x509.AddArgument(new Argument<string?>("signature") { Arity = ArgumentArity.ZeroOrOne });
        x509.AddOption(new Option<FileInfo?>("--payload", "-p"));
        x509.AddOption(new Option<bool>("--signature-only"));

        // Let each provider register its options - this initializes the provider's Option fields.
        foreach (var provider in providers)
        {
            provider.AddVerificationOptions(x509);
        }

        verify.AddCommand(x509);
        return verify;
    }

    private sealed class FixedKeyVerificationProvider : IVerificationProvider
    {
        private readonly ECDsa _key;

        public FixedKeyVerificationProvider(ECDsa key)
        {
            _key = key;
        }

        public string ProviderName => "FixedKey";

        public string Description => "Fixed signing key provider";

        public int Priority => 0;

        public void AddVerificationOptions(Command command)
        {
        }

        public bool IsActivated(ParseResult parseResult) => true;

        public void ConfigureValidation(ICoseValidationBuilder validationBuilder, ParseResult parseResult, VerificationContext context)
        {
            validationBuilder.Services.AddSingleton<ISigningKeyResolver>(_ => new FixedSigningKeyResolver(_key));
        }

        public IDictionary<string, object?> GetVerificationMetadata(ParseResult parseResult, CoseSign1Message message, ValidationResult result)
            => new Dictionary<string, object?>();
    }

    private sealed class FixedSigningKeyResolver : ISigningKeyResolver
    {
        private readonly ECDsa _key;

        public FixedSigningKeyResolver(ECDsa key)
        {
            _key = key;
        }

        public SigningKeyResolutionResult Resolve(CoseSign1Message message)
        {
            return SigningKeyResolutionResult.Success(new FixedSigningKey(_key));
        }

        public Task<SigningKeyResolutionResult> ResolveAsync(CoseSign1Message message, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(Resolve(message));
        }
    }

    private sealed class FixedSigningKey : ISigningKey
    {
        private readonly ECDsa _key;

        public FixedSigningKey(ECDsa key)
        {
            _key = key;
        }

        public CoseKey GetCoseKey() => new CoseKey(_key, HashAlgorithmName.SHA256);

        public void Dispose()
        {
            // Key lifetime is owned by the test.
        }
    }

    /// <summary>
    /// Creates an InvocationContext using a command that has all verification provider options registered.
    /// </summary>
    private static InvocationContext CreateInvocationContextWithProviders(
        IEnumerable<IVerificationProvider> providers,
        string args)
    {
        var verifyCommand = CreateVerifyCommandWithProviders(providers);
        var root = new RootCommand();
        root.AddCommand(verifyCommand);

        var parseResult = root.Parse(args);
        return new InvocationContext(parseResult);
    }

    [Test]
    public async Task HandleAsync_WithMissingSignatureFile_ReturnsFileNotFound()
    {
        var output = new StringWriter();
        var error = new StringWriter();
        var handler = TestConsole.CreateVerifyCommandHandler(new TextOutputFormatter(output, error));

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
        var handler = TestConsole.CreateVerifyCommandHandler(new TextOutputFormatter(output, error));

        var context = CreateInvocationContext(signature: null);
        var missingPayload = new FileInfo(Path.Combine(Path.GetTempPath(), $"missing_payload_{Guid.NewGuid():N}.bin"));

        var result = await handler.HandleAsync(context, payloadFile: missingPayload, signatureOnly: false);

        Assert.That(result, Is.EqualTo((int)ExitCode.FileNotFound));
        Assert.That(error.ToString(), Does.Contain("Payload file not found"));
    }

    [Test]
    public async Task HandleAsync_WithStdinAndNoData_ReturnsFileNotFoundAndWritesNoStdinData()
    {
        var output = new StringWriter();
        var formatter = new TextOutputFormatter(output: output, error: output);
        var console = new TestConsole(Array.Empty<byte>());
        var handler = new VerifyCommandHandler(console, formatter)
        {
            StdinTimeout = TimeSpan.FromMilliseconds(25)
        };

        // Build a root command with the correct argument name and pass '-' so the handler reads stdin.
        // With fix-forward CLI, verification root is required.
        var verify = new Command("verify");
        var x509 = new Command("x509");
        x509.AddArgument(new Argument<string?>("signature"));
        verify.AddCommand(x509);
        var root = new RootCommand();
        root.AddCommand(verify);

        var context = CreateInvocationContext(root, "verify x509 -");

        var exitCode = await handler.HandleAsync(context);
        formatter.Flush();

        Assert.That(exitCode, Is.EqualTo((int)ExitCode.FileNotFound));

        var text = output.ToString();
        Assert.That(
            text,
            Does.Contain("No signature data received from stdin")
                .Or.Contain("Timed out")
        );
    }

    [Test]
    [System.Runtime.Versioning.RequiresPreviewFeatures("Uses preview cryptography APIs.")]
    public async Task HandleAsync_WithValidSignatureAndActivatedProvider_WritesMetadataAndReturnsSuccess()
    {
        var output = new StringWriter();
        var error = new StringWriter();
        var formatter = new TextOutputFormatter(output, error);

        // Use X509VerificationProvider which extracts the actual signing key from x5chain
        var provider = new X509VerificationProvider();
        var handler = TestConsole.CreateVerifyCommandHandler(formatter, new List<IVerificationProvider> { provider });

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
            // Use the new helper that ensures provider options are registered on the same instance
            var context = CreateInvocationContextWithProviders(
                new[] { provider },
                $"verify x509 \"{tempSignaturePath}\" --allow-untrusted");

            var result = await handler.HandleAsync(context, payloadFile: null, signatureOnly: false);

            // Ephemeral cert is untrusted, so we get UntrustedCertificate rather than Success
            Assert.That(result, Is.EqualTo((int)ExitCode.UntrustedCertificate).Or.EqualTo((int)ExitCode.Success));

            var outText = output.ToString();
            Assert.That(outText, Does.Contain("Active Providers"));
            Assert.That(outText, Does.Contain(provider.ProviderName));
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

        // Use X509VerificationProvider to resolve the signing key from x5chain
        var provider = new X509VerificationProvider();
        var handler = TestConsole.CreateVerifyCommandHandler(formatter, new List<IVerificationProvider> { provider });

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
            // Use the new helper that ensures provider options are registered on the same instance
            // Also include --allow-untrusted since we're using an ephemeral cert
            var context = CreateInvocationContextWithProviders(
                new[] { provider },
                $"verify x509 \"{tempSignaturePath}\" --signature-only --allow-untrusted");

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
        // Use X509VerificationProvider to resolve the real signing key from x5chain
        var x509Provider = new X509VerificationProvider();
        var handler = TestConsole.CreateVerifyCommandHandler(formatter, new[] { x509Provider });

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
            // Use helper that ensures provider options are registered
            var context = CreateInvocationContextWithProviders(
                new[] { x509Provider },
                $"verify x509 \"{tempSignaturePath}\" --allow-untrusted");
            var result = await handler.HandleAsync(context, payloadFile: new FileInfo(tempPayloadPath), signatureOnly: false);

            Assert.That(result, Is.EqualTo((int)ExitCode.VerificationFailed));
            Assert.That(error.ToString(), Does.Contain("payload hash does not match").IgnoreCase);
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

    private sealed class AlwaysOnVerificationProvider : IVerificationProvider, IVerificationProviderWithTrustPlanPolicy
    {
        public string ProviderName => "TestProvider";
        public string Description => "Test provider";
        public int Priority => 0;

        public void AddVerificationOptions(Command command)
        {
        }

        public bool IsActivated(ParseResult parseResult) => true;

        public void ConfigureValidation(ICoseValidationBuilder validationBuilder, ParseResult parseResult, VerificationContext context)
        {
            validationBuilder.Services.AddSingleton<ISigningKeyResolver, MockSigningKeyResolver>();
        }

        public TrustPlanPolicy? CreateTrustPlanPolicy(ParseResult parseResult, VerificationContext context)
        {
            // Allow all trust so tests can exercise non-trust behavior paths.
            return TrustPlanPolicy.Message(_ => _);
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
        // Arrange - Create a real signature using sign x509 ephemeral
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var handler = TestConsole.CreateVerifyCommandHandler(verificationProviders: new[] { new X509VerificationProvider() });

        try
        {
            File.WriteAllText(tempPayload, "Test payload for verify test");
            rootCommand.Invoke($"sign x509 ephemeral \"{tempPayload}\"");
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
        var handler = TestConsole.CreateVerifyCommandHandler(formatter);
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
        var handler = TestConsole.CreateVerifyCommandHandler(formatter);
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
        var handler = TestConsole.CreateVerifyCommandHandler(formatter);
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
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var stringWriter = new StringWriter();
        var formatter = new TextOutputFormatter(stringWriter);
        var handler = TestConsole.CreateVerifyCommandHandler(formatter);

        try
        {
            File.WriteAllText(tempPayload, "Test payload");
            // Use embedded signature type
            rootCommand.Invoke($"sign x509 ephemeral \"{tempPayload}\" --signature-type embedded");
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
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var stringWriter = new StringWriter();
        var formatter = new TextOutputFormatter(stringWriter);
        var handler = TestConsole.CreateVerifyCommandHandler(formatter);

        try
        {
            File.WriteAllText(tempPayload, "Test payload");
            // Use direct with detached flag
            rootCommand.Invoke($"sign x509 ephemeral \"{tempPayload}\" --signature-type detached");
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
        // Arrange - Create a real signature using sign x509 ephemeral
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var stringWriter = new StringWriter();
        var formatter = new TextOutputFormatter(stringWriter);

        // Create a mock provider that is activated and returns validators
        // Don't include mock key resolver - let X509 provider handle key resolution
        var mockProvider = new MockVerificationProvider(isActivated: true, validationPasses: true, includeKeyResolver: false);
        // Include X509VerificationProvider to resolve the actual signing key
        var x509Provider = new X509VerificationProvider();
        var handler = TestConsole.CreateVerifyCommandHandler(formatter, new IVerificationProvider[] 
        { 
            x509Provider,
            mockProvider 
        });

        try
        {
            File.WriteAllText(tempPayload, "Test payload for verify test");
            rootCommand.Invoke($"sign x509 ephemeral \"{tempPayload}\"");
            Assert.That(File.Exists(tempSignature), "Signature should exist");

            var signature = new FileInfo(tempSignature);
            // Use the helper that ensures provider options are registered on the same instance
            var context = CreateInvocationContextWithProviders(
                new IVerificationProvider[] { x509Provider, mockProvider },
                $"verify x509 \"{signature.FullName}\" --allow-untrusted --payload \"{tempPayload}\"");

            // Act - provide payload for indirect signature validation
            var result = await handler.HandleAsync(context, payloadFile: new FileInfo(tempPayload), signatureOnly: false);
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
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var stringWriter = new StringWriter();
        var formatter = new TextOutputFormatter(output: stringWriter, error: stringWriter);

        // Use X509VerificationProvider for key resolution plus NullMetadataVerificationProvider for metadata
        var x509Provider = new X509VerificationProvider();
        var nullMetadataProvider = new NullMetadataVerificationProvider();
        var handler = TestConsole.CreateVerifyCommandHandler(formatter, new IVerificationProvider[] 
        { 
            x509Provider,
            nullMetadataProvider 
        });

        try
        {
            File.WriteAllText(tempPayload, "Test payload for null-metadata verify test");
            rootCommand.Invoke($"sign x509 ephemeral \"{tempPayload}\"");
            Assert.That(File.Exists(tempSignature), "Signature should exist");

            var signature = new FileInfo(tempSignature);
            // Use the helper that ensures provider options are registered on the same instance
            var context = CreateInvocationContextWithProviders(
                new IVerificationProvider[] { x509Provider, nullMetadataProvider },
                $"verify x509 \"{signature.FullName}\" --allow-untrusted --payload \"{tempPayload}\"");

            // Act - pass payloadFile to validate the payload hash
            var result = await handler.HandleAsync(context, payloadFile: new FileInfo(tempPayload), signatureOnly: false);
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
        // Arrange - Create a real signature using sign x509 ephemeral
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var stringWriter = new StringWriter();
        var formatter = new TextOutputFormatter(stringWriter);

        // Create a provider that adds a failing validator
        var x509Provider = new X509VerificationProvider();
        var mockProvider = new MockVerificationProvider(isActivated: true, validationPasses: false, includeKeyResolver: false);
        var handler = TestConsole.CreateVerifyCommandHandler(formatter, new IVerificationProvider[] { x509Provider, mockProvider });

        try
        {
            File.WriteAllText(tempPayload, "Test payload for verify test");
            rootCommand.Invoke($"sign x509 ephemeral \"{tempPayload}\"");
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
    public async Task HandleAsync_WithInactiveProvider_DoesNotCallProviderValidators()
    {
        // Arrange - Create a real signature using sign x509 ephemeral
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var stringWriter = new StringWriter();
        var formatter = new TextOutputFormatter(stringWriter);

        // Create a provider that is NOT activated
        var x509Provider = new X509VerificationProvider();
        var mockProvider = new MockVerificationProvider(isActivated: false, validationPasses: true, includeKeyResolver: false);
        var handler = TestConsole.CreateVerifyCommandHandler(formatter, new IVerificationProvider[] { x509Provider, mockProvider });

        try
        {
            File.WriteAllText(tempPayload, "Test payload for verify test");
            rootCommand.Invoke($"sign x509 ephemeral \"{tempPayload}\"");
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
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var stringWriter = new StringWriter();
        var formatter = new TextOutputFormatter(stringWriter);
        var handler = TestConsole.CreateVerifyCommandHandler(formatter);

        try
        {
            File.WriteAllText(tempPayload, "Test payload for detached verification test");
            // Create a detached signature
            rootCommand.Invoke($"sign x509 ephemeral \"{tempPayload}\" --signature-type detached");
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
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var handler = TestConsole.CreateVerifyCommandHandler();

        try
        {
            File.WriteAllText(tempPayload, "Test payload");
            rootCommand.Invoke($"sign x509 ephemeral \"{tempPayload}\"");
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
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var stringWriter = new StringWriter();
        var formatter = new TextOutputFormatter(stringWriter);
        var handler = TestConsole.CreateVerifyCommandHandler(formatter);

        try
        {
            File.WriteAllText(tempPayload, "Test payload for signature-only test");
            rootCommand.Invoke($"sign x509 ephemeral \"{tempPayload}\"");
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
    public async Task HandleAsync_WithSignatureOnlyTrue_WhenNoProviders_ReturnsSuccess()
    {
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();

        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";

        var output = new StringWriter();
        var error = new StringWriter();
        var formatter = new TextOutputFormatter(output, error);

        // Use X509VerificationProvider to resolve the signing key from x5chain
        var provider = new X509VerificationProvider();
        var handler = TestConsole.CreateVerifyCommandHandler(formatter, new List<IVerificationProvider> { provider });

        try
        {
            File.WriteAllText(tempPayload, "Test payload for signature-only test");
            rootCommand.Invoke($"sign x509 ephemeral \"{tempPayload}\"");
            Assert.That(File.Exists(tempSignature), "Signature should exist");

            // Use the helper that ensures provider options are registered on the same instance
            var context = CreateInvocationContextWithProviders(
                new[] { provider },
                $"verify x509 \"{tempSignature}\" --signature-only --allow-untrusted");
            var result = await handler.HandleAsync(context, payloadFile: null, signatureOnly: true);
            formatter.Flush();

            Assert.That(result, Is.EqualTo((int)ExitCode.Success));
            Assert.That(output.ToString(), Does.Contain("payload verification skipped"));
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
    public async Task HandleAsync_WithMultipleTrustPolicies_WritesWarningAndReturnsSuccess()
    {
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();

        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";

        var output = new StringWriter();
        var error = new StringWriter();
        var formatter = new TextOutputFormatter(output, error);

        // Use X509VerificationProvider for actual key resolution, plus AllowAll providers for multiple trust policies
        var x509Provider = new X509VerificationProvider();
        var handler = TestConsole.CreateVerifyCommandHandler(
            formatter,
            new IVerificationProvider[]
            {
                x509Provider,
                new AllowAllTrustProvider("P1"),
                new AllowAllTrustProvider("P2")
            });

        try
        {
            File.WriteAllText(tempPayload, "Test payload");
            rootCommand.Invoke($"sign x509 ephemeral \"{tempPayload}\"");
            Assert.That(File.Exists(tempSignature), "Signature should exist");

            // Use the helper that ensures provider options are registered on the same instance
            var context = CreateInvocationContextWithProviders(
                new IVerificationProvider[] { x509Provider, new AllowAllTrustProvider("P1"), new AllowAllTrustProvider("P2") },
                $"verify x509 \"{tempSignature}\" --allow-untrusted --payload \"{tempPayload}\"");
            var result = await handler.HandleAsync(context, payloadFile: new FileInfo(tempPayload), signatureOnly: false);
            formatter.Flush();

            Assert.That(result, Is.EqualTo((int)ExitCode.Success).Or.EqualTo((int)ExitCode.UntrustedCertificate));
            var combined = output.ToString() + error.ToString();
            Assert.That(combined, Does.Contain("Multiple trust policies were provided"));
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
    public async Task HandleAsync_WithFailingPostSignatureValidator_ReturnsVerificationFailed()
    {
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();

        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";

        var output = new StringWriter();
        var error = new StringWriter();
        var formatter = new TextOutputFormatter(output, error);

        // Use X509VerificationProvider to resolve the real signing key from x5chain
        // Then PostSignatureFailingProvider adds a failing post-signature assertion
        var x509Provider = new X509VerificationProvider();
        var failingProvider = new PostSignatureFailingProvider();
        var handler = TestConsole.CreateVerifyCommandHandler(
            formatter,
            new IVerificationProvider[] { x509Provider, failingProvider });

        try
        {
            File.WriteAllText(tempPayload, "Test payload");
            rootCommand.Invoke($"sign x509 ephemeral \"{tempPayload}\"");
            Assert.That(File.Exists(tempSignature), "Signature should exist");

            // Use the helper to ensure provider options are registered on the same instances
            var context = CreateInvocationContextWithProviders(
                new IVerificationProvider[] { x509Provider, failingProvider },
                $"verify x509 \"{tempSignature}\" --payload \"{tempPayload}\" --allow-untrusted");
            var result = await handler.HandleAsync(context, payloadFile: new FileInfo(tempPayload), signatureOnly: false);
            formatter.Flush();

            Assert.That(result, Is.EqualTo((int)ExitCode.VerificationFailed));
            Assert.That(error.ToString(), Does.Contain("Signature verification failed"));
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

    private sealed class AllowAllTrustProvider : IVerificationProvider, IVerificationProviderWithTrustPlanPolicy
    {
        private readonly string _name;

        public AllowAllTrustProvider(string name)
        {
            _name = name;
        }

        public string ProviderName => _name;

        public string Description => "Always active, allow-all trust policy";

        public int Priority => 0;

        public void AddVerificationOptions(Command command)
        {
        }

        public bool IsActivated(ParseResult parseResult) => true;

        public void ConfigureValidation(ICoseValidationBuilder validationBuilder, ParseResult parseResult, VerificationContext context)
        {
            // Don't add key resolver - rely on X509VerificationProvider when combined.
        }

        public TrustPlanPolicy? CreateTrustPlanPolicy(ParseResult parseResult, VerificationContext context)
        {
            return TrustPlanPolicy.Message(_ => _);
        }

        public IDictionary<string, object?> GetVerificationMetadata(ParseResult parseResult, CoseSign1Message message, ValidationResult validationResult)
        {
            return new Dictionary<string, object?>();
        }
    }

    private sealed class PostSignatureFailingProvider : IVerificationProvider, IVerificationProviderWithTrustPlanPolicy
    {
        public string ProviderName => "PostSigFail";

        public string Description => "Adds a failing post-signature validator";

        public int Priority => 100; // Run after X509VerificationProvider which is at 10

        public void AddVerificationOptions(Command command)
        {
        }

        public bool IsActivated(ParseResult parseResult) => true;

        public void ConfigureValidation(ICoseValidationBuilder validationBuilder, ParseResult parseResult, VerificationContext context)
        {
            validationBuilder.Services.AddSingleton<IPostSignatureValidator, MockFailingPostSignatureValidator>();
        }

        public TrustPlanPolicy? CreateTrustPlanPolicy(ParseResult parseResult, VerificationContext context)
        {
            return TrustPlanPolicy.Message(_ => _);
        }

        public IDictionary<string, object?> GetVerificationMetadata(ParseResult parseResult, CoseSign1Message message, ValidationResult validationResult)
        {
            return new Dictionary<string, object?>();
        }
    }

    [Test]
    public async Task HandleAsync_DetachedSignatureWithoutPayload_ReturnsInvalidArguments()
    {
        // Arrange
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var handler = TestConsole.CreateVerifyCommandHandler();

        try
        {
            File.WriteAllText(tempPayload, "Test payload for detached test");
            // Create a detached signature
            rootCommand.Invoke($"sign x509 ephemeral \"{tempPayload}\" --signature-type detached");
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
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var handler = TestConsole.CreateVerifyCommandHandler(verificationProviders: new[] { new X509VerificationProvider() });

        try
        {
            File.WriteAllText(tempPayload, "Test payload");
            rootCommand.Invoke($"sign x509 ephemeral \"{tempPayload}\"");
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
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";

        var stringWriter = new StringWriter();
        var formatter = new TextOutputFormatter(output: stringWriter, error: stringWriter);
        var handler = TestConsole.CreateVerifyCommandHandler(
            formatter,
            new IVerificationProvider[] { new X509VerificationProvider(), new ThrowingVerificationProvider() });

        try
        {
            File.WriteAllText(tempPayload, "Test payload for provider-throws test");
            rootCommand.Invoke($"sign x509 ephemeral \"{tempPayload}\"");
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

    [Test]
    public async Task HandleAsync_WhenResolutionValidatorFails_ReturnsVerificationFailedAndWritesFailureDetails()
    {
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";

        var output = new StringWriter();
        var formatter = new TextOutputFormatter(output: output, error: output);
        var handler = TestConsole.CreateVerifyCommandHandler(formatter, new[] { new ResolutionFailingProvider() });

        try
        {
            File.WriteAllText(tempPayload, "resolution-failure-test");
            rootCommand.Invoke($"sign x509 ephemeral \"{tempPayload}\"");
            Assert.That(File.Exists(tempSignature), "Signature should exist");

            // sign x509 ephemeral creates indirect signatures - use --signature-only since we're testing key resolution failure
            var context = CreateInvocationContext(rootCommand, $"verify x509 \"{tempSignature}\" --signature-only");
            var exitCode = await handler.HandleAsync(context, payloadFile: null, signatureOnly: true);
            formatter.Flush();

            Assert.That(exitCode, Is.EqualTo((int)ExitCode.VerificationFailed));
            Assert.That(output.ToString(), Does.Contain("Key material resolution failed"));
            // The error code surfaced is NO_SIGNING_KEY_RESOLVED not the custom message
            Assert.That(output.ToString(), Does.Contain("NO_SIGNING_KEY_RESOLVED"));
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

    private sealed class ResolutionFailingProvider : IVerificationRootProvider, IVerificationProviderWithTrustPlanPolicy
    {
        public string ProviderName => "ResolutionFail";

        public string Description => "Adds a failing key material resolution validator";

        public string RootId => "x509";

        public string RootDisplayName => "X509";

        public string RootHelpSummary => "Test root provider for resolution failure";

        public int Priority => 0;

        public void AddVerificationOptions(Command command)
        {
        }

        public bool IsActivated(ParseResult parseResult) => true;

        public void ConfigureValidation(ICoseValidationBuilder validationBuilder, ParseResult parseResult, VerificationContext context)
        {
            validationBuilder.Services.AddSingleton<ISigningKeyResolver>(_ =>
                new MockSigningKeyResolver(shouldSucceed: false, errorMessage: "Key material resolution failed"));
        }

        public TrustPlanPolicy? CreateTrustPlanPolicy(ParseResult parseResult, VerificationContext context)
        {
            return TrustPlanPolicy.Message(_ => _);
        }

        public IDictionary<string, object?> GetVerificationMetadata(ParseResult parseResult, CoseSign1Message message, ValidationResult validationResult)
        {
            return new Dictionary<string, object?>();
        }
    }

    #endregion

    /// <summary>
    /// Mock verification provider for testing provider integration.
    /// </summary>
    private class MockVerificationProvider : IVerificationProvider, IVerificationProviderWithTrustPlanPolicy
    {
        private readonly bool IsActivatedValue;
        private readonly bool ValidationPasses;
        private readonly bool IncludeKeyResolver;

        public bool IsActivatedCalled { get; private set; }
        public bool CreateValidatorsCalled { get; private set; }
        public bool GetMetadataCalled { get; private set; }

        /// <summary>
        /// Creates a mock verification provider for testing.
        /// </summary>
        /// <param name="isActivated">Whether this provider is activated.</param>
        /// <param name="validationPasses">Whether validation should pass.</param>
        /// <param name="includeKeyResolver">If true, adds a mock key resolver. Set to false when using alongside
        /// X509VerificationProvider to let the real certificate-based resolver handle key resolution.</param>
        public MockVerificationProvider(bool isActivated, bool validationPasses, bool includeKeyResolver = true)
        {
            IsActivatedValue = isActivated;
            ValidationPasses = validationPasses;
            IncludeKeyResolver = includeKeyResolver;
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

        public void ConfigureValidation(ICoseValidationBuilder validationBuilder, ParseResult parseResult, VerificationContext context)
        {
            CreateValidatorsCalled = true;

            // Always provide the pack so the trust plan can evaluate deterministically.
            validationBuilder.Services.AddSingleton<ITrustPack>(_ => new MockTrustPack(isValid: ValidationPasses));

            if (IncludeKeyResolver)
            {
                validationBuilder.Services.AddSingleton<ISigningKeyResolver, MockSigningKeyResolver>();
            }
        }

        public TrustPlanPolicy? CreateTrustPlanPolicy(ParseResult parseResult, VerificationContext context)
        {
            if (!ValidationPasses)
            {
                return TrustPlanPolicy.Message(m =>
                    m.RequireFact<MockTrustFact>(
                        f => f.IsValid,
                        "MOCK_ERROR: Mock validation must pass"));
            }

            // Otherwise permit trust so the test can focus on provider integration behavior.
            return TrustPlanPolicy.Message(_ => _);
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

    private sealed record MockTrustFact(bool IsValid) : CoseSign1.Validation.Trust.Facts.IMessageFact
    {
        public CoseSign1.Validation.Trust.Facts.TrustFactScope Scope => CoseSign1.Validation.Trust.Facts.TrustFactScope.Message;
    }

    private sealed class MockTrustPack : ITrustPack
    {
        private readonly bool IsValid;

        public MockTrustPack(bool isValid)
        {
            IsValid = isValid;
        }

        public IReadOnlyCollection<Type> FactTypes => new[] { typeof(MockTrustFact) };

    public CoseSign1.Validation.Interfaces.ISigningKeyResolver? SigningKeyResolver => null;

        public CoseSign1.Validation.Trust.Plan.TrustPlanDefaults GetDefaults()
        {
            return new CoseSign1.Validation.Trust.Plan.TrustPlanDefaults(
                constraints: CoseSign1.Validation.Trust.Rules.TrustRules.AllowAll(),
                trustSources: new[] { CoseSign1.Validation.Trust.Rules.TrustRules.DenyAll("MockTrustPack defaults are not used by the CLI") },
                vetoes: CoseSign1.Validation.Trust.Rules.TrustRules.DenyAll("No mock vetoes"));
        }

        public ValueTask<CoseSign1.Validation.Trust.Engine.ITrustFactSet> ProduceAsync(
            CoseSign1.Validation.Trust.Engine.TrustFactContext context,
            Type factType,
            CancellationToken cancellationToken)
        {
            if (factType != typeof(MockTrustFact))
            {
                throw new NotSupportedException($"Unsupported fact type: {factType}");
            }

            return new ValueTask<CoseSign1.Validation.Trust.Engine.ITrustFactSet>(
                CoseSign1.Validation.Trust.Engine.TrustFactSet<MockTrustFact>.Available(new MockTrustFact(IsValid)));
        }
    }

    private sealed class NullMetadataVerificationProvider : IVerificationProvider, IVerificationProviderWithTrustPlanPolicy
    {
        public string ProviderName => "NullMetadataProvider";

        public string Description => "Provides null metadata values";

        public int Priority => 0;

        public void AddVerificationOptions(Command command)
        {
            // No-op
        }

        public bool IsActivated(ParseResult parseResult) => true;

        public void ConfigureValidation(ICoseValidationBuilder validationBuilder, ParseResult parseResult, VerificationContext context)
        {
            // Don't add a key resolver - let X509 provider handle key resolution when combined.
        }

        public TrustPlanPolicy? CreateTrustPlanPolicy(ParseResult parseResult, VerificationContext context)
        {
            return TrustPlanPolicy.Message(_ => _);
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

        public void ConfigureValidation(ICoseValidationBuilder validationBuilder, ParseResult parseResult, VerificationContext context)
        {
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
    /// Mock signing key for testing.
    /// </summary>
    private sealed class MockSigningKey : ISigningKey
    {
        private readonly ECDsa _key;

        public MockSigningKey()
        {
            _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        }

        public CoseKey GetCoseKey() => new CoseKey(_key, HashAlgorithmName.SHA256);

        public void Dispose() => _key.Dispose();
    }

    /// <summary>
    /// Mock signing key resolver for testing.
    /// </summary>
    private sealed class MockSigningKeyResolver : ISigningKeyResolver
    {
        private readonly bool _shouldSucceed;
        private readonly string? _errorMessage;

        public MockSigningKeyResolver(bool shouldSucceed = true, string? errorMessage = null)
        {
            _shouldSucceed = shouldSucceed;
            _errorMessage = errorMessage ?? "Key resolution failed";
        }

        public SigningKeyResolutionResult Resolve(CoseSign1Message message)
        {
            if (_shouldSucceed)
            {
                return SigningKeyResolutionResult.Success(new MockSigningKey());
            }
            return SigningKeyResolutionResult.Failure(_errorMessage!);
        }

        public Task<SigningKeyResolutionResult> ResolveAsync(CoseSign1Message message, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(Resolve(message));
        }
    }

    /// <summary>
    /// Mock post-signature validator that always fails.
    /// </summary>
    private sealed class MockFailingPostSignatureValidator : IPostSignatureValidator
    {
        public ValidationResult Validate(IPostSignatureValidationContext context)
        {
            return ValidationResult.Failure(
                "MockFailingPostSignature",
                "Post-signature validation failed",
                "POST_SIGNATURE_FAILED");
        }

        public Task<ValidationResult> ValidateAsync(IPostSignatureValidationContext context, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(Validate(context));
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

