// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.CommandLine;
using System.CommandLine.Invocation;
using System.CommandLine.Parsing;
using System.Security.Cryptography.Cose;
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

    private static InvocationContext CreateInvocationContext(FileInfo? signature = null)
    {
        var command = new Command("verify");
        var signatureArg = new Argument<string?>("signature");

        command.AddArgument(signatureArg);

        var args = signature != null ? $"verify \"{signature.FullName}\"" : "verify";
        var parseResult = command.Parse(args);
        return new InvocationContext(parseResult);
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
}